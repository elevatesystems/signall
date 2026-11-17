"""Smart card (PKCS#11) access: find the card, pick the signing certificate, sign.

A CAC's signing key (PIV slot 9C) has CKA_ALWAYS_AUTHENTICATE set: the card
wants the PIN again immediately before every signature. Signall logs in to the
token and then supplies the same PIN as a context-specific login right before
C_Sign, so the user is asked once per signature.
"""
from __future__ import annotations

import contextlib
import datetime
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from asn1crypto import x509
from pyhanko.sign.pkcs11 import PKCS11Signer

from signall.pdf import SignallError

PinProvider = Callable[["TokenInfo", "CertificateInfo"], str]

MODULE_CANDIDATES = (
    "/usr/lib64/p11-kit-proxy.so",
    "/usr/lib64/pkcs11/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/p11-kit-proxy.so",
    "/usr/lib/opensc-pkcs11.so",
)


def find_module(explicit: str | None = None) -> str:
    candidates = [explicit] if explicit else []
    if os.environ.get("SIGNALL_PKCS11_MODULE"):
        candidates.insert(0, os.environ["SIGNALL_PKCS11_MODULE"])
    candidates += list(MODULE_CANDIDATES)
    for path in candidates:
        if path and Path(path).is_file():
            return path
    raise SignallError("no PKCS#11 module found; install opensc (sudo dnf install opensc)")


@dataclass(frozen=True)
class TokenInfo:
    label: str
    manufacturer: str
    model: str
    serial: str


@dataclass(frozen=True)
class CertificateInfo:
    label: str
    cert_id: bytes
    certificate: x509.Certificate

    @property
    def subject(self) -> str:
        return self.certificate.subject.native.get("common_name", self.certificate.subject.human_friendly)

    @property
    def issuer(self) -> str:
        return self.certificate.issuer.native.get("common_name", self.certificate.issuer.human_friendly)

    @property
    def key_usage(self) -> set[str]:
        value = self.certificate.key_usage_value
        return set(value.native) if value is not None else set()

    @property
    def extended_key_usage(self) -> set[str]:
        value = self.certificate.extended_key_usage_value
        return set(value.native) if value is not None else set()

    @property
    def not_after(self) -> datetime.datetime:
        return self.certificate["tbs_certificate"]["validity"]["not_after"].native

    @property
    def can_sign_documents(self) -> bool:
        return {"digital_signature", "non_repudiation"} <= self.key_usage

    def expired(self, now: datetime.datetime | None = None) -> bool:
        return (now or datetime.datetime.now(datetime.timezone.utc)) > self.not_after


def _lib(module: str):
    import pkcs11

    try:
        return pkcs11.lib(module)
    except Exception as exc:
        raise SignallError(f"could not load PKCS#11 module {module}: {exc}") from exc


def _present_tokens(lib) -> list:
    from pkcs11 import TokenFlag

    tokens = []
    for slot in lib.get_slots(token_present=True):
        token = slot.get_token()
        if token.flags & TokenFlag.TOKEN_INITIALIZED:
            tokens.append(token)
    return tokens


def list_tokens(module: str) -> list[TokenInfo]:
    lib = _lib(module)
    out = []
    for token in _present_tokens(lib):
        out.append(TokenInfo(
            label=token.label.strip(), manufacturer=token.manufacturer_id.strip(),
            model=token.model.strip(), serial=token.serial.decode(errors="replace").strip()
            if isinstance(token.serial, bytes) else str(token.serial).strip(),
        ))
    return out


def _get_token(lib, token: TokenInfo | None):
    tokens = _present_tokens(lib)
    if not tokens:
        raise SignallError("no smart card found; is the card inserted and pcscd running?")
    if token is None:
        if len(tokens) > 1:
            labels = ", ".join(t.label.strip() for t in tokens)
            raise SignallError(f"more than one card or token is present ({labels}); choose one with --token")
        return tokens[0]
    for t in tokens:
        if t.label.strip() == token.label and (not token.serial or token.serial in str(t.serial)):
            return t
    raise SignallError(f"token {token.label!r} is not present")


def list_certificates(module: str, token: TokenInfo | None = None) -> list[CertificateInfo]:
    from pkcs11 import Attribute, ObjectClass

    lib = _lib(module)
    tok = _get_token(lib, token)
    out = []
    with tok.open() as session:
        for obj in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
            try:
                cert = x509.Certificate.load(obj[Attribute.VALUE])
            except Exception:
                continue
            out.append(CertificateInfo(label=obj[Attribute.LABEL], cert_id=bytes(obj[Attribute.ID]), certificate=cert))
    return out


def choose_signing_certificate(certs: list[CertificateInfo], now: datetime.datetime | None = None) -> CertificateInfo:
    """Pick the card's document-signing certificate (PIV 9C on a CAC)."""
    usable = [c for c in certs if c.can_sign_documents and not c.expired(now)]
    if not usable:
        if any(c.can_sign_documents for c in certs):
            raise SignallError("the signing certificate on this card has expired")
        raise SignallError("this card has no certificate that can sign documents")

    def score(c: CertificateInfo) -> tuple:
        eku = c.extended_key_usage
        return (
            "microsoft_document_signing" in eku or "document_signing" in eku or "1.3.6.1.4.1.311.10.3.12" in eku,
            "email_protection" in eku,
            "EMAIL" in c.issuer.upper(),
            "key_encipherment" not in c.key_usage,
            c.not_after,
        )

    return max(usable, key=score)


class CardSigner(PKCS11Signer):
    """A pyHanko signer that answers the card's per-signature PIN check."""

    def __init__(self, *args, context_pin: str | None, **kwargs):
        super().__init__(*args, **kwargs)
        self._context_pin = context_pin

    @property
    def cert_registry(self):
        # PKCS11Signer registers the signing certificate in its own registry, and pyHanko adds it to
        # the signature again; leave it out here so that it is embedded once.
        from pyhanko_certvalidator.registry import SimpleCertificateStore

        mine = self.signing_cert.sha256
        return SimpleCertificateStore.from_certs([c for c in super().cert_registry if c.sha256 != mine])

    def sign_kwargs(self, data_to_sign: bytes):
        kwargs = dict(super().sign_kwargs(data_to_sign))
        if self._context_pin is not None:
            kwargs["pin"] = self._context_pin
        return kwargs


def _explain(exc: Exception) -> SignallError:
    import pkcs11.exceptions as e

    if isinstance(exc, e.PinIncorrect):
        return SignallError("incorrect PIN")
    if isinstance(exc, e.PinLocked):
        return SignallError("the card's PIN is locked; it must be reset by your CAC office (RAPIDS)")
    if isinstance(exc, (e.PinLenRange, e.PinInvalid)):
        return SignallError("that PIN has the wrong length or format")
    return SignallError(f"smart card error: {type(exc).__name__}")


@contextlib.contextmanager
def open_signer(module: str, pin_provider: PinProvider, token: TokenInfo | None = None,
                cert_id: bytes | None = None, ca_chain=(),
                chain_for: Callable[[x509.Certificate], list[x509.Certificate]] | None = None,
                ) -> Iterator[CardSigner]:
    """Open the card and yield a signer for its document-signing certificate.

    ``chain_for`` is called with the chosen certificate before the PIN is asked for, and returns the
    CA certificates to embed (it may go to the network); otherwise ``ca_chain`` is embedded.
    """
    import pkcs11
    from pkcs11 import Attribute, ObjectClass

    lib = _lib(module)
    tok = _get_token(lib, token)
    token_info = TokenInfo(
        label=tok.label.strip(), manufacturer=tok.manufacturer_id.strip(), model=tok.model.strip(),
        serial=tok.serial.decode(errors="replace").strip() if isinstance(tok.serial, bytes) else str(tok.serial),
    )
    certs = list_certificates(module, token_info)
    chosen = next((c for c in certs if c.cert_id == cert_id), None) if cert_id else choose_signing_certificate(certs)
    if chosen is None:
        raise SignallError("the requested certificate is not on the card")

    if chain_for is not None:
        ca_chain = chain_for(chosen.certificate)
    pin = pin_provider(token_info, chosen)
    try:
        session = tok.open(user_pin=pin)
    except pkcs11.exceptions.PKCS11Error as exc:
        raise _explain(exc) from exc
    try:
        keys = list(session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.ID: chosen.cert_id}))
        if not keys:
            raise SignallError("the card has no private key for the signing certificate")
        try:
            always_auth = bool(keys[0][Attribute.ALWAYS_AUTHENTICATE])
        except (pkcs11.exceptions.AttributeTypeInvalid, KeyError):
            always_auth = False
        signer = CardSigner(
            session, cert_id=chosen.cert_id, signing_cert=chosen.certificate,
            ca_chain=list(ca_chain), other_certs_to_pull=(), context_pin=pin if always_auth else None,
        )
        yield signer
    except pkcs11.exceptions.PKCS11Error as exc:
        raise _explain(exc) from exc
    finally:
        del pin
        with contextlib.suppress(Exception):
            session.close()
