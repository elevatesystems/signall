"""Check the signatures in a PDF."""
from __future__ import annotations

import contextlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from asn1crypto import pem, x509
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from signall.pdf import open_reader

SYSTEM_BUNDLES = (
    "/etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem",
    "/etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/certs/ca-certificates.crt",
)


@dataclass
class CertificateInfo:
    """One certificate on the way from the signer to a root, for showing why trust failed."""
    name: str               # common name, or the whole subject
    issuer: str
    serial: str = ""
    valid_from: str = ""    # YYYY-MM-DD
    valid_until: str = ""
    key_usage: str = ""
    sha256: str = ""
    source: str = ""        # where Signall found it (see SOURCES)
    trust_anchor: bool = False
    missing: bool = False   # an issuer that could not be found; only name and download_url are set
    download_url: str | None = None


SOURCES = {
    "signer": "The signer's certificate",
    "signature": "Included in the signature",
    "dod": "Signall's DoD certificates",
    "system": "This computer's trusted certificates",
    "extra": "Added with --trust",
    "fetched": "Downloaded",
}


@dataclass
class SignatureReport:
    field: str
    signer: str
    signing_time: str | None
    intact: bool          # the signed bytes are unchanged and the math checks out
    trusted: bool         # the certificate chains to a trusted root
    covers_whole_file: bool
    changes_after: str    # "none", "form filling", "annotations", "other"
    revocation: str = "not embedded"
    """Embedded (Acrobat-style) revocation data: "not embedded", "good at signing time", or "not usable"."""
    issuer: str = ""
    problem: str | None = None
    """Why the signature is not valid or not trusted, in plain words. None if it is fine."""
    indication: str | None = None
    """pyHanko's AdES sub-indication for a trust problem, such as NO_CERTIFICATE_CHAIN_FOUND."""
    messages: list[str] = field(default_factory=list)
    """pyHanko's own messages about the problem, for bug reports."""
    certificates: list[CertificateInfo] = field(default_factory=list)
    """The signer's certificate first, then its issuers toward the root."""

    @property
    def ok(self) -> bool:
        return self.intact and self.trusted and self.changes_after != "other"


def load_certificates(path: str | Path) -> list[x509.Certificate]:
    data = Path(path).read_bytes()
    if pem.detect(data):
        return [x509.Certificate.load(der) for _, _, der in pem.unarmor(data, multiple=True)]
    return [x509.Certificate.load(data)]


def system_trust_roots() -> list[x509.Certificate]:
    roots, seen = [], set()
    for bundle in SYSTEM_BUNDLES:
        if not Path(bundle).is_file():
            continue
        for cert in load_certificates(bundle):
            if cert.sha256 not in seen:
                seen.add(cert.sha256)
                roots.append(cert)
    return roots


def trust_certificates(extra: list[x509.Certificate] = ()) -> list[x509.Certificate]:
    """The system trust store, Signall's bundled DoD certificates, and ``extra``, without duplicates."""
    from signall.trust import dod_intermediates, dod_roots

    out, seen = [], set()
    for cert in [*system_trust_roots(), *dod_roots(), *dod_intermediates(), *extra]:
        if cert.sha256 not in seen:
            seen.add(cert.sha256)
            out.append(cert)
    return out


_CHANGES = {"NONE": "none", "LTA_UPDATES": "none", "FORM_FILLING": "form filling",
            "ANNOTATIONS": "annotations", "OTHER": "other"}


def embedded_revocation_info(emb) -> tuple[list, list] | None:
    """(OCSP responses, CRLs) from the adbe-revocationInfoArchival attribute, or None."""
    from pyhanko.sign.general import MultivaluedAttributeError, NonexistentAttributeError, find_unique_cms_attribute

    try:
        archival = find_unique_cms_attribute(emb.signer_info["signed_attrs"], "adobe_revocation_info_archival")
    except (NonexistentAttributeError, MultivaluedAttributeError):
        return None
    ocsps = list(archival["ocsp"]) if archival["ocsp"].native is not None else []
    crls = list(archival["crl"]) if archival["crl"].native is not None else []
    return ocsps, crls


def _revocation_state(emb, extra_roots) -> str:
    """Check the embedded revocation data offline, as of the signing time."""
    from signall.chain import validation_context

    found = embedded_revocation_info(emb)
    if found is None:
        return "not embedded"
    ocsps, crls = found
    when = emb.self_reported_timestamp
    context = validation_context(fetch=False, require_revocation=True, extra_roots=extra_roots,
                                 ocsps=ocsps, crls=crls, moment=when)
    status = validate_pdf_signature(emb, signer_validation_context=context)
    return "good at signing time" if status.trusted and status.revocation_details is None else "not usable"


def _xfa_datasets_ref(resolver):
    """(reference, index in /XFA) of the XFA datasets packet in one revision, or (None, None)."""
    from pyhanko.pdf_utils import generic

    try:
        acroform = resolver.root["/AcroForm"]
        xfa = acroform["/XFA"]
    except (KeyError, TypeError):
        return None, None
    if not isinstance(xfa, generic.ArrayObject):
        return None, None
    for i in range(0, len(xfa) - 1, 2):
        if str(xfa[i]) == "datasets":
            raw = xfa.raw_get(i + 1)
            return (raw.reference, i + 1) if isinstance(raw, generic.IndirectObject) else (None, None)
    return None, None


def diff_policy():
    """pyHanko's standard change analysis, plus: rewriting the XFA form data counts as form filling.

    That is how Acrobat treats it. XFA forms keep their data (the ``datasets`` packet) apart from
    the AcroForm fields, so filling an XFA form after a signature updates that packet. Only an
    in-place update of the packet object is accepted; changing the ``/XFA`` array itself, which
    could swap the form's layout or scripts, is still flagged.
    """
    from pyhanko.pdf_utils.reader import RawPdfPath
    from pyhanko.sign.diff_analysis import DEFAULT_DIFF_POLICY, ModificationLevel, StandardDiffPolicy, WhitelistRule
    from pyhanko.sign.diff_analysis.rules_api import Context, ReferenceUpdate

    class XfaDataRule(WhitelistRule):
        def apply(self, old, new):
            old_ref, index = _xfa_datasets_ref(old)
            new_ref, _ = _xfa_datasets_ref(new)
            if old_ref is None or new_ref != old_ref:
                return
            path = RawPdfPath("/Root", "/AcroForm", "/XFA", index)
            yield ReferenceUpdate(old_ref, context_checked=Context.from_absolute(old, path))

    return StandardDiffPolicy(
        global_rules=[*DEFAULT_DIFF_POLICY.global_rules, XfaDataRule().as_qualified(ModificationLevel.FORM_FILLING)],
        form_rule=DEFAULT_DIFF_POLICY.form_rule,
    )


def verify(data: bytes, extra_roots: list[x509.Certificate] = (), online: bool = False) -> list[SignatureReport]:
    from signall.chain import split_trust_store

    reader = open_reader(data)
    roots, intermediates = split_trust_store(trust_certificates(extra_roots))
    context = ValidationContext(trust_roots=roots, other_certs=intermediates, allow_fetching=online)
    policy = diff_policy()
    sources = _sources(extra_roots)
    reports = []
    for emb in reader.embedded_signatures:
        with _pyhanko_messages() as messages:
            status = validate_pdf_signature(emb, signer_validation_context=context, diff_policy=policy)
        cert = status.signing_cert
        report = SignatureReport(
            field=emb.field_name,
            signer=_name(cert.subject),
            issuer=_name(cert.issuer),
            signing_time=status.signer_reported_dt.isoformat() if status.signer_reported_dt else None,
            intact=bool(status.intact and status.valid),
            trusted=bool(status.trusted),
            covers_whole_file=status.coverage.name == "ENTIRE_FILE",
            changes_after=_CHANGES.get(status.modification_level.name, "other") if status.modification_level else "none",
            indication=status.trust_problem_indic.name if status.trust_problem_indic else None,
            messages=list(dict.fromkeys(messages)),
        )
        with _pyhanko_messages():
            report.revocation = _revocation_state(emb, extra_roots)
        embedded = {c.sha256 for c in emb.other_embedded_certs}
        if status.validation_path is not None:
            path = [*status.validation_path][::-1]  # pyHanko lists the root first
            report.certificates = [_info(c, _source(c, cert, embedded, sources)) for c in path]
            if report.certificates:
                report.certificates[-1].trust_anchor = True  # pyHanko's paths end at a trust root
        else:
            report.certificates = _trail(cert, list(emb.other_embedded_certs), embedded, sources)
        report.problem = _explain(report, cert, status)
        reports.append(report)
    return reports


# --- Explaining a result ---------------------------------------------------------


@contextlib.contextmanager
def _pyhanko_messages():
    """Collect pyHanko's warnings (which explain trust failures) instead of printing them."""
    messages: list[str] = []

    class Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            exc = record.exc_info[1] if record.exc_info else None
            text = getattr(exc, "failure_msg", None) or (str(exc) if exc else record.getMessage())
            messages.append(" ".join(str(text).split()))

    logger = logging.getLogger("pyhanko")
    handler = Collect(logging.WARNING)
    saved = logger.level, logger.propagate
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    logger.addHandler(handler)
    try:
        yield messages
    finally:
        logger.removeHandler(handler)
        logger.setLevel(saved[0])
        logger.propagate = saved[1]


def _name(name: x509.Name) -> str:
    return name.native.get("common_name") or name.human_friendly


def _sources(extra_roots) -> dict[bytes, str]:
    from signall.trust import dod_intermediates, dod_roots

    out = {}
    for key, certs in (("extra", extra_roots), ("system", system_trust_roots()),
                       ("dod", [*dod_roots(), *dod_intermediates()])):
        out.update({c.sha256: key for c in certs})
    return out


def _source(cert, signer, embedded: set[bytes], sources: dict[bytes, str]) -> str:
    if cert.sha256 == signer.sha256:
        return "signer"
    if cert.sha256 in sources:
        return sources[cert.sha256]
    return "signature" if cert.sha256 in embedded else "fetched"


def _info(cert: x509.Certificate, source: str) -> CertificateInfo:
    usage = cert.key_usage_value
    return CertificateInfo(
        name=_name(cert.subject), issuer=_name(cert.issuer), serial=format(cert.serial_number, "x"),
        valid_from=cert.not_valid_before.date().isoformat(), valid_until=cert.not_valid_after.date().isoformat(),
        key_usage=", ".join(sorted(usage.native)).replace("_", " ") if usage is not None else "",
        sha256=cert.sha256.hex(), source=source,
    )


def _ca_issuers_url(cert: x509.Certificate) -> str | None:
    for access in cert.authority_information_access_value or []:
        if access["access_method"].native == "ca_issuers" and access["access_location"].name == "uniform_resource_identifier":
            return access["access_location"].native
    return None


def _trail(signer, embedded_certs, embedded: set[bytes], sources: dict[bytes, str]) -> list[CertificateInfo]:
    """The signer's certificate and the issuers Signall can find by name, up to a root or a missing CA.

    Used when no validation path could be built, to show where the chain breaks.
    """
    from signall.trust import dod_intermediates, dod_roots

    pool = [*embedded_certs, *system_trust_roots(), *dod_roots(), *dod_intermediates()]
    trail = [_info(signer, "signer")]
    cert, seen = signer, {signer.sha256}
    for _ in range(10):
        if cert.self_signed != "no":
            break
        candidates = [c for c in pool if c.subject == cert.issuer and c.sha256 not in seen]
        aki = cert.authority_key_identifier
        if aki is not None:
            candidates = [c for c in candidates if c.key_identifier in (None, aki)]
        if not candidates:
            trail.append(CertificateInfo(name=_name(cert.issuer), issuer="", missing=True,
                                         download_url=_ca_issuers_url(cert)))
            break
        cert = candidates[0]
        seen.add(cert.sha256)
        trail.append(_info(cert, _source(cert, signer, embedded, sources)))
    return trail


_TRUST_PROBLEMS = {
    "OUT_OF_BOUNDS_NO_POE": "The signer's certificate has expired ({horizon}), and the signature has no "
                            "trusted timestamp to prove it was made before then.",
    "OUT_OF_BOUNDS_NOT_REVOKED": "The signer's certificate has expired ({horizon}), and the signature has no "
                                 "trusted timestamp to prove it was made before then.",
    "EXPIRED": "A certificate in the chain has expired ({horizon}).",
    "NOT_YET_VALID": "A certificate in the chain was not valid yet at the time of checking.",
    "REVOKED_NO_POE": "The signer's certificate was revoked ({horizon}).",
    "REVOKED_CA_NO_POE": "A CA certificate in the chain was revoked ({horizon}).",
    "CRYPTO_CONSTRAINTS_FAILURE": "The signature or a certificate uses an algorithm that is no longer accepted.",
    "CRYPTO_CONSTRAINTS_FAILURE_NO_POE": "The signature or a certificate uses an algorithm that is no longer "
                                         "accepted.",
    "TRY_LATER": "The revocation data needed to check the certificate is out of date.",
    "NO_POE": "The certificate could only be checked with proof of when the signature was made, which it lacks.",
}


def _explain(report: SignatureReport, cert: x509.Certificate, status) -> str | None:
    if not report.intact:
        return ("The signed content doesn't match the signature: the document was altered after it was signed, "
                "or the signature is damaged.")
    if not report.trusted:
        return _trust_problem(report, cert, status)
    if report.changes_after == "other":
        return "The document was changed after it was signed, beyond filling in the form or adding comments."
    return None


def _trust_problem(report: SignatureReport, cert: x509.Certificate, status) -> str:
    from signall.trust import bundle_version

    indication = report.indication or ""
    last = report.certificates[-1] if report.certificates else None
    if indication == "NO_CERTIFICATE_CHAIN_FOUND" or (last is not None and last.missing):
        if last is not None and last.missing:
            return (f"The certificate was issued by “{last.name}”, which Signall doesn't have. It isn't among "
                    f"Signall's DoD certificates (version {bundle_version()}) or this computer's trusted "
                    f"certificates, and the signature doesn't include it.")
        if last is not None and len(report.certificates) > 1 and last.source not in ("dod", "system", "extra"):
            return (f"The certificate chain ends at “{last.name}”, which is not a trusted root. Signall trusts "
                    "the DoD root CAs and this computer's trusted certificates.")
        return "Signall couldn't connect the signer's certificate to a trusted root CA."
    if indication == "CHAIN_CONSTRAINTS_FAILURE":
        usage = cert.key_usage_value
        if usage is not None and "non_repudiation" not in usage.native:
            have = ", ".join(sorted(usage.native)).replace("_", " ")
            return ("The signer's certificate isn't meant for signing documents: its key usage is "
                    f"“{have}” and lacks “non-repudiation”. This happens when a document is signed with a "
                    "CAC's authentication certificate instead of its signing certificate.")
        return "A certificate in the chain may not be used this way (key usage or policy constraints)."
    horizon = status.error_time_horizon
    template = _TRUST_PROBLEMS.get(indication)
    if template:
        when = f"on {horizon.date().isoformat()}" if horizon else "date unknown"
        return template.format(horizon=when).replace(" (date unknown)", "")
    return "The signer's certificate chain could not be validated."


def describe(report: SignatureReport, *, private: bool = True) -> str:
    """A plain-text account of one signature for a bug report.

    With ``private``, the signer's name and DoD ID number (EDIPI) are left out.
    """
    from importlib.metadata import PackageNotFoundError, version

    from signall import __version__
    from signall.trust import bundle_version

    def hide(text: str) -> str:
        if not private:
            return text
        text = text.replace(report.signer, "[signer]") if report.signer else text
        return re.sub(r"(?<!\d)\d{10}(?!\d)", "[EDIPI]", text)

    try:
        pyhanko = version("pyHanko")
    except PackageNotFoundError:
        pyhanko = "unknown"
    state = "valid" if report.ok else ("not trusted" if report.intact and report.changes_after != "other"
                                       else "NOT VALID")
    lines = [
        f"Signall {__version__}, DoD certificates {bundle_version()}, pyHanko {pyhanko}",
        f"Field: {report.field}",
        f"Result: {state}" + (f" ({report.indication})" if report.indication else ""),
    ]
    if report.problem:
        lines.append(f"Why: {hide(report.problem)}")
    lines += [
        f"Signed by: {hide(report.signer)}",
        f"Signing time: {report.signing_time or 'not recorded'}",
        f"Signed content intact: {'yes' if report.intact else 'NO'}",
        f"Covers the whole file: {'yes' if report.covers_whole_file else 'no'}; "
        f"later changes: {report.changes_after}",
        f"Revocation data: {report.revocation}",
        "Certificates, signer first:",
    ]
    for i, c in enumerate(report.certificates, 1):
        if c.missing:
            lines.append(f"  {i}. {hide(c.name)}: NOT FOUND" + (f" (download: {c.download_url})" if c.download_url else ""))
            continue
        lines.append(f"  {i}. {hide(c.name)}" + (" [trust anchor]" if c.trust_anchor else ""))
        lines.append(f"     issued by {hide(c.issuer)}; valid {c.valid_from} to {c.valid_until}; "
                     f"source: {SOURCES.get(c.source, c.source)}")
        if c.key_usage:
            lines.append(f"     key usage: {c.key_usage}")
        if c.source != "signer" or not private:
            lines.append(f"     serial {c.serial}; SHA-256 {c.sha256}")
    for message in report.messages:
        lines.append(f"pyHanko: {hide(message)}")
    return "\n".join(lines)
