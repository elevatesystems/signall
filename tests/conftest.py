"""Shared fixtures: a synthetic DoD-like PKI and a SoftHSM token shaped like a CAC.

Nothing here is real: every certificate is generated for the test run.
"""
from __future__ import annotations

import datetime
import io
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from asn1crypto import ocsp as asn1_ocsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID
from pyhanko.sign import signers

FIXTURES = Path(__file__).parent / "fixtures"
SOFTHSM_MODULE = "/usr/lib64/pkcs11/libsofthsm2.so"
TOKEN_PIN = "123456"
OCSP_URL = "http://ocsp.signall.test"  # .test never resolves; tests supply OCSP responses directly
DOCUMENT_SIGNING = x509.ObjectIdentifier("1.3.6.1.4.1.311.10.3.12")


@dataclass
class Identity:
    key: rsa.RSAPrivateKey
    cert: x509.Certificate

    @property
    def asn1(self) -> asn1_x509.Certificate:
        return asn1_x509.Certificate.load(self.cert.public_bytes(serialization.Encoding.DER))


@dataclass
class TestPki:
    root: Identity
    email_ca: Identity
    id_ca: Identity
    signing: Identity      # like PIV 9C: digitalSignature + nonRepudiation, from the EMAIL CA
    supervisor: Identity   # a second person's signing certificate
    auth: Identity         # like PIV 9A: digitalSignature only, from the ID CA
    encryption: Identity   # like PIV 9D: keyEncipherment, from the EMAIL CA

    def signer(self, who: Identity | None = None) -> signers.SimpleSigner:
        who = who or self.signing
        from pyhanko.keys import load_private_key_from_pemder_data

        key = load_private_key_from_pemder_data(
            who.key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()), passphrase=None)
        from pyhanko_certvalidator.registry import SimpleCertificateStore

        return signers.SimpleSigner(
            signing_cert=who.asn1, signing_key=key,
            cert_registry=SimpleCertificateStore.from_certs([self.email_ca.asn1, self.id_ca.asn1, self.root.asn1]),
        )


def _name(cn: str, ou: list[str]) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
             x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Signall Test Government")]
    attrs += [x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u) for u in ou]
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def _issue(subject: x509.Name, issuer: Identity | None, *, ca: bool, key_usage: dict, eku=None) -> Identity:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.cert.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(**{**dict(
            digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False,
        ), **key_usage}), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if issuer:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False)
        builder = builder.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(OCSP_URL))]), critical=False)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    cert = builder.sign(issuer.key if issuer else key, hashes.SHA256())
    return Identity(key=key, cert=cert)


def ocsp_response(cert: Identity, issuer: Identity, *, revoked: bool = False) -> asn1_ocsp.OCSPResponse:
    """An OCSP response for ``cert``, signed by its issuer, like ocsp.disa.mil would give."""
    now = datetime.datetime.now(datetime.timezone.utc)
    response = ocsp.OCSPResponseBuilder().add_response(
        cert=cert.cert, issuer=issuer.cert, algorithm=hashes.SHA1(),
        cert_status=ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD,
        this_update=now - datetime.timedelta(minutes=5), next_update=now + datetime.timedelta(days=1),
        revocation_time=now - datetime.timedelta(hours=1) if revoked else None, revocation_reason=None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, issuer.cert).sign(issuer.key, hashes.SHA256())
    return asn1_ocsp.OCSPResponse.load(response.public_bytes(serialization.Encoding.DER))


def build_pki() -> TestPki:
    root = _issue(_name("Signall Test Root CA", ["PKI"]), None, ca=True,
                  key_usage=dict(key_cert_sign=True, crl_sign=True, digital_signature=True))
    email_ca = _issue(_name("SIGNALL TEST EMAIL CA-1", ["PKI"]), root, ca=True,
                      key_usage=dict(key_cert_sign=True, crl_sign=True, digital_signature=True))
    id_ca = _issue(_name("SIGNALL TEST ID CA-1", ["PKI"]), root, ca=True,
                   key_usage=dict(key_cert_sign=True, crl_sign=True, digital_signature=True))
    person = _name("DOE.JANE.Q.0000000001", ["PKI", "TEST"])
    return TestPki(
        root=root, email_ca=email_ca, id_ca=id_ca,
        signing=_issue(person, email_ca, ca=False,
                       key_usage=dict(digital_signature=True, content_commitment=True),
                       eku=[ExtendedKeyUsageOID.EMAIL_PROTECTION, DOCUMENT_SIGNING]),
        supervisor=_issue(_name("ROE.RICHARD.A.0000000002", ["PKI", "TEST"]), email_ca, ca=False,
                          key_usage=dict(digital_signature=True, content_commitment=True),
                          eku=[ExtendedKeyUsageOID.EMAIL_PROTECTION, DOCUMENT_SIGNING]),
        auth=_issue(person, id_ca, ca=False, key_usage=dict(digital_signature=True),
                    eku=[ExtendedKeyUsageOID.CLIENT_AUTH]),
        encryption=_issue(person, email_ca, ca=False, key_usage=dict(key_encipherment=True),
                          eku=[ExtendedKeyUsageOID.EMAIL_PROTECTION]),
    )


@pytest.fixture(scope="session")
def pki() -> TestPki:
    return build_pki()


@pytest.fixture(scope="session")
def root_pem(pki, tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("trust") / "root.pem"
    path.write_bytes(pki.root.cert.public_bytes(serialization.Encoding.PEM))
    return path


def make_plain_pdf(text: str = "Certificate of Completion") -> bytes:
    """A one-page letter-size PDF with a line of text and no form."""
    content = f"BT /F1 24 Tf 72 700 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.7\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n%s\nendobj\n" % (i, body))
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1))
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref))
    return out.getvalue()


def make_acroform_pdf() -> bytes:
    """A one-page form with a text field, a multiline text field, a check box, and two radio buttons."""
    import pymupdf

    doc = pymupdf.open()
    page = doc.new_page(width=612, height=792)
    page.insert_text((72, 72), "Training Acknowledgment", fontsize=18)

    def add(kind, name, rect, **extra):
        w = pymupdf.Widget()
        w.field_type = kind
        w.field_name = name
        w.rect = pymupdf.Rect(*rect)
        for key, value in extra.items():
            setattr(w, key, value)
        page.add_widget(w)

    add(pymupdf.PDF_WIDGET_TYPE_TEXT, "name", (72, 100, 300, 120), text_fontsize=0)
    add(pymupdf.PDF_WIDGET_TYPE_TEXT, "notes", (72, 130, 300, 190), field_flags=4096, text_fontsize=10)
    add(pymupdf.PDF_WIDGET_TYPE_CHECKBOX, "agree", (72, 200, 86, 214))
    add(pymupdf.PDF_WIDGET_TYPE_RADIOBUTTON, "status", (72, 230, 86, 244), button_caption="Military")
    add(pymupdf.PDF_WIDGET_TYPE_RADIOBUTTON, "status", (120, 230, 134, 244), button_caption="Civilian")
    # pymupdf names every radio button's "on" state /None; real forms name each option.
    radios = [w for w in page.widgets() if w.field_type == pymupdf.PDF_WIDGET_TYPE_RADIOBUTTON]
    for widget, option in zip(radios, ("Military", "Civilian")):
        states = doc.xref_get_key(widget.xref, "AP/N")[1]
        doc.xref_set_key(widget.xref, "AP/N", states.replace("/None", f"/{option}"))
        doc.xref_set_key(widget.xref, "AS", "/Off")
    return doc.tobytes()


@pytest.fixture
def acroform_pdf() -> bytes:
    return make_acroform_pdf()


@pytest.fixture
def plain_pdf() -> bytes:
    return make_plain_pdf()


@pytest.fixture
def dd2875() -> bytes:
    return (FIXTURES / "dd2875-blank.pdf").read_bytes()


@pytest.fixture
def dd2842() -> bytes:
    return (FIXTURES / "dd2842-blank.pdf").read_bytes()


def _have_display() -> bool:
    try:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("WebKit", "6.0")
        from gi.repository import Gtk, WebKit  # noqa: F401

        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) and Gtk.init_check()
    except (ImportError, ValueError):
        return False


def pytest_collection_modifyitems(config, items):
    if not _have_display():
        skip = pytest.mark.skip(reason="needs WebKitGTK 6 and a display (run dev/run-tests.sh)")
        for item in items:
            if "render" in item.keywords:
                item.add_marker(skip)


# --- SoftHSM token that behaves like a CAC -------------------------------------------------

def _import_identity(session, identity: Identity, key_id: bytes, label: str, always_authenticate: bool) -> None:
    from pkcs11 import Attribute, CertificateType, KeyType, ObjectClass

    numbers = identity.key.private_numbers()
    pub = numbers.public_numbers

    def big(n: int) -> bytes:
        return n.to_bytes((n.bit_length() + 7) // 8, "big")

    session.create_object({
        Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.KEY_TYPE: KeyType.RSA,
        Attribute.TOKEN: True, Attribute.PRIVATE: True, Attribute.SENSITIVE: True, Attribute.SIGN: True,
        Attribute.ID: key_id, Attribute.LABEL: label + " Key",
        Attribute.MODULUS: big(pub.n), Attribute.PUBLIC_EXPONENT: big(pub.e),
        Attribute.PRIVATE_EXPONENT: big(numbers.d), Attribute.PRIME_1: big(numbers.p),
        Attribute.PRIME_2: big(numbers.q), Attribute.EXPONENT_1: big(numbers.dmp1),
        Attribute.EXPONENT_2: big(numbers.dmq1), Attribute.COEFFICIENT: big(numbers.iqmp),
        Attribute.ALWAYS_AUTHENTICATE: always_authenticate,
    })
    session.create_object({
        Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
        Attribute.TOKEN: True, Attribute.ID: key_id, Attribute.LABEL: label,
        Attribute.SUBJECT: identity.cert.subject.public_bytes(),
        Attribute.VALUE: identity.cert.public_bytes(serialization.Encoding.DER),
    })


@pytest.fixture(scope="session")
def softhsm(pki, tmp_path_factory) -> str:
    """A SoftHSM token holding CAC-like certificates; returns the module path."""
    if not Path(SOFTHSM_MODULE).is_file() or not shutil.which("softhsm2-util"):
        pytest.skip("SoftHSM2 is not installed")
    base = tmp_path_factory.mktemp("softhsm")
    (base / "tokens").mkdir()
    conf = base / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {base / 'tokens'}\nobjectstore.backend = file\nlog.level = ERROR\n")
    os.environ["SOFTHSM2_CONF"] = str(conf)
    subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "SIGNALL TEST CAC",
                    "--so-pin", "87654321", "--pin", TOKEN_PIN], check=True, capture_output=True)
    import pkcs11

    token = pkcs11.lib(SOFTHSM_MODULE).get_token(token_label="SIGNALL TEST CAC")
    with token.open(rw=True, user_pin=TOKEN_PIN) as session:
        _import_identity(session, pki.auth, b"\x01", "Certificate for PIV Authentication", False)
        _import_identity(session, pki.signing, b"\x02", "Certificate for Digital Signature", True)
        _import_identity(session, pki.encryption, b"\x03", "Certificate for Key Management", False)
    return SOFTHSM_MODULE
