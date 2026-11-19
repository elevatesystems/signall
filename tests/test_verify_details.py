"""Explaining why a signature is or isn't trusted, and the signature details dialog."""
import re
from pathlib import Path

import pytest
from pyhanko.sign import signers
from pyhanko_certvalidator.registry import SimpleCertificateStore

from signall import verify as verify_module
from signall.signing import SignRequest, sign
from signall.verify import describe, verify

BOX = SignRequest(box=(0, (72, 72, 288, 108)))
APP = Path(verify_module.__file__).parent / "app"


@pytest.fixture(autouse=True)
def no_system_trust(monkeypatch):
    """Keep the host's trust store out of these tests."""
    monkeypatch.setattr(verify_module, "system_trust_roots", lambda: [])


def _signer(pki, who=None, chain=None):
    """Like pki.signer(), but embedding only ``chain`` (default: the whole chain)."""
    signer = pki.signer(who)
    if chain is None:
        return signer
    return signers.SimpleSigner(signing_cert=signer.signing_cert, signing_key=signer.signing_key,
                                cert_registry=SimpleCertificateStore.from_certs(chain))


def test_trusted_signature_lists_its_chain(pki, plain_pdf):
    (report,) = verify(sign(plain_pdf, _signer(pki), BOX), [pki.root.asn1])
    assert report.ok and report.problem is None and report.indication is None
    assert [c.name for c in report.certificates] == [
        "DOE.JANE.Q.0000000001", "SIGNALL TEST EMAIL CA-1", "Signall Test Root CA"]
    assert [c.source for c in report.certificates] == ["signer", "signature", "extra"]
    assert report.certificates[-1].trust_anchor
    assert report.certificates[0].key_usage == "digital signature, non repudiation"


def test_untrusted_root_is_named(pki, plain_pdf):
    (report,) = verify(sign(plain_pdf, _signer(pki), BOX))
    assert report.intact and not report.trusted
    assert report.indication == "NO_CERTIFICATE_CHAIN_FOUND"
    assert report.certificates[-1].name == "Signall Test Root CA" and not report.certificates[-1].missing
    assert "ends at “Signall Test Root CA”, which is not a trusted root" in report.problem
    assert report.messages  # pyHanko's own explanation is kept


def test_missing_intermediate_is_named(pki, plain_pdf):
    (report,) = verify(sign(plain_pdf, _signer(pki, chain=[]), BOX), [pki.root.asn1])
    assert not report.trusted
    assert [c.missing for c in report.certificates] == [False, True]
    assert report.certificates[-1].name == "SIGNALL TEST EMAIL CA-1"
    assert "issued by “SIGNALL TEST EMAIL CA-1”, which Signall doesn't have" in report.problem


def test_authentication_certificate_is_explained(pki, plain_pdf):
    (report,) = verify(sign(plain_pdf, _signer(pki, pki.auth), BOX), [pki.root.asn1])
    assert report.intact and not report.trusted
    assert report.indication == "CHAIN_CONSTRAINTS_FAILURE"
    assert "authentication certificate" in report.problem


def test_describe_leaves_out_the_signer(pki, plain_pdf):
    (report,) = verify(sign(plain_pdf, _signer(pki), BOX))
    text = describe(report)
    assert "DOE.JANE" not in text and "0000000001" not in text
    assert "Signall Test Root CA" in text and "NO_CERTIFICATE_CHAIN_FOUND" in text
    assert "DOE.JANE.Q.0000000001" in describe(report, private=False)


def test_rows_without_a_report_say_why(dd2842):
    from signall.app.model import Document

    doc = Document.load(Path("x.pdf"), dd2842)
    for row in doc.rows:
        row.signed = True
    doc.apply_reports([], "ValueError: broken")
    assert all(r.status == "error" and r.error == "ValueError: broken" for r in doc.rows)


def test_every_interface_icon_has_a_fallback():
    names = set()
    for source in APP.glob("*.py"):
        names |= set(re.findall(r'"([a-z-]+-symbolic)"', source.read_text()))
    bundled = {p.stem for p in (APP / "icons").glob("*.svg")}
    assert names and names <= bundled, f"add these to src/signall/app/icons: {sorted(names - bundled)}"


def _self_signed_id():
    """Like Acrobat's "Create a new Digital ID": self-signed, digital signature only, email in the name."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from pyhanko.keys import load_cert_from_pemder, load_private_key_from_pemder_data

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Jane Example"),
                      x509.NameAttribute(NameOID.EMAIL_ADDRESS, "jane.example@mail.test"),
                      x509.NameAttribute(NameOID.COUNTRY_NAME, "US")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=5 * 365))
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    signing_key = load_private_key_from_pemder_data(
        key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()), passphrase=None)
    from asn1crypto import x509 as asn1_x509

    return signers.SimpleSigner(signing_cert=asn1_x509.Certificate.load(der), signing_key=signing_key,
                                cert_registry=SimpleCertificateStore())


def test_self_signed_digital_id_is_explained_and_kept_private(plain_pdf):
    (report,) = verify(sign(plain_pdf, _self_signed_id(), BOX))
    assert report.intact and not report.trusted
    assert "self-signed certificate" in report.problem and "CAC" in report.problem
    text = describe(report)
    assert "Jane Example" not in text and "jane.example" not in text and "mail.test" not in text
    assert "Result: not trusted" in text
