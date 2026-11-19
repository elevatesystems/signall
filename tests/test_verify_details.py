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
