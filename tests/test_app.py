"""The app's document logic (no display needed, except where marked)."""
import base64
from pathlib import Path

import pytest

from signall import xfa_sign
from signall.app.model import (
    CardStatus, Document, card_status, display_name, output_name, pdf_date, run_signing, sentence_case,
)
from signall.pdf import SignallError, open_reader
from signall.signing import SignRequest
from signall.verify import SignatureReport, load_certificates, verify
from signall.xfa import Datasets, XfaPackets

from conftest import TOKEN_PIN


def test_display_name():
    assert display_name("DOE.JANE.QUINCY.0000000001") == "Jane Quincy Doe"
    assert display_name("DOE.JANE.Q.0000000001") == "Jane Q. Doe"
    assert display_name("Signall Test Root CA") == "Signall Test Root CA"
    assert display_name(None) == "Unknown signer"


def test_pdf_date():
    assert pdf_date("D:20261117145903-08'00'") == "2026-11-17 14:59"
    assert pdf_date(None) is None


def test_sentence_case_keeps_acronyms():
    assert sentence_case("ISSO OR APPOINTEE SIGNATURE") == "ISSO or appointee signature"
    assert sentence_case("INFORMATION OWNER/OPR SIGNATURE") == "Information owner/OPR signature"


def test_output_name():
    assert output_name(Path("form.pdf")) == "form - signed.pdf"
    assert output_name(Path("form - signed.pdf")) == "form - signed.pdf"


def _trusted(root_pem, pki):
    # Offline, the signature carries no chain; a DoD machine has the intermediates bundled.
    return load_certificates(root_pem) + [pki.email_ca.asn1]


def _doc(data: bytes, name: str = "form.pdf") -> Document:
    return Document.load(Path(name), data)


def test_rejects_non_pdf():
    with pytest.raises(SignallError, match="not a PDF"):
        _doc(b"hello")


def test_dynamic_xfa_rows(dd2875):
    doc = _doc(dd2875)
    assert doc.dynamic_xfa and not doc.can_draw_box
    labels = [r.label for r in doc.rows]
    assert labels[:4] == ["User signature", "Supervisor signature", "Information owner/OPR signature",
                          "ISSO or appointee signature"]
    assert all(r.path and not r.signed for r in doc.rows)


def test_static_xfa_rows(dd2842):
    doc = _doc(dd2842)
    assert [r.label for r in doc.rows] == ["Subscriber's signature", "Registration official's signature"]
    first = doc.rows[0]
    assert first.page == 0 and first.rect is not None and first.rect[2] > first.rect[0]


def test_plain_pdf_has_no_rows(plain_pdf):
    doc = _doc(plain_pdf)
    assert doc.rows == [] and doc.can_draw_box


def test_view_hides_widgets_of_signed_dynamic_xfa(dd2875):
    shown, config = _doc(dd2875).view()
    assert config["xfa"] and config["forms"] and len(config["fields"]) == 7
    assert shown.startswith(dd2875)  # the original plus a display-only update


def test_form_changes_from_viewer_copy(dd2875):
    doc = _doc(dd2875)
    packets = XfaPackets.from_root(open_reader(dd2875).root)
    edited = Datasets(packets.get("datasets"))
    edited.set("form1.page1.Part1.Organization", "Typed Org")
    copy = xfa_sign._layout_input(dd2875, edited.to_bytes())
    changes = doc.form_changes(base64.b64encode(copy).decode())
    assert changes == {"form1[0].page1[0].Part1[0].Organization[0]": "Typed Org"}
    assert doc.form_changes(None) == {}


def test_report_statuses(dd2842):
    doc = _doc(dd2842)
    name = doc.rows[0].name
    for intact, trusted, changes, expected in [
        (True, True, "none", "valid"), (True, False, "none", "untrusted"),
        (True, True, "other", "modified"), (False, True, "none", "invalid"),
    ]:
        doc.apply_reports([SignatureReport(name, "X", None, intact, trusted, True, changes)])
        assert doc.rows[0].status == expected


def test_card_status_reports_a_missing_module(monkeypatch):
    # (Loading a real second module would break the SoftHSM tests: one PKCS#11 module per process.)
    import signall.token

    def missing(_explicit=None):
        raise SignallError("no PKCS#11 module found; install opensc")

    monkeypatch.setattr(signall.token, "find_module", missing)
    status = card_status()
    assert status.state == "error" and "opensc" in status.message


def test_card_status_finds_the_signing_certificate(softhsm):
    status = card_status(softhsm)
    assert status.state == "ready"
    assert status.signer == "Jane Q. Doe" and status.issuer == "SIGNALL TEST EMAIL CA-1"
    assert card_status(softhsm, previous=status) is status  # the same card is not read again


def test_app_signs_drawn_box_with_card(softhsm, plain_pdf, root_pem, pki):
    asked = []

    def ask_pin(_token, cert):
        asked.append(cert.subject)
        return TOKEN_PIN

    outcome = run_signing(_doc(plain_pdf), SignRequest(box=(0, (72, 72, 288, 108))), ask_pin=ask_pin,
                          module=softhsm, online=False)
    assert len(asked) == 1
    (report,) = verify(outcome.data, _trusted(root_pem, pki))
    assert report.intact and report.trusted


def test_app_cancelled_pin_signs_nothing(softhsm, plain_pdf):
    def ask_pin(_token, _cert):
        raise SignallError("cancelled")

    with pytest.raises(SignallError, match="cancelled"):
        run_signing(_doc(plain_pdf), SignRequest(box=(0, (72, 72, 288, 108))), ask_pin=ask_pin,
                    module=softhsm, online=False)


@pytest.mark.render
def test_app_signs_dynamic_xfa_with_typed_values(softhsm, dd2875, root_pem, pki):
    doc = _doc(dd2875)
    request = SignRequest(field=doc.rows[0].name, values={"form1[0].page1[0].Part1[0].Organization[0]": "Typed Org"})
    outcome = run_signing(doc, request, ask_pin=lambda *_: TOKEN_PIN, module=softhsm, online=False)
    signed = _doc(outcome.data)
    assert signed.rows[0].signed and signed.rows[0].signer == "Jane Q. Doe"
    ds = Datasets(XfaPackets.from_root(open_reader(outcome.data).root).get("datasets"))
    assert ds.get("form1.page1.Part1.Organization") == "Typed Org"
    (report,) = verify(outcome.data, _trusted(root_pem, pki))
    assert report.intact and report.trusted
