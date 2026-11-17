"""Filling AcroForm fields in the signed update."""
import pymupdf
import pytest

from signall.document import inspect
from signall.pdf import SignallError, get as pget, open_reader
from signall.signing import SignRequest, sign
from signall.verify import load_certificates, verify

BOX = (0, (72, 300, 288, 340))


def _values(data: bytes) -> dict:
    doc = pymupdf.open(stream=data, filetype="pdf")
    out = {}
    for page in doc:
        for w in page.widgets():
            if w.field_type == pymupdf.PDF_WIDGET_TYPE_RADIOBUTTON:
                if w.field_value not in (False, "Off", None):
                    out[w.field_name] = w.on_state()
            elif w.field_type != pymupdf.PDF_WIDGET_TYPE_SIGNATURE:
                out[w.field_name] = w.field_value
    return out


def _appearance(data: bytes, name: str) -> bytes:
    reader = open_reader(data)
    for field in pget(reader.root["/AcroForm"], "/Fields"):
        field = field.get_object()
        if str(pget(field, "/T")) == name:
            widget = pget(field, "/Kids", [field])[0].get_object()  # pymupdf puts the widget in /Kids
            return pget(widget, "/AP")["/N"].get_object().data
    raise KeyError(name)


def test_fills_text_check_box_and_radio(pki, root_pem, acroform_pdf):
    signed = sign(acroform_pdf, pki.signer(), SignRequest(box=BOX, fields={
        "name": "Jane Q. Doe", "notes": "First line of a longer note that has to wrap inside its box.",
        "agree": True, "status": "Civilian",
    }))
    assert signed.startswith(acroform_pdf)
    values = _values(signed)
    assert values["name"] == "Jane Q. Doe"
    assert values["notes"].startswith("First line")
    assert values["agree"] in (True, "Yes")
    assert values["status"] == "Civilian"
    assert b"(Jane Q. Doe) Tj" in _appearance(signed, "name")
    assert _appearance(signed, "notes").count(b"Tj") > 1  # wrapped
    (report,) = verify(signed, load_certificates(root_pem))
    assert report.intact and report.trusted and report.covers_whole_file


def test_later_signer_fills_fields_as_form_filling(pki, root_pem, dd2842):
    # The DD 2842's fields are merged field/widget dictionaries, as Adobe's tools write them.
    # (pyHanko's change analysis doesn't account for appearances on separate /Kids widgets.)
    first = sign(dd2842, pki.signer(), SignRequest(field="certAccptBy[0].sig[0]", fields={
        "form1[0].page1[0].certAccptBy[0].name[0]": "Doe, Jane Q"}))
    second = sign(first, pki.signer(pki.supervisor), SignRequest(field="RegOfficial[0].sig[0]", fields={
        "form1[0].page1[0].RegOfficial[0].name[0]": "Roe, Richard"}))
    reports = verify(second, load_certificates(root_pem))
    assert len(reports) == 2 and all(r.intact and r.trusted for r in reports)
    assert reports[0].changes_after == "form filling"
    assert _values(second)["form1[0].page1[0].RegOfficial[0].name[0]"] == "Roe, Richard"


def test_fills_encrypted_static_xfa_and_keeps_usage_rights(pki, root_pem, dd2842):
    name = "form1[0].page1[0].certAccptBy[0].name[0]"
    signed = sign(dd2842, pki.signer(), SignRequest(field="certAccptBy[0].sig[0]", fields={name: "Doe, Jane Q"}))
    info = inspect(signed)
    assert info.encrypted and info.usage_rights
    values = _values(signed)
    assert values[name] == "Doe, Jane Q"
    # The form's own signing script would stamp the date as yyyymmmdd (2026Nov17); so does Signall.
    import re
    assert re.fullmatch(r"\d{4}[A-Z][a-z]{2}\d{2}", values["form1[0].page1[0].certAccptBy[0].signedDate[0]"])
    assert not values["form1[0].page1[0].RegOfficial[0].signedDate2[0]"]
    (report,) = verify(signed, load_certificates(root_pem))
    assert report.intact and report.trusted


def test_unknown_and_signature_fields_are_refused(pki, acroform_pdf, dd2842):
    with pytest.raises(SignallError, match="no form field"):
        sign(acroform_pdf, pki.signer(), SignRequest(box=BOX, fields={"nope": "x"}))
    with pytest.raises(SignallError, match="signature field"):
        sign(dd2842, pki.signer(), SignRequest(field="certAccptBy[0].sig[0]",
                                               fields={"form1[0].page1[0].RegOfficial[0].sig[0]": "x"}))


def test_dynamic_xfa_refuses_acroform_values(pki, dd2875):
    with pytest.raises(SignallError, match="XFA data"):
        sign(dd2875, pki.signer(), SignRequest(fields={"x": "y"}))
