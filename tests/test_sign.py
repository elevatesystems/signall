import pytest

from signall.appearance import acrobat_offset, fit, text_width, wrap
from signall.document import inspect
from signall.pdf import SignallError, get as pget, open_reader
from signall.signing import SignRequest, parse_box, sign
from signall.verify import load_certificates, verify
from signall.xfa import XfaPackets


def _check(data, root_pem, count=1):
    reports = verify(data, load_certificates(root_pem))
    assert len(reports) == count
    for r in reports:
        assert r.intact and r.trusted, r
    return reports


def test_wrap_prefers_period_breaks():
    lines = wrap("DOE.JANE.QUINCY.0000000001", 20, 180)
    assert len(lines) > 1 and all(text_width(l, 20) <= 180 for l in lines)
    assert lines[1].startswith(".")


def test_fit_shrinks_to_box():
    size, lines = fit("Digitally signed by DOE.JANE.Q.0000000001\nDate: 2026.01.01", 120, 20, max_size=10)
    assert len(lines) * size * 1.15 <= 20


def test_acrobat_offset():
    assert acrobat_offset("2026.11.17 11:04:37 -0800") == "2026.11.17 11:04:37 -08'00'"


def test_parse_box():
    assert parse_box("1:72,72,288,108") == (0, (72.0, 72.0, 288.0, 108.0))
    with pytest.raises(SignallError):
        parse_box("1:300,72,100,108")


def test_sign_plain_pdf_with_new_box(pki, root_pem, plain_pdf):
    signed = sign(plain_pdf, pki.signer(), SignRequest(box=(0, (72, 72, 288, 108))))
    assert signed.startswith(plain_pdf)  # incremental: original bytes untouched
    (report,) = _check(signed, root_pem)
    assert report.signer == "DOE.JANE.Q.0000000001" and report.changes_after == "none"
    info = inspect(signed)
    assert [f.name for f in info.signature_fields] == ["Signature1"]


def test_plain_pdf_needs_a_box(pki, plain_pdf):
    with pytest.raises(SignallError, match="draw one"):
        sign(plain_pdf, pki.signer())


def test_sign_encrypted_static_xfa_keeps_usage_rights(pki, root_pem, dd2842):
    signed = sign(dd2842, pki.signer(), SignRequest(field="certAccptBy[0].sig[0]"))
    assert signed.startswith(dd2842)
    _check(signed, root_pem)
    info = inspect(signed)
    assert info.encrypted and info.usage_rights
    assert [f.signed for f in info.signature_fields] == [True, False]


def test_second_signer_on_static_xfa(pki, root_pem, dd2842):
    first = sign(dd2842, pki.signer(), SignRequest(field="certAccptBy[0].sig[0]"))
    second = sign(first, pki.signer(pki.supervisor), SignRequest())
    reports = _check(second, root_pem, count=2)
    assert reports[0].changes_after in ("none", "form filling")


@pytest.mark.render
def test_sign_dynamic_xfa_like_acrobat(pki, root_pem, dd2875, tmp_path):
    values = {"form1.page1.Part1.Organization": "Signall Test Org", "form1.page1.Part1.userName": "Doe, Jane, Q"}
    signed = sign(dd2875, pki.signer(), SignRequest(values=values))
    assert signed.startswith(dd2875)
    (report,) = _check(signed, root_pem)
    assert report.field == "form1[0].page1[0].Part1[0].userSig[0].userSig[0]"
    assert report.covers_whole_file

    reader = open_reader(signed)
    root = reader.root
    assert root["/NeedsRendering"] and "/UR3" in root["/Perms"]  # Reader needs both
    assert int(root["/Pages"]["/Count"]) == 3
    info = inspect(signed)
    assert len(info.signature_fields) == 7
    from signall.xfa import Datasets

    ds = Datasets(XfaPackets.from_root(root).get("datasets"))
    assert ds.get("form1.page1.Part1.Organization") == "Signall Test Org"
    assert len(ds.get("form1.page1.Part1.userSig.signedDate")) == 8

    # The widget sits where Acrobat puts it (from the Acrobat-signed reference file).
    widget = next(w for w in _widgets(reader) if str(pget(w, "/T")) == "userSig[0]")
    for ours, acrobat in zip([float(v) for v in widget["/Rect"]], (19.08, 375.092, 448.92, 397.412)):
        assert abs(ours - acrobat) < 1.5

    # The pre-rendered page shows the filled data to non-Adobe viewers.
    page = root["/Pages"]["/Kids"][0]
    assert "/SignallRendered" in page["/Resources"]["/XObject"]
    (tmp_path / "dd2875-signed.pdf").write_bytes(signed)


@pytest.mark.render
def test_supervisor_countersigns_dynamic_xfa(pki, root_pem, dd2875):
    first = sign(dd2875, pki.signer(), SignRequest())
    second = sign(first, pki.signer(pki.supervisor), SignRequest(
        field="Supervisor[0].Sig[0]", values={"form1.page1.Part2.Supervisor.Name": "Roe, Richard"}))
    _check(second, root_pem, count=2)
    # The supervisor's re-render shows the new data to non-Adobe viewers.
    import pymupdf

    text = pymupdf.open(stream=second, filetype="pdf")[0].get_text()
    assert "Roe, Richard" in text
    # pyHanko's generic change analysis reports the supervisor's re-rendered pages as "other"
    # changes; an XFA-aware policy is on the roadmap. Acrobat is the reference for this case.
    reader = open_reader(second)
    supervisor = next(w for w in _widgets(reader) if "/Lock" in w)
    assert str(supervisor["/Lock"]["/Action"]) == "/Include"


def _widgets(reader):
    for page in reader.root["/Pages"]["/Kids"]:
        for annot in pget(page, "/Annots", []):
            yield annot.get_object()
