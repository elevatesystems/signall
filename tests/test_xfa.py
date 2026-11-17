from signall.document import Kind, inspect
from signall.pdf import open_reader
from signall.xfa import Datasets, Template, XfaPackets, measure


def _template(data: bytes) -> Template:
    return Template(XfaPackets.from_root(open_reader(data).root).get("template"))


def test_measure():
    assert measure("72pt") == 72
    assert measure("1in") == 72
    assert round(measure("0.381mm"), 2) == 1.08
    assert measure(None, 5) == 5


def test_classifies_documents(plain_pdf, dd2875, dd2842):
    assert inspect(plain_pdf).kind is Kind.PLAIN
    info = inspect(dd2875)
    assert info.kind is Kind.DYNAMIC_XFA
    assert info.usage_rights and not info.encrypted
    info = inspect(dd2842)
    assert info.kind is Kind.STATIC_XFA
    assert info.encrypted and info.usage_rights
    assert [f.name for f in info.signature_fields] == [
        "form1[0].page1[0].certAccptBy[0].sig[0]", "form1[0].page1[0].RegOfficial[0].sig[0]"]


def test_dd2875_signature_fields(dd2875):
    fields = _template(dd2875).signature_fields()
    assert [f.som for f in fields] == [
        "form1[0].page1[0].Part1[0].userSig[0].userSig[0]",
        "form1[0].page1[0].Part2[0].Supervisor[0].Sig[0]",
        "form1[0].page1[0].Part2[0].ioOPR[0].Sig[0]",
        "form1[0].page1[0].Part2[0].IA[0].Sig[0]",
        "form1[0].page2[0].Part3[0].SecurityManager[0].Sig[0]",
        "form1[0].page2[0].Part4[0].Processed[0].ProcessedBy[0].ProcessedSig[0]",
        "form1[0].page2[0].Part4[0].Revalidated[0].RevalidatedBy[0].RevalidatedSig[0]",
    ]
    user, supervisor = fields[0], fields[1]
    assert user.caption.text == "11. USER SIGNATURE"
    assert user.caption.placement == "top" and round(user.caption.reserve_pt, 2) == 11.52
    assert user.date_data_path == ("form1", "page1", "Part1", "userSig", "signedDate")
    assert user.date_format == "%Y%m%d"
    assert user.lock_action is None  # matches Acrobat: no field lock on the user's signature
    assert supervisor.lock_action == "include"
    assert "form1[0].page1[0].Part1[0].userName[0]" in supervisor.lock_fields


def test_widget_rect_matches_acrobat(dd2875):
    user = _template(dd2875).signature_fields()[0]
    # The field's laid-out box (from pdf.js) and the widget Acrobat created for it.
    x0, y0, x1, y1 = user.widget_rect((18.0, 374.1, 450.0, 410.1))
    for ours, acrobat in zip((x0, y0, x1, y1), (19.08, 375.092, 448.92, 397.412)):
        assert abs(ours - acrobat) < 0.5


def test_datasets_roundtrip(dd2875):
    ds = Datasets(XfaPackets.from_root(open_reader(dd2875).root).get("datasets"))
    ds.set("form1.page1.Part1.Organization", "Example Org")
    ds.set("form1.page1.Part1.userSig.signedDate", "20260101")
    again = Datasets(ds.to_bytes())
    assert again.get("form1.page1.Part1.Organization") == "Example Org"
    assert again.get("form1.page1.Part1.userSig.signedDate") == "20260101"
    assert b"xfa:datasets" in ds.to_bytes()  # namespace prefix preserved
