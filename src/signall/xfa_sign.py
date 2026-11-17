"""Prepare a dynamic XFA form for signing, the way Acrobat does.

Everything happens in one incremental update on top of the original bytes:

* the ``datasets`` packet gets the filled values (and the date the form's own
  script would stamp next to the signature);
* every page gets pre-rendered content, so non-Adobe viewers show the form;
* every XFA signature field gets an AcroForm ``/Sig`` widget named by its SOM
  path, which Acrobat binds back to the XFA field;
* ``/XFA``, ``/NeedsRendering`` and the usage-rights signature are left alone.
"""
from __future__ import annotations

import datetime
import io
from typing import Callable

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name, pdf_string
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader

from signall.pdf import SignallError, get as pget, open_writer, rect
from signall.render import RenderResult, SignatureFieldSpec
from signall.xfa import Datasets, SignatureField, Template, XfaPackets, printd

Renderer = Callable[[bytes, list[SignatureFieldSpec]], RenderResult]


def _css_font(field: SignatureField) -> str:
    cap = field.caption
    if cap is None:
        return ""
    weight = "bold " if cap.bold else ""
    # pdf.js lays XFA out in points and scales the whole layer, so px here means pt on paper.
    return f"{weight}{cap.size_pt:g}px \"{cap.typeface}\", \"Liberation Sans\", Arial, sans-serif"


def _specs(fields: list[SignatureField]) -> list[SignatureFieldSpec]:
    return [
        SignatureFieldSpec(path=f.names, caption=f.caption.text if f.caption else "", css_font=_css_font(f))
        for f in fields
    ]


def _replace_packet(writer: IncrementalPdfFileWriter, packets: XfaPackets, name: str, data: bytes) -> None:
    index = packets.index(name)
    if index is None:
        raise SignallError(f"the form has no XFA {name} packet")
    ref = packets.array.raw_get(index)
    if isinstance(ref, generic.IndirectObject):
        # Rewrite the packet in place: the /XFA array stays the same, which is how change analysis
        # (signall.verify's XFA data rule) recognizes the update as form filling.
        stream = ref.get_object()
        stream.strip_filters()
        stream._data = stream._encoded_data = data
        stream.compress()
        writer.mark_update(ref)
        return
    packets.array[index] = writer.add_object(generic.StreamObject(stream_data=data))
    xfa_ref = writer.root["/AcroForm"].raw_get("/XFA")
    if isinstance(xfa_ref, generic.IndirectObject):
        writer.update_container(packets.array)
    else:
        writer.update_container(writer.root["/AcroForm"])


def _update_datasets(datasets: Datasets, values: dict[str, str], target: SignatureField | None,
                     now: datetime.datetime) -> None:
    for path, value in values.items():
        datasets.set(path, value)
    if target is not None and target.date_data_path and target.date_format:
        if not (datasets.get(target.date_data_path) or "").strip():
            datasets.set(target.date_data_path, printd(target.date_format, now))


def _layout_input(data: bytes, datasets_xml: bytes) -> bytes:
    """A copy that pdf.js will lay out as pure XFA: new data, no AcroForm widgets."""
    writer = open_writer(data)
    packets = XfaPackets.from_root(writer.root)
    _replace_packet(writer, packets, "datasets", datasets_xml)
    acroform = writer.root["/AcroForm"]
    acroform[pdf_name("/Fields")] = generic.ArrayObject()
    writer.update_container(acroform)
    writer.update_root()
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def _set_page_content(writer: IncrementalPdfFileWriter, page_ref, rendered: PdfFileReader, index: int) -> None:
    src = rendered.root["/Pages"]["/Kids"][index]
    contents = src["/Contents"]
    if isinstance(contents, generic.ArrayObject):
        stream = b"\n".join(c.get_object().data for c in contents)
    else:
        stream = contents.data
    box = [float(v) for v in pget(src, "/MediaBox", [0, 0, 612, 792])]
    form = generic.StreamObject({
        pdf_name("/Type"): pdf_name("/XObject"),
        pdf_name("/Subtype"): pdf_name("/Form"),
        pdf_name("/BBox"): rect(box),
        pdf_name("/Resources"): writer.import_object(src["/Resources"]),
    }, stream_data=stream)
    page = page_ref.get_object()
    page[pdf_name("/MediaBox")] = rect(box)
    page[pdf_name("/Resources")] = generic.DictionaryObject({
        pdf_name("/XObject"): generic.DictionaryObject({pdf_name("/SignallRendered"): writer.add_object(form)}),
    })
    page[pdf_name("/Contents")] = writer.add_object(generic.StreamObject(stream_data=b"q /SignallRendered Do Q\n"))
    writer.update_container(page)


def _ensure_pages(writer: IncrementalPdfFileWriter, count: int) -> list[generic.IndirectObject]:
    pages = writer.root["/Pages"]
    kids = pages["/Kids"]
    if any(pget(kid, "/Type") == "/Pages" for kid in kids):
        raise SignallError("nested page trees in XFA forms are not supported yet")
    while len(kids) < count:
        page = generic.DictionaryObject({
            pdf_name("/Type"): pdf_name("/Page"),
            pdf_name("/Parent"): writer.root.raw_get("/Pages"),
            pdf_name("/MediaBox"): rect([0, 0, 612, 792]),
            pdf_name("/Resources"): generic.DictionaryObject(),
        })
        kids.append(writer.add_object(page))
    pages[pdf_name("/Count")] = generic.NumberObject(len(kids))
    writer.update_container(pages)
    return [kids.raw_get(i) for i in range(len(kids))]


def _existing_field_names(acroform) -> set[str]:
    names: set[str] = set()

    def walk(node, prefix: str) -> None:
        node = node.get_object()
        name = prefix + str(pget(node, "/T", ""))
        names.add(name)
        for kid in pget(node, "/Kids", []):
            walk(kid, name + ".")

    for f in pget(acroform, "/Fields", []):
        walk(f, "")
    return names


def _add_widgets(writer: IncrementalPdfFileWriter, fields: list[SignatureField], render: RenderResult,
                 page_refs: list) -> None:
    acroform = writer.root["/AcroForm"]
    existing = _existing_field_names(acroform)
    top = acroform["/Fields"]
    nodes: dict[str, generic.IndirectObject] = {}

    def find_or_make(parts: list[str]) -> generic.IndirectObject:
        key = ".".join(parts)
        if key in nodes:
            return nodes[key]
        siblings = top if len(parts) == 1 else find_or_make(parts[:-1]).get_object()["/Kids"]
        for ref in siblings:
            if str(pget(ref, "/T", "")) == parts[-1]:
                nodes[key] = ref
                return ref
        node = generic.DictionaryObject({pdf_name("/T"): pdf_string(parts[-1]), pdf_name("/Kids"): generic.ArrayObject()})
        if len(parts) > 1:
            node[pdf_name("/Parent")] = nodes[".".join(parts[:-1])]
        ref = writer.add_object(node)
        siblings.append(ref)
        if len(parts) > 1:
            writer.update_container(nodes[".".join(parts[:-1])].get_object())
        nodes[key] = ref
        return ref

    placements = {p.spec.path: p for p in render.fields}
    annots: dict[int, list] = {}
    for f in fields:
        if f.som in existing:
            continue
        placement = placements.get(f.names)
        if placement is None:
            raise SignallError(f"could not find signature field {f.som} in the rendered form")
        parts = f.som.split(".")
        parent = find_or_make(parts[:-1])
        widget = generic.DictionaryObject({
            pdf_name("/Type"): pdf_name("/Annot"),
            pdf_name("/Subtype"): pdf_name("/Widget"),
            pdf_name("/FT"): pdf_name("/Sig"),
            pdf_name("/T"): pdf_string(parts[-1]),
            pdf_name("/Parent"): parent,
            pdf_name("/F"): generic.NumberObject(4),
            pdf_name("/P"): page_refs[placement.page],
            pdf_name("/Rect"): rect(f.widget_rect(placement.rect)),
            pdf_name("/DA"): pdf_string("/TimesNewRomanPSMT 10.00 Tf 0 g"),
            pdf_name("/MK"): generic.DictionaryObject(),
        })
        if f.lock_action and (f.lock_fields or f.lock_action == "all"):
            lock = generic.DictionaryObject({
                pdf_name("/Type"): pdf_name("/SigFieldLock"),
                pdf_name("/Action"): pdf_name("/" + f.lock_action.capitalize()),
            })
            if f.lock_action != "all":
                lock[pdf_name("/Fields")] = generic.ArrayObject(pdf_string(s) for s in f.lock_fields)
            widget[pdf_name("/Lock")] = writer.add_object(lock)
        ref = writer.add_object(widget)
        parent.get_object()["/Kids"].append(ref)
        writer.update_container(parent.get_object())
        annots.setdefault(placement.page, []).append(ref)

    for index, refs in annots.items():
        page = page_refs[index].get_object()
        existing_annots = pget(page, "/Annots")
        if existing_annots is None:
            page[pdf_name("/Annots")] = generic.ArrayObject(refs)
        else:
            existing_annots = existing_annots.get_object()
            existing_annots.extend(refs)
            if isinstance(page.raw_get("/Annots"), generic.IndirectObject):
                writer.update_container(existing_annots)
        writer.update_container(page)
    if isinstance(acroform.raw_get("/Fields"), generic.IndirectObject):
        writer.update_container(top)
    writer.update_container(acroform)


def prepare(data: bytes, target_som: str | None, values: dict[str, str], renderer: Renderer,
            now: datetime.datetime | None = None) -> tuple[IncrementalPdfFileWriter, SignatureField]:
    """Return a writer holding the prepared (unsigned) update, and the field to sign."""
    now = now or datetime.datetime.now().astimezone()
    writer = open_writer(data)
    packets = XfaPackets.from_root(writer.root)
    if packets is None:
        raise SignallError("not an XFA form")
    template = packets.get("template")
    fields = Template(template).signature_fields() if template else []
    if not fields:
        raise SignallError("this form has no signature fields")
    target = resolve_field(fields, target_som)

    datasets = Datasets(packets.get("datasets") or b'<xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/"/>')
    _update_datasets(datasets, values, target, now)
    datasets_xml = datasets.to_bytes()

    render = renderer(_layout_input(data, datasets_xml), _specs(fields))
    rendered = PdfFileReader(io.BytesIO(render.pdf), strict=False)

    _replace_packet(writer, packets, "datasets", datasets_xml)
    page_refs = _ensure_pages(writer, render.page_count)
    for i in range(render.page_count):
        _set_page_content(writer, page_refs[i], rendered, i)
    _add_widgets(writer, fields, render, page_refs)
    return writer, target


def resolve_field(fields: list[SignatureField], wanted: str | None) -> SignatureField:
    if wanted is None:
        return fields[0]
    for f in fields:
        if wanted in (f.som, ".".join(f.names)):
            return f
    matches = [f for f in fields if f.som.endswith(wanted) or ".".join(f.names).endswith(wanted)]
    if len(matches) == 1:
        return matches[0]
    choices = ", ".join(f.som for f in fields)
    raise SignallError(f"no single signature field matches {wanted!r}; choose one of: {choices}")
