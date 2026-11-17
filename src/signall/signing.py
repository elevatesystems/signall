"""Sign a PDF: pick or create the field, prepare XFA forms, apply the signature."""
from __future__ import annotations

import datetime
import io
import re
from dataclasses import dataclass, field as dataclass_field

from pyhanko.sign import fields as sig_fields
from pyhanko.sign import signers
from pyhanko.sign.general import SigningError

from signall.appearance import AcrobatStampStyle
from signall.document import Kind, inspect
from signall.pdf import SignallError, open_writer
from signall.xfa import Datasets, XfaPackets, printd
from signall import acroform, xfa_sign


@dataclass
class SignRequest:
    field: str | None = None
    """Name of an existing signature field (for XFA forms, its SOM path or a unique suffix)."""
    box: tuple[int, tuple[float, float, float, float]] | None = None
    """Create a new field instead: (page index, (x0, y0, x1, y1)) in PDF points."""
    values: dict[str, str] = dataclass_field(default_factory=dict)
    """XFA data values to fill before signing, keyed by data path (form1.page1.Part1.Organization)."""
    fields: dict[str, object] = dataclass_field(default_factory=dict)
    """AcroForm values to fill before signing, keyed by field name: text, a radio export value, or a bool."""
    reason: str | None = None
    location: str | None = None


def _signer_name(signer: signers.Signer) -> str:
    cert = signer.signing_cert
    return cert.subject.native.get("common_name") or cert.subject.human_friendly


def _new_field_name(existing: list[str]) -> str:
    taken = set(existing)
    n = 1
    while f"Signature{n}" in taken:
        n += 1
    return f"Signature{n}"


def _apply_values_static(writer, values: dict[str, str]) -> None:
    if not values:
        return
    packets = XfaPackets.from_root(writer.root)
    if packets is None:
        raise SignallError("filling values is only supported for XFA forms so far")
    datasets = Datasets(packets.get("datasets"))
    for path, value in values.items():
        datasets.set(path, value)
    xfa_sign._replace_packet(writer, packets, "datasets", datasets.to_bytes())


def sign(data: bytes, signer: signers.Signer, request: SignRequest | None = None, *,
         renderer: xfa_sign.Renderer | None = None, now: datetime.datetime | None = None,
         validation_context=None) -> bytes:
    """Sign ``data`` and return the signed PDF bytes (the original plus one incremental update).

    With a ``validation_context`` (see :func:`signall.chain.prepare_embedding`), the OCSP and CRL
    responses it holds are embedded Acrobat-style, in the adbe-revocationInfoArchival attribute.
    """
    request = request or SignRequest()
    now = now or datetime.datetime.now().astimezone()
    info = inspect(data)
    name = _signer_name(signer)
    new_field = None

    if info.kind is Kind.DYNAMIC_XFA:
        if request.fields:
            raise SignallError("dynamic XFA forms are filled through their XFA data, not AcroForm fields")
        if request.box is not None:
            raise SignallError("dynamic XFA forms can only be signed in their own signature fields")
        if renderer is None:
            from signall.render import render_xfa as renderer
        signed = {f.name for f in info.signature_fields if f.signed}
        wanted = request.field
        if wanted is None:
            unsigned = [f.som for f in info.xfa_signature_fields if f.som not in signed]
            if not unsigned:
                raise SignallError("every signature field in this form is already signed")
            wanted = unsigned[0]
        target = xfa_sign.resolve_field(info.xfa_signature_fields, wanted)
        if target.som in signed:
            raise SignallError(f"{target.som} is already signed")
        writer, target = xfa_sign.prepare(data, target.som, request.values, renderer, now)
        field_name = target.som
    else:
        writer = open_writer(data)
        _apply_values_static(writer, request.values)
        acroform.fill(writer, request.fields)
        if request.box is not None:
            page, box = request.box
            if not 0 <= page < info.page_count:
                raise SignallError(f"page {page + 1} does not exist (the document has {info.page_count})")
            field_name = _new_field_name([f.name for f in info.signature_fields])
            new_field = sig_fields.SigFieldSpec(sig_field_name=field_name, on_page=page, box=tuple(box))
        else:
            unsigned = [f.name for f in info.signature_fields if not f.signed]
            if request.field:
                matches = [n for n in unsigned if n == request.field or n.endswith(request.field)]
                if len(matches) != 1:
                    raise SignallError(f"no single unsigned signature field matches {request.field!r}")
                field_name = matches[0]
            elif unsigned:
                field_name = unsigned[0]
            else:
                raise SignallError("this PDF has no empty signature field; draw one (--box) to sign it")

    if info.kind is Kind.STATIC_XFA and new_field is None:
        _stamp_static_date(writer, info, field_name, now, request)

    meta = signers.PdfSignatureMetadata(
        field_name=field_name, name=name, reason=request.reason, location=request.location,
        subfilter=sig_fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
        embed_validation_info=validation_context is not None, validation_context=validation_context,
    )
    pdf_signer = signers.PdfSigner(meta, signer, stamp_style=AcrobatStampStyle(), new_field_spec=new_field)
    out = io.BytesIO()
    try:
        pdf_signer.sign_pdf(writer, output=out)
    except SigningError as exc:
        raise SignallError(f"signing failed: {exc}") from exc
    return out.getvalue()


def _stamp_static_date(writer, info, field_name: str, now: datetime.datetime, request: SignRequest) -> None:
    """Fill the date that the form's own script sets when this field is signed (if still empty)."""
    target = next((f for f in info.xfa_signature_fields if f.som == field_name), None)
    if target is None or not target.date_data_path or not target.date_format:
        return
    stamp = printd(target.date_format, now)
    packets = XfaPackets.from_root(writer.root)
    datasets = Datasets(packets.get("datasets"))
    if not (datasets.get(target.date_data_path) or "").strip():
        datasets.set(target.date_data_path, stamp)
        xfa_sign._replace_packet(writer, packets, "datasets", datasets.to_bytes())
    date_field = f"{field_name.rsplit('.', 1)[0]}.{target.date_data_path[-1]}[0]"
    if date_field not in request.fields and not acroform.value_of(writer, date_field):
        try:
            acroform.fill(writer, {date_field: stamp})
        except SignallError:
            pass  # no such AcroForm field, or it is read-only: the XFA data still has the date


def parse_box(spec: str) -> tuple[int, tuple[float, float, float, float]]:
    """Parse ``PAGE:x0,y0,x1,y1`` (page numbers start at 1)."""
    m = re.fullmatch(r"\s*(\d+)\s*:\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*", spec)
    if not m:
        raise SignallError("box must look like PAGE:x0,y0,x1,y1 (points from the bottom-left corner)")
    page = int(m.group(1)) - 1
    x0, y0, x1, y1 = (float(m.group(i)) for i in range(2, 6))
    if x1 <= x0 or y1 <= y0:
        raise SignallError("box corners must be bottom-left then top-right")
    return page, (x0, y0, x1, y1)
