"""Fill AcroForm fields (text, check boxes, radio buttons, choices) and draw their appearances."""
from __future__ import annotations

import re

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name, pdf_string

from signall.appearance import _escape, fit, text_width, wrap
from signall.pdf import SignallError, get as pget

_READ_ONLY = 1
_MULTILINE = 1 << 12
_PASSWORD = 1 << 13
_PADDING = 2.0
_DEFAULT_SIZE = 10.0


def _fields(acroform) -> dict[str, generic.IndirectObject]:
    """Every terminal field, keyed by its fully qualified name."""
    out: dict[str, generic.IndirectObject] = {}

    def walk(ref, prefix: str, inherited_ft) -> None:
        node = ref.get_object()
        t = pget(node, "/T")
        name = f"{prefix}.{t}" if prefix and t is not None else (str(t) if t is not None else prefix)
        ft = pget(node, "/FT", inherited_ft)
        kids = pget(node, "/Kids", None)
        named_kids = [k for k in (kids or []) if "/T" in k.get_object()]
        if named_kids:
            for kid in named_kids:
                walk(kid, name, ft)
        elif name:
            out[name] = ref

    for ref in pget(acroform, "/Fields", []) or []:
        walk(ref, "", None)
    return out


def _inherited(field, key: str, acroform=None, default=None):
    node = field
    while node is not None:
        if key in node:
            return pget(node, key)
        parent = pget(node, "/Parent")
        node = parent.get_object() if parent is not None else None
    if acroform is not None and key in acroform:
        return pget(acroform, key)
    return default


def _widgets(field_ref) -> list[generic.IndirectObject]:
    field = field_ref.get_object()
    kids = pget(field, "/Kids", None)
    if kids:
        return [k for k in kids if "/T" not in k.get_object()]
    return [field_ref]


def _parse_da(da: str) -> tuple[str, float, str]:
    """(font resource name, size, color operators) from a /DA string such as ``/Helv 0 Tf 0 g``."""
    font = re.search(r"/([^\s/]+)\s+([\d.]+)\s+Tf", da)
    color = re.search(r"([\d.\s]+(?:g|rg|k))\s*$", da.strip())
    name = font.group(1) if font else "Helv"
    size = float(font.group(2)) if font else 0.0
    return name, size, color.group(1).strip() if color else "0 g"


def _text_appearance(widget, value: str, flags: int, acroform, field) -> generic.StreamObject:
    r = [float(v) for v in pget(widget, "/Rect")]
    width, height = abs(r[2] - r[0]), abs(r[3] - r[1])
    da = str(_inherited(widget, "/DA", acroform, "/Helv 0 Tf 0 g"))
    font, size, color = _parse_da(da)
    quadding = int(_inherited(widget, "/Q", acroform, 0) or 0)
    inner_w, inner_h = max(width - 2 * _PADDING, 1), max(height - 2 * _PADDING, 1)
    if flags & _PASSWORD:
        value = "*" * len(value)

    if flags & _MULTILINE:
        if size == 0:
            size, lines = fit(value, inner_w, inner_h, max_size=12)
        else:
            lines = [line for para in value.splitlines() or [""] for line in (wrap(para, size, inner_w) or [""])]
        leading = size * 1.15
        y = height - _PADDING - size
    else:
        if size == 0:
            size = min(12.0, inner_h * 0.75)
            while size > 4 and text_width(value, size) > inner_w:
                size -= 0.5
        lines = [value]
        leading = size
        y = (height - size * 0.72) / 2  # center the cap height

    ops = [b"/Tx BMC q", f"{_PADDING} {_PADDING} {inner_w} {inner_h} re W n".encode(), b"BT",
           f"/{font} {size:g} Tf {color}".encode()]
    x_prev = y_prev = 0.0
    for line in lines:
        w = text_width(line, size)
        x = _PADDING + {1: (inner_w - w) / 2, 2: inner_w - w}.get(quadding, 0.0)
        ops.append(f"{x - x_prev:.2f} {y - y_prev:.2f} Td".encode())
        ops.append(b"(" + _escape(line) + b") Tj")
        x_prev, y_prev = x, y
        y -= leading
    ops += [b"ET Q EMC"]

    resources = generic.DictionaryObject()
    dr = pget(acroform, "/DR")
    if dr is not None and "/Font" in dr:
        resources[pdf_name("/Font")] = pget(dr, "/Font")
    stream = generic.StreamObject({
        pdf_name("/Type"): pdf_name("/XObject"),
        pdf_name("/Subtype"): pdf_name("/Form"),
        pdf_name("/BBox"): generic.ArrayObject([generic.FloatObject(0), generic.FloatObject(0),
                                                generic.FloatObject(width), generic.FloatObject(height)]),
        pdf_name("/Resources"): resources,
    }, stream_data=b"\n".join(ops))
    return stream


def _on_state(widget) -> str | None:
    ap = pget(widget, "/AP")
    normal = pget(ap, "/N") if ap is not None else None
    if not isinstance(normal, generic.DictionaryObject) or isinstance(normal, generic.StreamObject):
        return None  # a single appearance stream, not a set of states
    for key in normal:
        if key != "/Off":
            return key[1:]
    return None


def value_of(writer, name: str) -> str | None:
    """The current value of a field, or None if it has none (or doesn't exist)."""
    acroform = pget(writer.root, "/AcroForm")
    ref = _fields(acroform).get(name) if acroform is not None else None
    if ref is None:
        return None
    value = _inherited(ref.get_object(), "/V")
    if value is None or isinstance(value, generic.NullObject):
        return None
    return str(value) or None


def fill(writer, values: dict[str, object]) -> list[str]:
    """Set AcroForm field values in ``writer`` (an incremental writer) and draw their appearances.

    ``values`` maps fully qualified field names to a string (text and choice fields, or the export
    value of a radio button) or a bool (check boxes). Returns the names that were filled.
    """
    if not values:
        return []
    acroform = pget(writer.root, "/AcroForm")
    if acroform is None:
        raise SignallError("this PDF has no form fields to fill")
    fields = _fields(acroform)
    filled = []
    for name, value in values.items():
        ref = fields.get(name)
        if ref is None:
            raise SignallError(f"no form field named {name!r}")
        field = ref.get_object()
        ft = str(_inherited(field, "/FT", None, ""))
        flags = int(_inherited(field, "/Ff", None, 0) or 0)
        if ft == "/Sig":
            raise SignallError(f"{name} is a signature field")
        if flags & _READ_ONLY:
            raise SignallError(f"{name} is read-only")

        if ft in ("/Tx", "/Ch"):
            text = "" if value is None else str(value)
            field[pdf_name("/V")] = pdf_string(text)
            writer.update_container(field)
            for w_ref in _widgets(ref):
                widget = w_ref.get_object()
                ap_ref = writer.add_object(_text_appearance(widget, text, flags, acroform, field))
                widget[pdf_name("/AP")] = generic.DictionaryObject({pdf_name("/N"): ap_ref})
                writer.update_container(widget)
        elif ft == "/Btn":
            widgets = _widgets(ref)
            if isinstance(value, bool):  # a check box
                state = (_on_state(widgets[0].get_object()) or "Yes") if value else "Off"
            else:
                state = str(value) or "Off"
            field[pdf_name("/V")] = pdf_name(f"/{state}")
            writer.update_container(field)
            for w_ref in widgets:
                widget = w_ref.get_object()
                own = _on_state(widget)
                widget[pdf_name("/AS")] = pdf_name(f"/{state}" if own == state else "/Off")
                writer.update_container(widget)
        else:
            raise SignallError(f"{name} is not a field Signall can fill ({ft or 'unknown type'})")
        filled.append(name)
    return filled


__all__ = ["fill", "value_of"]
