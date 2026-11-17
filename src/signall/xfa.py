"""Reading and editing the XFA parts of a PDF form.

An XFA form keeps its definition (``template``) and its values (``datasets``)
as XML packets in ``/AcroForm /XFA``. Signall reads the template to find
signature fields and edits the datasets to fill values.
"""
from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field

from lxml import etree
from pyhanko.pdf_utils import generic

from signall.pdf import SignallError, get as pget

XFA_DATA_NS = "http://www.xfa.org/schema/xfa-data/1.0/"
_UNITS_PT = {"pt": 1.0, "in": 72.0, "mm": 72 / 25.4, "cm": 72 / 2.54, "mp": 0.001}
_TRANSPARENT = {"subformSet", "area"}
_CONTAINERS = {"subform", "subformSet", "area", "exclGroup"}


def measure(value: str | None, default: float = 0.0) -> float:
    """Convert an XFA measurement such as ``0.381mm`` to points."""
    if not value:
        return default
    m = re.fullmatch(r"\s*(-?[\d.]+)\s*([a-z]*)\s*", value)
    if not m:
        return default
    number, unit = float(m.group(1)), m.group(2) or "in"
    return number * _UNITS_PT.get(unit, 72.0)


def _local(tag) -> str:
    return etree.QName(tag).localname if isinstance(tag, str) else ""


@dataclass(frozen=True)
class Caption:
    text: str
    size_pt: float = 8.0
    typeface: str = "Arial"
    bold: bool = False
    reserve_pt: float = 0.0
    placement: str = "left"


@dataclass(frozen=True)
class SignatureField:
    som: str                      # full SOM path, e.g. form1[0].page1[0].Part1[0].userSig[0].userSig[0]
    names: tuple[str, ...]        # the same path without indices
    caption: Caption | None
    margins: tuple[float, float, float, float]  # left, bottom, right, top insets in points
    date_data_path: tuple[str, ...] | None = None  # datasets element the form stamps on signing
    date_format: str | None = None                 # the form's util.printd pattern for that date, e.g. "yyyymmdd"
    lock_action: str | None = None                 # "include", "exclude" or "all": fields frozen by signing
    lock_fields: tuple[str, ...] = ()              # SOM paths of the locked fields

    def widget_rect(self, field_rect: tuple[float, float, float, float]) -> tuple[float, float, float, float]:
        """Map the field's laid-out box to the widget box Acrobat uses (inside margins and caption)."""
        x0, y0, x1, y1 = field_rect
        left, bottom, right, top = self.margins
        x0, y0, x1, y1 = x0 + left, y0 + bottom, x1 - right, y1 - top
        if self.caption and self.caption.reserve_pt:
            reserve = self.caption.reserve_pt
            match self.caption.placement:
                case "top":
                    y1 -= reserve
                case "bottom":
                    y0 += reserve
                case "left":
                    x0 += reserve
                case "right":
                    x1 -= reserve
        return (x0, y0, x1, y1)


@dataclass
class XfaPackets:
    """The XFA packet array from ``/AcroForm /XFA``."""

    array: generic.ArrayObject
    names: list[str] = field(default_factory=list)

    @classmethod
    def from_root(cls, root) -> "XfaPackets | None":
        acroform = pget(root, "/AcroForm")
        xfa = pget(acroform, "/XFA")
        if xfa is None:
            return None
        if not isinstance(xfa, generic.ArrayObject):
            raise SignallError("single-stream XFA documents are not supported yet")
        return cls(array=xfa, names=[str(xfa[i]) for i in range(0, len(xfa) - 1, 2)])

    def get(self, name: str) -> bytes | None:
        for i in range(0, len(self.array) - 1, 2):
            if str(self.array[i]) == name:
                return self.array[i + 1].get_object().data
        return None

    def index(self, name: str) -> int | None:
        for i in range(0, len(self.array) - 1, 2):
            if str(self.array[i]) == name:
                return i + 1
        return None


class Template:
    def __init__(self, xml: bytes):
        self.root = etree.fromstring(xml)
        self.ns = etree.QName(self.root).namespace

    def _tag(self, name: str) -> str:
        return f"{{{self.ns}}}{name}"

    def signature_fields(self) -> list[SignatureField]:
        out: list[SignatureField] = []
        top = [c for c in self.root if _local(c.tag) == "subform"]
        counters: dict[str, int] = {}
        for sub in top:
            self._walk(sub, [], [], counters, out)
        return out

    def _walk(self, node, som, names, counters, out) -> None:
        kind = _local(node.tag)
        name = node.get("name")
        if kind == "pageSet":
            return
        if kind in _TRANSPARENT or (kind == "subform" and not name):
            child_som, child_names = som, names
            child_counters = counters  # children are addressed through the parent
        else:
            idx = counters.get(name, 0)
            counters[name] = idx + 1
            child_som = som + [f"{name}[{idx}]"]
            child_names = names + [name]
            child_counters = {}
        if kind == "field":
            ui = node.find(self._tag("ui"))
            if ui is not None and ui.find(self._tag("signature")) is not None:
                out.append(self._signature_field(node, child_som, child_names))
            return
        if kind in _CONTAINERS:
            for child in node:
                if _local(child.tag) in _CONTAINERS | {"field"}:
                    self._walk(child, child_som, child_names, child_counters, out)

    def _signature_field(self, node, som, names) -> SignatureField:
        margin = node.find(self._tag("margin"))
        margins = (0.0, 0.0, 0.0, 0.0)
        if margin is not None:
            margins = tuple(measure(margin.get(k)) for k in ("leftInset", "bottomInset", "rightInset", "topInset"))
        caption = None
        cap = node.find(self._tag("caption"))
        if cap is not None and cap.get("presence") not in ("hidden", "invisible"):
            text = " ".join("".join(cap.find(self._tag("value")).itertext()).split()) if cap.find(self._tag("value")) is not None else ""
            font = cap.find(self._tag("font"))
            caption = Caption(
                text=text,
                size_pt=measure(font.get("size"), 10.0) if font is not None else 10.0,
                typeface=(font.get("typeface") if font is not None else None) or "Arial",
                bold=font is not None and font.get("weight") == "bold",
                reserve_pt=measure(cap.get("reserve")),
                placement=cap.get("placement", "left"),
            )
        date_path, date_format = self._date_stamp(node, names)
        lock_action, lock_fields = self._lock(node)
        return SignatureField(
            som=".".join(som), names=tuple(names), caption=caption, margins=margins,
            date_data_path=date_path, date_format=date_format,
            lock_action=lock_action, lock_fields=lock_fields,
        )

    def _lock(self, node) -> tuple[str | None, tuple[str, ...]]:
        """Read the field-lock manifest a signature field refers to (Acrobat turns it into FieldMDP)."""
        signature = node.find(f"{self._tag('ui')}/{self._tag('signature')}")
        manifest = signature.find(self._tag("manifest")) if signature is not None else None
        if manifest is None:
            return None, ()
        action = manifest.get("action", "include")
        use = manifest.get("use", "")
        if use.startswith("#"):
            target = next((m for m in self.root.iter(self._tag("manifest")) if m.get("id") == use[1:]), None)
            if target is not None:
                action = manifest.get("action") or target.get("action", "include")
                manifest = target
        refs = []
        for ref in manifest.iter(self._tag("ref")):
            text = (ref.text or "").strip()
            text = re.sub(r"^(?:xfa\[0\]\.)?template\[0\]\.", "", text)
            if text:
                refs.append(text)
        return action, tuple(refs)

    def _date_stamp(self, node, names):
        """Find the date field the form's own script fills in when this field is signed."""
        for script in node.iter(self._tag("script")):
            m = re.search(r"(\w+)\.rawValue\s*=\s*util\.printd\(\s*\"([^\"]+)\"", script.text or "")
            if m:
                return tuple(names[:-1]) + (m.group(1),), m.group(2)
        return None, None


_MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
           "November", "December"]
_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
_PRINTD = re.compile(r"yyyy|yy|mmmm|mmm|mm|m|dddd|ddd|dd|d|HH|H|hh|h|MM|M|ss|s|tt|'[^']*'")


def printd(pattern: str, when: datetime.datetime) -> str:
    """Format a date like Acrobat's ``util.printd`` (always in English, whatever the locale)."""
    h12 = when.hour % 12 or 12
    tokens = {
        "yyyy": f"{when.year:04d}", "yy": f"{when.year % 100:02d}",
        "mmmm": _MONTHS[when.month - 1], "mmm": _MONTHS[when.month - 1][:3],
        "mm": f"{when.month:02d}", "m": str(when.month),
        "dddd": _DAYS[when.weekday()], "ddd": _DAYS[when.weekday()][:3],
        "dd": f"{when.day:02d}", "d": str(when.day),
        "HH": f"{when.hour:02d}", "H": str(when.hour), "hh": f"{h12:02d}", "h": str(h12),
        "MM": f"{when.minute:02d}", "M": str(when.minute), "ss": f"{when.second:02d}", "s": str(when.second),
        "tt": "am" if when.hour < 12 else "pm",
    }
    return _PRINTD.sub(lambda m: m.group(0)[1:-1] if m.group(0).startswith("'") else tokens[m.group(0)], pattern)


class Datasets:
    """The form's data, as stored in the ``datasets`` packet."""

    def __init__(self, xml: bytes):
        self.root = etree.fromstring(xml)
        data = self.root.find(f"{{{XFA_DATA_NS}}}data")
        if data is None:
            data = etree.SubElement(self.root, f"{{{XFA_DATA_NS}}}data")
        self.data = data

    @staticmethod
    def _split(path) -> list[tuple[str, int]]:
        parts = path.split(".") if isinstance(path, str) else list(path)
        out = []
        for part in parts:
            m = re.fullmatch(r"([^\[\]]+)(?:\[(\d+)\])?", part)
            if not m:
                raise SignallError(f"invalid data path: {path!r}")
            out.append((m.group(1), int(m.group(2) or 0)))
        return out

    def _find(self, path, create: bool):
        node = self.data
        for name, idx in self._split(path):
            matches = [c for c in node if _local(c.tag) == name]
            if idx < len(matches):
                node = matches[idx]
            elif create and idx == len(matches):
                node = etree.SubElement(node, name)
            else:
                return None
        return node

    def get(self, path) -> str | None:
        node = self._find(path, create=False)
        return None if node is None else (node.text or "")

    def set(self, path, value: str) -> None:
        node = self._find(path, create=True)
        if len(node):
            raise SignallError(f"{path} is a group of fields, not a single value")
        node.text = value

    def values(self) -> dict[str, str]:
        """Every value in the data, keyed by its indexed path (``form1.page1.Part1[0].Phone``)."""
        out: dict[str, str] = {}

        def walk(node, prefix: str) -> None:
            counts: dict[str, int] = {}
            for child in node:
                if not isinstance(child.tag, str):
                    continue  # comments, processing instructions
                name = _local(child.tag)
                index = counts.get(name, 0)
                counts[name] = index + 1
                path = f"{prefix}.{name}[{index}]" if prefix else f"{name}[{index}]"
                if len(child):
                    walk(child, path)
                else:
                    out[path] = child.text or ""

        walk(self.data, "")
        return out

    def changes_from(self, original: "Datasets") -> dict[str, str]:
        """The values that differ from ``original``: what a viewer's edits changed."""
        before = original.values()
        return {path: value for path, value in self.values().items() if before.get(path, "") != value}

    def to_bytes(self) -> bytes:
        return etree.tostring(self.root, encoding="UTF-8", xml_declaration=False)
