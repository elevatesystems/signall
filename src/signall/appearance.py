"""A signature appearance laid out like Adobe Acrobat's default.

Left column: the signer's name, as large as fits.
Right column: "Digitally signed by <name>" and "Date: 2026.11.17 11:04:37 -08'00'".
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from pyhanko.pdf_utils import generic, layout
from pyhanko.pdf_utils.content import ResourceType
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.stamp.base import BaseStamp
from pyhanko.stamp.text import TextStampStyle

# Helvetica advance widths (1/1000 em) for ASCII 32..126, from the standard AFM metrics.
_HELVETICA = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556,
    556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722,
    722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722,
    667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556,
    556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500,
    500, 334, 260, 334, 584,
]
_FONT = pdf_name("/SignallHelv")
_LINE = 1.15


def text_width(text: str, size: float) -> float:
    return sum(_HELVETICA[ord(c) - 32] if 32 <= ord(c) <= 126 else 556 for c in text) * size / 1000


def _break_word(word: str, size: float, width: float) -> list[str]:
    """Split a word that is too wide, preferring breaks before periods (LAST.FIRST.MI.ID)."""
    pieces = re.findall(r"\.?[^.]+|\.", word) if "." in word else list(word)
    lines, current = [], ""
    for piece in pieces:
        if current and text_width(current + piece, size) > width:
            lines.append(current)
            current = piece
        else:
            current += piece
    if current:
        lines.append(current)
    out = []
    for line in lines:  # a single piece can still be too wide; fall back to characters
        while len(line) > 1 and text_width(line, size) > width:
            cut = 1
            while cut < len(line) and text_width(line[: cut + 1], size) <= width:
                cut += 1
            out.append(line[:cut])
            line = line[cut:]
        out.append(line)
    return out


def wrap(text: str, size: float, width: float) -> list[str]:
    lines: list[str] = []
    for paragraph in text.split("\n"):
        current = ""
        for word in paragraph.split(" "):
            candidate = f"{current} {word}" if current else word
            if text_width(candidate, size) <= width:
                current = candidate
                continue
            if current:
                lines.append(current)
            if text_width(word, size) <= width:
                current = word
            else:
                *full, current = _break_word(word, size, width)
                lines.extend(full)
        lines.append(current)
    return lines


def fit(text: str, width: float, height: float, max_size: float, min_size: float = 3.0) -> tuple[float, list[str]]:
    size = max_size
    while size > min_size:
        lines = wrap(text, size, width)
        if len(lines) * size * _LINE <= height and all(text_width(l, size) <= width for l in lines):
            return size, lines
        size -= 0.25
    return min_size, wrap(text, min_size, width)


def _escape(text: str) -> bytes:
    raw = text.encode("cp1252", errors="replace")
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def acrobat_offset(ts: str) -> str:
    """Turn a trailing ``-0800`` into Acrobat's ``-08'00'``."""
    return re.sub(r"([+-])(\d{2})(\d{2})$", r"\1\2'\3'", ts)


@dataclass(frozen=True)
class AcrobatStampStyle(TextStampStyle):
    timestamp_format: str = "%Y.%m.%d %H:%M:%S %z"
    border_width: int = 0

    def create_stamp(self, writer, box: layout.BoxConstraints, text_params: dict) -> "AcrobatStamp":
        return AcrobatStamp(writer, self, box, text_params)


class AcrobatStamp(BaseStamp):
    def __init__(self, writer, style, box, text_params):
        super().__init__(writer=writer, style=style, box=box)
        self.text_params = text_params

    def _render_inner_content(self):
        self.set_resource(
            category=ResourceType.FONT,
            name=_FONT,
            value=generic.DictionaryObject({
                pdf_name("/Type"): pdf_name("/Font"),
                pdf_name("/Subtype"): pdf_name("/Type1"),
                pdf_name("/BaseFont"): pdf_name("/Helvetica"),
                pdf_name("/Encoding"): pdf_name("/WinAnsiEncoding"),
            }),
        )
        name = str(self.text_params.get("signer", "")).strip()
        when = acrobat_offset(str(self.text_params.get("ts", "")))
        w, h = self.box.width, self.box.height
        pad = min(2.0, h * 0.08)
        inner_h = h - 2 * pad
        left_w = w * 0.48
        right_x = left_w + pad * 2
        right_w = w - right_x - pad

        name_size, name_lines = fit(name, left_w - pad, inner_h, max_size=min(inner_h * 0.85, 28))
        details = f"Digitally signed by {name}\nDate: {when}"
        detail_size, detail_lines = fit(details, right_w, inner_h, max_size=min(name_size * 0.6, 10))

        ops = [b"0 g"]
        ops += self._column(name_lines, name_size, pad, pad, inner_h)
        ops += self._column(detail_lines, detail_size, right_x, pad, inner_h)
        return ops

    @staticmethod
    def _column(lines, size, x, y0, height) -> list[bytes]:
        block = len(lines) * size * _LINE
        # vertically center; the first baseline sits one ascent (~0.8 em) below the top of the block
        top = y0 + (height + block) / 2
        ops = [b"BT", b"%s %.2f Tf" % (str(_FONT).encode(), size)]
        for i, line in enumerate(lines):
            baseline = top - size * 0.85 - i * size * _LINE
            ops.append(b"1 0 0 1 %.2f %.2f Tm (%s) Tj" % (x, baseline, _escape(line)))
        ops.append(b"ET")
        return ops
