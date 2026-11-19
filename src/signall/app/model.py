"""The app's document logic, kept free of GTK so it can be tested without a display."""
from __future__ import annotations

import base64
import datetime
import re
from dataclasses import dataclass, field
from pathlib import Path

from signall.document import DocumentInfo, Kind, inspect
from signall.pdf import SignallError, open_reader
from signall.verify import SignatureReport
from signall.xfa import Datasets, XfaPackets


def display_name(common_name: str | None) -> str:
    """``DOE.JANE.QUINCY.1234567890`` → ``Jane Quincy Doe``; other names are returned unchanged."""
    if not common_name:
        return "Unknown signer"
    parts = common_name.split(".")
    if len(parts) >= 3 and parts[-1].isdigit():
        last, first, *middle = parts[:-1]
        names = [first, *middle, last]
        return " ".join(n.capitalize() if len(n) > 1 else f"{n}." for n in names if n)
    return common_name


def pdf_date(value: str | None) -> str | None:
    """Format a PDF date (``D:20261117145903-08'00'``) for display."""
    if not value:
        return None
    m = re.match(r"D?:?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?", value)
    if not m:
        return value
    year, month, day, hour, minute = (int(g) if g else d for g, d in zip(m.groups(), (0, 1, 1, 0, 0)))
    try:
        return datetime.datetime(year, month, day, hour, minute).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value


def output_name(path: Path) -> str:
    stem = path.stem
    return f"{stem}.pdf" if stem.endswith(" - signed") else f"{stem} - signed.pdf"


@dataclass
class FieldRow:
    """One signature field, as the sidebar and the document view show it."""
    name: str                       # what signing targets: the SOM path or the AcroForm name
    label: str                      # a short human name
    signed: bool
    signer: str | None = None
    date: str | None = None
    path: list[str] | None = None   # XFA template names, for locating the field in the layout
    page: int | None = None
    rect: tuple[float, float, float, float] | None = None
    status: str | None = None       # "valid", "untrusted", "modified", "invalid", "error", or None (not checked yet)
    report: SignatureReport | None = None
    error: str | None = None        # why the signature couldn't be checked (status "error")


# Words that stay in capitals when a form's all-caps caption is turned into a label.
ACRONYMS = {"CAC", "DD", "DOD", "IA", "IAM", "IAO", "IASO", "ID", "ISSM", "ISSO", "IT", "OPR", "PKI", "POC", "SAAR"}


def sentence_case(text: str) -> str:
    """``ISSO OR APPOINTEE SIGNATURE`` → ``ISSO or appointee signature``."""
    def word(m: re.Match) -> str:
        w = m.group(0)
        return w if w.upper() in ACRONYMS and w.isupper() else w.lower()

    out = re.sub(r"[A-Za-z]+", word, text.strip())
    return out[:1].upper() + out[1:]


def field_label(name: str) -> str:
    """A readable label from a field name: ``ReceivedBy`` → ``Received by``, ``Signature1`` → ``Signature 1``."""
    last = re.sub(r"\[\d+\]$", "", name.rsplit(".", 1)[-1])
    words = re.sub(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Za-z])(?=\d)|[_\-]+", " ", last).split()
    if not words:
        return name
    if all(w.isupper() for w in words if w.isalpha()):
        return sentence_case(" ".join(words))
    out = " ".join(w if w.upper() in ACRONYMS and w.isupper() else w.lower() for w in words)
    return out[:1].upper() + out[1:]


def _xfa_label(f) -> str:
    caption = (f.caption.text if f.caption else "").strip()
    caption = re.sub(r"\(.*?\)|\(.*$", "", caption, flags=re.S)  # drop explanations in parentheses
    caption = re.sub(r"^\s*(\d+[a-z]?|[A-Za-z])\.\s*", "", caption)  # "17d. SIGNATURE", "h. SIGNATURE"
    caption = " ".join(caption.split())
    if caption and caption.upper() != "SIGNATURE":
        return sentence_case(caption)
    owner = f.names[-2] if len(f.names) >= 2 else f.names[-1]
    return sentence_case(re.sub(r"(?<=[a-z])(?=[A-Z])", " ", owner))  # "userSig" → "User sig"


@dataclass
class Document:
    path: Path
    data: bytes
    info: DocumentInfo
    rows: list[FieldRow] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path, data: bytes | None = None) -> Document:
        data = Path(path).read_bytes() if data is None else data
        if not data.lstrip()[:5].startswith(b"%PDF"):
            raise SignallError(f"{Path(path).name} is not a PDF")
        doc = cls(path=Path(path), data=data, info=inspect(data))
        doc.rows = doc._rows()
        return doc

    @property
    def dynamic_xfa(self) -> bool:
        return self.info.kind is Kind.DYNAMIC_XFA

    @property
    def has_xfa(self) -> bool:
        return self.info.kind in (Kind.DYNAMIC_XFA, Kind.STATIC_XFA)

    @property
    def can_draw_box(self) -> bool:
        return not self.dynamic_xfa

    def _rows(self) -> list[FieldRow]:
        acro = {f.name: f for f in self.info.signature_fields}
        rows = []
        if self.dynamic_xfa:
            for f in self.info.xfa_signature_fields:
                done = acro.get(f.som)
                rows.append(FieldRow(
                    name=f.som, label=_xfa_label(f), signed=bool(done and done.signed),
                    signer=display_name(done.signer) if done and done.signed else None,
                    date=pdf_date(done.signing_time) if done else None, path=list(f.names),
                ))
            return rows
        xfa_by_som = {f.som: f for f in self.info.xfa_signature_fields}
        for f in self.info.signature_fields:
            if f.name in xfa_by_som:
                label = _xfa_label(xfa_by_som[f.name])
            else:
                label = field_label(f.name)
            rows.append(FieldRow(
                name=f.name, label=label, signed=f.signed,
                signer=display_name(f.signer) if f.signed else None, date=pdf_date(f.signing_time),
                page=f.page, rect=f.rect,
            ))
        return rows

    def apply_reports(self, reports: list[SignatureReport], error: str | None = None) -> None:
        """Set each signed row's status from the verification reports.

        ``error`` says why verification failed altogether; signed rows without a report get it.
        """
        by_field = {r.field: r for r in reports}
        for row in self.rows:
            r = by_field.get(row.name)
            row.report = r
            if r is None:
                if row.signed:
                    row.status = "error"
                    row.error = error or "Signall found no signature data for this field."
                continue
            if not r.intact:
                row.status = "invalid"
            elif not r.trusted:
                row.status = "untrusted"
            elif r.changes_after == "other" and not self.dynamic_xfa:
                # A later signer of a dynamic XFA form re-renders its pages, which generic change
                # analysis calls "other"; Acrobat accepts it, so don't flag it here.
                row.status = "modified"
            else:
                row.status = "valid"

    def view(self, dark: bool = False) -> tuple[bytes, dict]:
        """The bytes and configuration for the document view."""
        config = {
            "xfa": self.dynamic_xfa, "forms": True, "xfaData": self.dynamic_xfa, "dark": dark,
            "fields": [
                {"name": r.name, "path": r.path, "page": r.page, "rect": r.rect, "signed": r.signed,
                 "signer": r.signer, "date": r.date}
                for r in self.rows
            ],
        }
        if self.info.kind is Kind.STATIC_XFA:
            return _without_xfa(self.data), config
        if not self.dynamic_xfa:
            return self.data, config
        # Once signed, a dynamic XFA form has AcroForm widgets and pdf.js would show the static
        # pre-rendered pages. Hide the widgets so it lays out the live (fillable) form instead.
        from signall import xfa_sign

        datasets = XfaPackets.from_root(open_reader(self.data).root).get("datasets")
        if datasets is None:
            return self.data, config
        return xfa_sign._layout_input(self.data, datasets), config

    def field_changes(self, changes: dict) -> dict[str, object]:
        """The AcroForm values the user changed, as reported by the viewer (dynamic XFA has none)."""
        if self.dynamic_xfa or not isinstance(changes, dict):
            return {}
        out: dict[str, object] = {}
        for name, value in changes.items():
            if isinstance(name, str) and isinstance(value, (str, bool)):
                out[name] = value
        return out

    def xfa_values_for(self, fields: dict[str, object]) -> dict[str, str]:
        """For a static XFA form: the XFA data matching AcroForm text changes.

        Forms made with Adobe's designer bind each field to the data node with the same path as the
        field's full name, so only paths that exist in the data are used.
        """
        if self.info.kind is not Kind.STATIC_XFA or not fields:
            return {}
        packets = XfaPackets.from_root(open_reader(self.data).root)
        if packets is None or packets.get("datasets") is None:
            return {}
        data = Datasets(packets.get("datasets"))
        out = {}
        for name, value in fields.items():
            if isinstance(value, str):
                node = data._find(name, create=False)
                if node is not None and not len(node):
                    out[name] = value
        return out

    def form_changes(self, viewer_copy_b64: str | None) -> dict[str, str]:
        """The XFA values the user typed, from the viewer's saved copy of a dynamic XFA form."""
        if not viewer_copy_b64 or not self.dynamic_xfa:
            return {}
        edited = XfaPackets.from_root(open_reader(base64.b64decode(viewer_copy_b64)).root)
        original = XfaPackets.from_root(open_reader(self.data).root)
        if edited is None or original is None or edited.get("datasets") is None:
            return {}
        before = original.get("datasets") or b'<xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/"/>'
        return Datasets(edited.get("datasets")).changes_from(Datasets(before))


def _without_xfa(data: bytes) -> bytes:
    """A display copy of a static XFA form that viewers show from its AcroForm alone.

    pdf.js fills an AcroForm field that has no value from the XFA data, and finds the wrong data
    node when sections repeat field names (DD 2842: a value typed into 1a also shows up in 2a).
    """
    import io

    from signall.pdf import open_writer

    writer = open_writer(data)
    acroform = writer.root["/AcroForm"]
    if "/XFA" not in acroform:
        return data
    del acroform["/XFA"]
    writer.update_container(acroform)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


@dataclass
class CardStatus:
    state: str                        # "ready", "absent", or "error"
    message: str = ""
    signer: str | None = None         # display name of the signing certificate's holder
    issuer: str | None = None
    token_key: tuple[str, str] | None = None  # (label, serial), to notice a different card


def card_status(module: str | None = None, previous: CardStatus | None = None) -> CardStatus:
    """Look for a card and its signing certificate. Never asks for the PIN.

    Reading certificates is slow on a real card, so they are only read again when a
    different card shows up.
    """
    from signall.token import choose_signing_certificate, find_module, list_certificates, list_tokens

    try:
        module_path = find_module(module)
        tokens = list_tokens(module_path)
    except SignallError as exc:
        return CardStatus("error", str(exc))
    except Exception as exc:  # the PKCS#11 module itself failed
        return CardStatus("error", f"smart card error: {exc or type(exc).__name__}")
    if not tokens:
        return CardStatus("absent", "No card found")
    if len(tokens) > 1:
        return CardStatus("error", "More than one card is inserted; remove all but one")
    token = tokens[0]
    key = (token.label, token.serial)
    if previous is not None and previous.state == "ready" and previous.token_key == key:
        return previous
    try:
        chosen = choose_signing_certificate(list_certificates(module_path, token))
    except SignallError as exc:
        return CardStatus("error", str(exc), token_key=key)
    except Exception as exc:
        return CardStatus("error", f"smart card error: {exc or type(exc).__name__}", token_key=key)
    return CardStatus("ready", "", signer=display_name(chosen.subject), issuer=chosen.issuer, token_key=key)


@dataclass
class SignOutcome:
    data: bytes
    note: str | None = None           # why revocation data or the chain is missing, if it is


def run_signing(doc: Document, request, *, ask_pin, renderer=None, module: str | None = None,
                online: bool = True) -> SignOutcome:
    """Sign ``doc`` with the card. Blocking: run it off the GTK main thread.

    ``ask_pin(token, certificate)`` returns the PIN, or raises SignallError to cancel.
    ``renderer`` lays out dynamic XFA forms (see :func:`signall.render.render_xfa`).
    """
    from signall.chain import prepare_embedding
    from signall.signing import sign
    from signall.token import find_module, open_signer

    embedding = None

    def chain_for(cert):
        nonlocal embedding
        embedding = prepare_embedding(cert, online=online)
        return embedding.chain

    with open_signer(find_module(module), ask_pin, chain_for=chain_for) as signer:
        signed = sign(doc.data, signer, request, renderer=renderer,
                      validation_context=embedding.context if embedding else None)
    return SignOutcome(signed, embedding.note if embedding else None)
