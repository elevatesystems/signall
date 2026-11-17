"""Render dynamic XFA forms to static PDF pages with pdf.js running in WebKitGTK.

Acrobat writes a pre-rendered copy of every page when it saves a dynamic XFA
form; non-Adobe viewers show that copy. Signall does the same: pdf.js lays the
form out, WebKitGTK prints it to PDF, and the result is transplanted into the
signed revision.
"""
from __future__ import annotations

import json
import mimetypes
import secrets
import tempfile
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

__all__ = ["FieldPlacement", "RenderError", "RenderResult", "SignatureFieldSpec", "render_xfa"]

SCHEME = "signall-render"
TIMEOUT_SECONDS = 60

# Documents being rendered, keyed by a per-render token that prefixes every URL.
_jobs: dict[str, dict[str, bytes]] = {}


class RenderError(RuntimeError):
    pass


@dataclass(frozen=True)
class SignatureFieldSpec:
    """A signature field to locate in the rendered layout."""

    path: tuple[str, ...]  # template names without indices, e.g. ("form1", "page1", "Part1", "userSig", "userSig")
    caption: str = ""
    css_font: str = ""


@dataclass(frozen=True)
class FieldPlacement:
    spec: SignatureFieldSpec
    page: int
    rect: tuple[float, float, float, float]  # PDF points, origin bottom-left


@dataclass
class RenderResult:
    pdf: bytes
    page_count: int
    fields: list[FieldPlacement] = field(default_factory=list)


def _asset_root() -> Path:
    root = Path(str(resources.files(__package__)))
    if not (root / "pdfjs" / "build" / "pdf.min.mjs").is_file():
        raise RenderError("pdf.js is missing; run scripts/fetch-pdfjs.py")
    return root


def _new_context(WebKit, Gio, GLib):
    """Create a private web context that serves the render assets.

    Do not use WebContext.get_default(): WebKit destroys the default context in
    a C exit handler, after the Python interpreter has shut down. Freeing the
    Python scheme handler at that point crashes the process (SIGSEGV on exit).
    A private context is released when the render finishes, while Python is
    still running.
    """
    root = _asset_root().resolve()

    def serve(request) -> None:
        token, _, name = request.get_path().lstrip("/").partition("/")
        job = _jobs.get(token)
        data = None
        if job is not None and name in job:
            data = job[name]
        elif job is not None:
            target = (root / name).resolve()
            if root in target.parents and target.is_file():
                data = target.read_bytes()
        if data is None:
            request.finish_error(GLib.Error.new_literal(Gio.io_error_quark(), "not found", Gio.IOErrorEnum.NOT_FOUND))
            return
        mime = "text/javascript" if name.endswith((".mjs", ".js")) else (
            mimetypes.guess_type(name)[0] or "application/octet-stream")
        request.finish(Gio.MemoryInputStream.new_from_bytes(GLib.Bytes.new(data)), len(data), mime)

    context = WebKit.WebContext()
    context.register_uri_scheme(SCHEME, serve)
    security = context.get_security_manager()
    security.register_uri_scheme_as_secure(SCHEME)
    security.register_uri_scheme_as_cors_enabled(SCHEME)
    return context


def _run(loop, GLib, what: str, state: dict) -> None:
    def expire() -> bool:
        state.setdefault("error", f"timed out {what}")
        loop.quit()
        return False

    timer = GLib.timeout_add_seconds(TIMEOUT_SECONDS, expire)
    loop.run()
    if "error" not in state or not state["error"].startswith("timed out"):
        GLib.source_remove(timer)


def render_xfa(pdf: bytes, fields: list[SignatureFieldSpec]) -> RenderResult:
    """Lay out a dynamic XFA document and print it to PDF.

    Needs a display (Wayland or X11). Runs its own GLib main loop, so call it
    from the CLI or a worker context, not from inside a running GTK main loop.
    """
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("WebKit", "6.0")
    from gi.repository import Gio, GLib, Gtk, WebKit

    if not Gtk.init_check():
        raise RenderError("no display available for rendering (need Wayland or X11)")
    context = _new_context(WebKit, Gio, GLib)

    token = secrets.token_hex(8)
    _jobs[token] = {
        "doc.pdf": pdf,
        "fields.json": json.dumps(
            [{"path": list(f.path), "caption": f.caption, "font": f.css_font} for f in fields]).encode(),
    }
    loop = GLib.MainLoop()
    state: dict = {}
    view = WebKit.WebView(web_context=context)
    view.get_settings().set_print_backgrounds(True)
    ucm = view.get_user_content_manager()
    ucm.register_script_message_handler("signall", None)

    def on_message(_ucm, value) -> None:
        state["message"] = json.loads(value.to_string())
        loop.quit()

    ucm.connect("script-message-received::signall", on_message)
    window = Gtk.Window(default_width=900, default_height=1200)
    window.set_child(view)
    try:
        view.load_uri(f"{SCHEME}:///{token}/page.html")
        _run(loop, GLib, "waiting for the form layout", state)
        msg = state.get("message")
        if msg is None or not msg.get("ok"):
            raise RenderError(f"XFA layout failed: {(msg or {}).get('error') or state.get('error')}")

        with tempfile.TemporaryDirectory(prefix="signall-render-") as tmp:
            out = Path(tmp) / "render.pdf"
            settings = Gtk.PrintSettings()
            settings.set_printer("Print to File")
            settings.set(Gtk.PRINT_SETTINGS_OUTPUT_FILE_FORMAT, "pdf")
            settings.set(Gtk.PRINT_SETTINGS_OUTPUT_URI, out.as_uri())
            page_setup = Gtk.PageSetup()
            page_setup.set_paper_size(Gtk.PaperSize.new(Gtk.PAPER_NAME_LETTER))
            for setter in ("set_top_margin", "set_bottom_margin", "set_left_margin", "set_right_margin"):
                getattr(page_setup, setter)(0, Gtk.Unit.POINTS)
            op = WebKit.PrintOperation.new(view)
            op.set_print_settings(settings)
            op.set_page_setup(page_setup)
            op.connect("failed", lambda _op, err: state.__setitem__("error", err.message if err else "print failed"))
            op.connect("finished", lambda _op: loop.quit())
            op.print_()
            _run(loop, GLib, "printing", state)
            if state.get("error"):
                raise RenderError(f"printing failed: {state['error']}")
            if not out.is_file() or out.stat().st_size == 0:
                raise RenderError("printing produced no output")
            rendered = out.read_bytes()
    finally:
        _jobs.pop(token, None)
        window.destroy()

    placements = [
        FieldPlacement(spec=fields[f["index"]], page=f["page"], rect=tuple(f["rect"]))
        for f in msg["fields"]
    ]
    return RenderResult(pdf=rendered, page_count=msg["pages"], fields=placements)
