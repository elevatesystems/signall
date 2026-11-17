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

__all__ = [
    "FieldPlacement", "RenderError", "RenderResult", "SignatureFieldSpec", "add_job", "new_web_context",
    "remove_job", "render_xfa", "render_xfa_async",
]

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


def add_job(files: dict[str, bytes]) -> str:
    """Make ``files`` available to web views as ``signall-render:///<token>/<name>``; returns the token."""
    token = secrets.token_hex(8)
    _jobs[token] = files
    return token


def remove_job(token: str) -> None:
    _jobs.pop(token, None)


def new_web_context():
    """Create a private web context that serves jobs and the bundled web assets.

    Do not use WebContext.get_default(): WebKit destroys the default context in
    a C exit handler, after the Python interpreter has shut down. Freeing the
    Python scheme handler at that point crashes the process (SIGSEGV on exit).
    A private context is released when the render finishes, while Python is
    still running.
    """
    import gi

    gi.require_version("WebKit", "6.0")
    from gi.repository import Gio, GLib, WebKit

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


def render_xfa_async(pdf: bytes, fields: list[SignatureFieldSpec], on_done) -> None:
    """Lay out a dynamic XFA document and print it to PDF, without blocking.

    Call on the GTK main thread. ``on_done(result, error)`` is called there with a
    :class:`RenderResult` or a :class:`RenderError`.
    """
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("WebKit", "6.0")
    from gi.repository import GLib, Gtk, WebKit

    if not Gtk.init_check():
        on_done(None, RenderError("no display available for rendering (need Wayland or X11)"))
        return
    context = new_web_context()
    token = add_job({
        "doc.pdf": pdf,
        "fields.json": json.dumps(
            [{"path": list(f.path), "caption": f.caption, "font": f.css_font} for f in fields]).encode(),
    })
    tmp = tempfile.TemporaryDirectory(prefix="signall-render-")
    out = Path(tmp.name) / "render.pdf"
    view = WebKit.WebView(web_context=context)
    view.get_settings().set_print_backgrounds(True)
    window = Gtk.Window(default_width=900, default_height=1200)
    window.set_child(view)
    state: dict = {"layout": None, "finished": False}

    def finish(result: RenderResult | None, error: str | None) -> None:
        if state["finished"]:
            return
        state["finished"] = True
        GLib.source_remove(state["timer"])
        remove_job(token)
        window.destroy()
        tmp.cleanup()
        on_done(result, RenderError(error) if error else None)

    def expire() -> bool:
        state["timer"] = 0
        finish(None, "timed out " + ("printing" if state["layout"] else "waiting for the form layout"))
        return False

    def printed(_op) -> None:
        if state["finished"]:
            return
        if not out.is_file() or out.stat().st_size == 0:
            finish(None, "printing produced no output")
            return
        msg = state["layout"]
        placements = [
            FieldPlacement(spec=fields[f["index"]], page=f["page"], rect=tuple(f["rect"]))
            for f in msg["fields"]
        ]
        finish(RenderResult(pdf=out.read_bytes(), page_count=msg["pages"], fields=placements), None)

    def on_message(_ucm, value) -> None:
        msg = json.loads(value.to_string())
        if not msg.get("ok"):
            finish(None, f"XFA layout failed: {msg.get('error')}")
            return
        state["layout"] = msg
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
        op.connect("failed", lambda _op, err: finish(None, f"printing failed: {err.message if err else 'unknown error'}"))
        op.connect("finished", printed)
        state["op"] = op
        op.print_()

    ucm = view.get_user_content_manager()
    ucm.register_script_message_handler("signall", None)
    ucm.connect("script-message-received::signall", on_message)
    state["timer"] = GLib.timeout_add_seconds(TIMEOUT_SECONDS, expire)
    view.load_uri(f"{SCHEME}:///{token}/page.html")


def render_xfa(pdf: bytes, fields: list[SignatureFieldSpec]) -> RenderResult:
    """Lay out a dynamic XFA document and print it to PDF (blocking).

    Needs a display (Wayland or X11). Runs its own GLib main loop, so call it
    from the CLI or a worker context, not from inside a running GTK main loop;
    there, use :func:`render_xfa_async`.
    """
    import gi

    gi.require_version("Gtk", "4.0")
    from gi.repository import GLib

    loop = GLib.MainLoop()
    box: dict = {}

    def done(result, error) -> None:
        box.update(result=result, error=error)
        loop.quit()

    render_xfa_async(pdf, fields, done)
    if not box:
        loop.run()
    if box["error"] is not None:
        raise box["error"]
    return box["result"]
