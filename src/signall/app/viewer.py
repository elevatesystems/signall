"""The document view: pdf.js's viewer running in WebKitGTK (see render/viewer.js)."""
from __future__ import annotations

import itertools
import json
from typing import Callable

import gi

gi.require_version("Adw", "1")
gi.require_version("Gtk", "4.0")
gi.require_version("WebKit", "6.0")
from gi.repository import Adw, Gtk, WebKit  # noqa: E402

from signall.render import SCHEME, add_job, remove_job  # noqa: E402


class DocumentView(Adw.Bin):
    """Shows one document at a time. Reports clicks on signature fields and drawn boxes.

    Callbacks (set by the owner): ``on_ready(pages)``, ``on_error(message)``, ``on_field(name)``,
    ``on_box(page, rect)``.
    """

    def __init__(self, web_context) -> None:
        super().__init__()
        self.on_ready: Callable[[int], None] = lambda pages: None
        self.on_error: Callable[[str], None] = lambda message: None
        self.on_field: Callable[[str], None] = lambda name: None
        self.on_box: Callable[[int, tuple], None] = lambda page, rect: None
        self._token: str | None = None
        self._requests = itertools.count(1)
        self._pending: dict[int, Callable] = {}

        self.web = WebKit.WebView(web_context=web_context)
        settings = self.web.get_settings()
        settings.set_enable_developer_extras(False)
        settings.set_javascript_can_open_windows_automatically(False)
        settings.set_enable_back_forward_navigation_gestures(False)
        self.web.set_background_color(_rgba("#00000000"))
        ucm = self.web.get_user_content_manager()
        ucm.register_script_message_handler("signall", None)
        ucm.connect("script-message-received::signall", self._on_message)
        self.web.connect("decide-policy", self._on_policy)
        self.web.connect("context-menu", lambda *_: True)  # no "Reload" or "Back" menu
        self.set_child(self.web)

    # --- Host → page ------------------------------------------------------------

    def load(self, data: bytes, config: dict) -> None:
        old = self._token
        self._token = add_job({"doc.pdf": data, "config.json": json.dumps(config).encode()})
        self._pending.clear()
        self.web.load_uri(f"{SCHEME}:///{self._token}/viewer.html")
        if old:
            remove_job(old)

    def unload(self) -> None:
        if self._token:
            remove_job(self._token)
            self._token = None
        self.web.load_uri("about:blank")

    def set_draw_mode(self, on: bool) -> None:
        self._call(f"signall.setDrawMode({json.dumps(on)})")

    def clear_draft(self) -> None:
        self._call("signall.clearDraft()")

    def zoom(self, how: str) -> None:
        self._call(f"signall.zoom({json.dumps(how)})")

    def set_dark(self, on: bool) -> None:
        self._call(f"signall.setDark({json.dumps(on)})")

    def collect(self, callback: Callable[[str | None, dict, str | None], None]) -> None:
        """Ask for the user's form input; ``callback(xfa_copy_base64, acroform_changes, error)``."""
        request = next(self._requests)
        self._pending[request] = callback
        self._call(f"signall.collect({request})")

    def _call(self, script: str) -> None:
        self.web.evaluate_javascript(f"window.signall && {script}", -1, None, None, None, None)

    # --- Page → host ------------------------------------------------------------

    def _on_message(self, _ucm, value) -> None:
        msg = json.loads(value.to_string())
        kind = msg.get("type")
        if kind == "ready":
            self.on_ready(msg.get("pages", 0))
        elif kind == "error":
            self.on_error(msg.get("error", "unknown error"))
        elif kind == "field":
            self.on_field(msg["name"])
        elif kind == "box":
            self.on_box(int(msg["page"]), tuple(float(v) for v in msg["rect"]))
        elif kind == "collected":
            callback = self._pending.pop(msg.get("id"), None)
            if callback:
                callback(msg.get("data"), msg.get("fields") or {}, msg.get("error"))

    def _on_policy(self, _web, decision, decision_type) -> bool:
        if decision_type == WebKit.PolicyDecisionType.RESPONSE:
            return False  # loading the page's own resources
        uri = decision.get_navigation_action().get_request().get_uri()
        if uri.startswith(f"{SCHEME}:") or uri == "about:blank":
            decision.use()
            return True
        decision.ignore()
        if uri.startswith(("https:", "http:", "mailto:")):
            Gtk.UriLauncher.new(uri).launch(self.get_root(), None, None)
        return True


def _rgba(spec: str):
    from gi.repository import Gdk

    color = Gdk.RGBA()
    color.parse(spec)
    return color
