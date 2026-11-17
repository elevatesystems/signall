"""Signall's GNOME app."""
from __future__ import annotations

import gc
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

APP_ID = "io.github.elevatesystems.Signall"
CARD_POLL_SECONDS = 3


def main(argv: list[str] | None = None) -> int:
    import gi

    gi.require_version("Adw", "1")
    gi.require_version("Gtk", "4.0")
    from gi.repository import Adw, Gdk, Gio, GLib, Gtk

    from signall import __version__
    from signall.app.model import CardStatus, card_status
    from signall.render import new_web_context

    class SignallApp(Adw.Application):
        def __init__(self) -> None:
            super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.HANDLES_OPEN)
            GLib.set_application_name("Signall")
            self.card = CardStatus("absent")
            self.card_executor: ThreadPoolExecutor | None = None
            self.web_context = None

        def do_startup(self) -> None:
            Adw.Application.do_startup(self)
            Gtk.Window.set_default_icon_name("signall")
            source_icons = Path(__file__).resolve().parents[3] / "data" / "icons"
            if source_icons.is_dir():  # running from a checkout
                Gtk.IconTheme.get_for_display(Gdk.Display.get_default()).add_search_path(str(source_icons))
            self.web_context = new_web_context()
            # Every card operation runs on this one thread, so polling never overlaps a signature.
            self.card_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="signall-card")

            for name, callback in (("about", self._about), ("quit", lambda: self.quit())):
                action = Gio.SimpleAction.new(name, None)
                action.connect("activate", lambda *_a, cb=callback: cb())
                self.add_action(action)
            for action, keys in {
                "app.quit": ["<Control>q"], "win.open": ["<Control>o"], "win.save": ["<Control>s"],
                "win.zoom-in": ["<Control>plus", "<Control>equal"], "win.zoom-out": ["<Control>minus"],
                "win.zoom-fit": ["<Control>0"], "win.toggle-sidebar": ["F9"], "window.close": ["<Control>w"],
            }.items():
                self.set_accels_for_action(action, keys)
            self._poll_card()

        def do_activate(self) -> None:
            window = self.get_active_window() or self._new_window()
            window.present()

        def do_open(self, files, _n, _hint) -> None:
            for file in files:
                window = self.get_active_window()
                if window is None or window.doc is not None:
                    window = self._new_window()
                window.present()
                if file.get_path():
                    window.open_path(Path(file.get_path()))

        def do_shutdown(self) -> None:
            if self.card_executor is not None:
                self.card_executor.shutdown(wait=False, cancel_futures=True)
            Adw.Application.do_shutdown(self)
            # Release WebKit while Python is still running (see render.new_web_context).
            self.web_context = None
            gc.collect()

        def _new_window(self):
            from signall.app.window import SignallWindow

            return SignallWindow(self)

        def _poll_card(self) -> None:
            previous = self.card
            future = self.card_executor.submit(card_status, None, previous)
            future.add_done_callback(lambda f: GLib.idle_add(self._card_polled, f))

        def _card_polled(self, future) -> bool:
            try:
                status = future.result()
            except Exception as exc:  # keep polling whatever happens
                status = CardStatus("error", f"smart card error: {exc}")
            if status != self.card:
                self.card = status
                for window in self.get_windows():
                    if hasattr(window, "update_card"):
                        window.update_card(status)
            GLib.timeout_add_seconds(CARD_POLL_SECONDS, lambda: self._poll_card() and False)
            return False

        def _about(self) -> None:
            about = Adw.AboutDialog(
                application_name="Signall", application_icon="signall", version=__version__,
                developer_name="The Signall contributors", license_type=Gtk.License.MIT_X11,
                comments="Sign PDFs and forms with your CAC",
                website="https://github.com/elevatesystems/signall",
                issue_url="https://github.com/elevatesystems/signall/issues",
            )
            about.add_legal_section("pdf.js", "© Mozilla Foundation", Gtk.License.APACHE_2_0, None)
            about.present(self.get_active_window())

    app = SignallApp()
    try:
        return app.run(sys.argv[:1] + list(argv if argv is not None else sys.argv[1:]))
    finally:
        del app
        gc.collect()
