"""Dialogs: the PIN prompt, errors, unsaved changes, and card troubleshooting."""
from __future__ import annotations

import threading
from typing import Callable

import gi

gi.require_version("Adw", "1")
gi.require_version("Gtk", "4.0")
from gi.repository import Adw, Gdk, GLib, Gtk  # noqa: E402

PIN_LENGTHS = range(4, 9)  # PIV PINs are 4–8 digits


def ask_pin(parent: Gtk.Widget, signer: str | None, issuer: str | None,
            on_result: Callable[[str | None], None]) -> None:
    """Ask for the card PIN; ``on_result(pin)`` gets None if the user cancels.

    The PIN is handed straight to the callback and cleared from the entry. It is never logged.
    """
    body = f"Signing as {signer}" if signer else "Signing with your smart card"
    if issuer:
        body += f"\nCertificate from {issuer}"
    dialog = Adw.AlertDialog.new("Enter Your PIN", body)
    dialog.add_response("cancel", "_Cancel")
    dialog.add_response("sign", "_Sign")
    dialog.set_response_appearance("sign", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("sign")
    dialog.set_close_response("cancel")
    dialog.set_response_enabled("sign", False)

    entry = Gtk.PasswordEntry(activates_default=True, placeholder_text="PIN")
    entry.update_property([Gtk.AccessibleProperty.LABEL], ["PIN"])
    entry.add_css_class("card")

    def changed(_entry) -> None:
        text = entry.get_text()
        dialog.set_response_enabled("sign", text.isdigit() and len(text) in PIN_LENGTHS)

    entry.connect("changed", changed)
    dialog.set_extra_child(entry)

    def responded(_dialog, response: str) -> None:
        pin = entry.get_text() if response == "sign" else None
        entry.set_text("")
        on_result(pin)

    dialog.connect("response", responded)
    dialog.present(parent)
    entry.grab_focus()


def show_error(parent: Gtk.Widget, heading: str, body: str, *, troubleshoot: Callable[[], None] | None = None) -> None:
    dialog = Adw.AlertDialog.new(heading, body)
    if troubleshoot is not None:
        dialog.add_response("troubleshoot", "_Troubleshoot")
    dialog.add_response("close", "_Close")
    dialog.set_default_response("close")
    dialog.set_close_response("close")
    if troubleshoot is not None:
        dialog.connect("response", lambda _d, r: troubleshoot() if r == "troubleshoot" else None)
    dialog.present(parent)


def confirm_discard(parent: Gtk.Widget, name: str, on_result: Callable[[str], None]) -> None:
    """Ask what to do with an unsaved signed copy; ``on_result`` gets "save", "discard", or "cancel"."""
    dialog = Adw.AlertDialog.new(
        "Save the Signed Copy?",
        f"“{name}” was signed but not saved. If you don't save it, the signature is lost and you will "
        "need to sign again.")
    dialog.add_response("cancel", "_Cancel")
    dialog.add_response("discard", "_Discard")
    dialog.add_response("save", "_Save…")
    dialog.set_response_appearance("discard", Adw.ResponseAppearance.DESTRUCTIVE)
    dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
    dialog.set_default_response("save")
    dialog.set_close_response("cancel")
    dialog.connect("response", lambda _d, r: on_result(r))
    dialog.present(parent)


_STATUS_STYLE = {
    "ok": ("emblem-ok-symbolic", "success"),
    "warn": ("dialog-warning-symbolic", "warning"),
    "FAIL": ("dialog-error-symbolic", "error"),
    "skip": ("action-unavailable-symbolic", "dim-label"),
}


class TroubleshootDialog(Adw.Dialog):
    """Runs ``signall doctor``'s checks and shows them, with fixes."""

    def __init__(self, module: str | None = None) -> None:
        super().__init__(title="Smart Card Check", content_width=560, content_height=640)
        self._module = module
        self._report = ""

        header = Adw.HeaderBar()
        self._copy = Gtk.Button(icon_name="edit-copy-symbolic", tooltip_text="Copy Report", sensitive=False)
        self._copy.connect("clicked", self._copy_report)
        header.pack_start(self._copy)
        self._rerun = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Check Again", sensitive=False)
        self._rerun.connect("clicked", lambda _b: self._run())
        header.pack_end(self._rerun)

        self._stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        busy = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, valign=Gtk.Align.CENTER)
        spinner = Gtk.Spinner(spinning=True, width_request=32, height_request=32)
        busy.append(spinner)
        busy.append(Gtk.Label(label="Checking the card reader, card, and certificates…", css_classes=["dim-label"]))
        self._stack.add_named(busy, "busy")
        self._page = Adw.PreferencesPage()
        self._stack.add_named(self._page, "results")

        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(self._stack)
        self.set_child(view)
        self._group: Adw.PreferencesGroup | None = None
        self._run()

    def _run(self) -> None:
        self._stack.set_visible_child_name("busy")
        self._rerun.set_sensitive(False)
        self._copy.set_sensitive(False)

        def work() -> None:
            from signall.doctor import run_checks

            try:
                checks = run_checks(self._module, online=True)
                error = None
            except Exception as exc:  # report it in the dialog rather than lose it
                checks, error = [], str(exc)
            GLib.idle_add(self._show, checks, error)

        threading.Thread(target=work, name="signall-doctor", daemon=True).start()

    def _show(self, checks, error) -> bool:
        if self._group is not None:
            self._page.remove(self._group)
        failed = [c for c in checks if c.status.value == "FAIL"]
        group = Adw.PreferencesGroup(
            title="Everything Looks Good" if checks and not failed else "Problems Found" if failed else "Check Failed",
            description=error or ("Your card is ready to sign." if checks and not failed else
                                  "Follow the suggested fixes, then check again."),
        )
        lines = []
        for check in checks:
            icon, style = _STATUS_STYLE.get(check.status.value, _STATUS_STYLE["skip"])
            subtitle = check.detail + (f"\n{check.fix}" if check.fix and check.status.value != "ok" else "")
            row = Adw.ActionRow(title=check.name, subtitle=subtitle, use_markup=False)
            row.add_prefix(Gtk.Image(icon_name=icon, css_classes=[style]))
            group.add(row)
            lines.append(f"[{check.status.value}] {check.name}: {check.detail}" + (f" ({check.fix})" if check.fix else ""))
        self._page.add(group)
        self._group = group
        self._report = "\n".join(lines) or (error or "")
        self._stack.set_visible_child_name("results")
        self._rerun.set_sensitive(True)
        self._copy.set_sensitive(bool(self._report))
        return False

    def _copy_report(self, _button) -> None:
        Gdk.Display.get_default().get_clipboard().set(self._report)
        self._copy.set_tooltip_text("Copied")
