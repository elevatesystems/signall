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
    "ok": ("object-select-symbolic", "success"),
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


_CHANGES_AFTER = {
    "none": "None",
    "form filling": "Form filled in",
    "annotations": "Comments added",
    "other": "Other changes",
}


class SignatureDetailsDialog(Adw.Dialog):
    """What Signall found out about one signature: why it is (not) trusted, and its certificates."""

    def __init__(self, row, status: tuple[str, str, str]) -> None:
        super().__init__(title="Signature Details", content_width=560, content_height=680)
        from signall.verify import SOURCES, describe

        report = row.report
        icon, style, heading = status
        self._report = describe(report) if report else f"Field: {row.name}\nCouldn't check: {row.error}"

        header = Adw.HeaderBar()
        self._copy = Gtk.Button(icon_name="edit-copy-symbolic",
                                tooltip_text="Copy Details (without the signer's name or DoD ID number)")
        self._copy.connect("clicked", self._copy_details)
        header.pack_start(self._copy)

        page = Adw.PreferencesPage()
        summary = Adw.PreferencesGroup()
        top = Gtk.Box(spacing=12)
        top.append(Gtk.Image(icon_name=icon, css_classes=[style], pixel_size=32, valign=Gtk.Align.START))
        text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        text.append(Gtk.Label(label=heading, xalign=0, wrap=True, css_classes=["title-4"]))
        problem = report.problem if report else row.error
        if problem:
            text.append(Gtk.Label(label=problem, xalign=0, wrap=True, selectable=True))
        top.append(text)
        summary.add(top)
        page.add(summary)

        def prop(group, title: str, value: str) -> None:
            r = Adw.ActionRow(title=title, subtitle=value or "—", use_markup=False, subtitle_selectable=True,
                              css_classes=["property"])
            group.add_row(r) if isinstance(group, Adw.ExpanderRow) else group.add(r)

        signature = Adw.PreferencesGroup(title="Signature")
        prop(signature, "Field", row.label if row.label == row.name else f"{row.label} ({row.name})")
        if report is not None:
            prop(signature, "Signed by", report.signer)
            prop(signature, "Certificate issued by", report.issuer)
            prop(signature, "Signing time", report.signing_time or "Not recorded")
            prop(signature, "Signed content", "Intact" if report.intact else "Altered or damaged")
            prop(signature, "Changes after signing", _CHANGES_AFTER.get(report.changes_after, report.changes_after))
            prop(signature, "Revocation data", report.revocation[:1].upper() + report.revocation[1:])
        page.add(signature)

        if report is not None and report.certificates:
            certs = Adw.PreferencesGroup(title="Certificate Chain", description="From the signer up to the root CA")
            for cert in report.certificates:
                if cert.missing:
                    r = Adw.ActionRow(title=cert.name, use_markup=False, subtitle_selectable=True,
                                      subtitle="Not found: not among Signall's DoD certificates or this computer's "
                                               "trusted certificates, and not included in the signature"
                                               + (f"\nAvailable from {cert.download_url}" if cert.download_url else ""))
                    r.add_prefix(Gtk.Image(icon_name="dialog-warning-symbolic", css_classes=["warning"]))
                    certs.add(r)
                    continue
                source = SOURCES.get(cert.source, cert.source)
                expander = Adw.ExpanderRow(title=cert.name, use_markup=False,
                                           subtitle=source + (" · trusted root" if cert.trust_anchor else ""))
                prop(expander, "Issued by", cert.issuer)
                prop(expander, "Valid", f"{cert.valid_from} to {cert.valid_until}")
                if cert.key_usage:
                    prop(expander, "Key usage", cert.key_usage)
                prop(expander, "Serial number", cert.serial)
                prop(expander, "SHA-256 fingerprint", cert.sha256)
                certs.add(expander)
            page.add(certs)

        if report is not None and (report.indication or report.messages):
            tech = Adw.PreferencesGroup(title="Technical Details")
            if report.indication:
                prop(tech, "Validation result", report.indication)
            for message in report.messages:
                prop(tech, "pyHanko", message)
            page.add(tech)

        copy_group = Adw.PreferencesGroup(
            description="Paste the details into a bug report or a message to your help desk. They leave out "
                        "the signer's name and DoD ID number.")
        copy_button = Gtk.Button(label="_Copy Details", use_underline=True, halign=Gtk.Align.CENTER,
                                 css_classes=["pill"], margin_top=6)
        copy_button.connect("clicked", self._copy_details)
        copy_group.add(copy_button)
        page.add(copy_group)

        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(page)
        self.toasts = Adw.ToastOverlay(child=view)
        self.set_child(self.toasts)

    def _copy_details(self, _button) -> None:
        Gdk.Display.get_default().get_clipboard().set(self._report)
        self.toasts.add_toast(Adw.Toast(title="Details copied", timeout=2))
