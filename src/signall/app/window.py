"""The main window: a document view with a signatures sidebar."""
from __future__ import annotations

import threading
from pathlib import Path

import gi

gi.require_version("Adw", "1")
gi.require_version("Gtk", "4.0")
from gi.repository import Adw, Gdk, Gio, GLib, GObject, Gtk  # noqa: E402

from signall.app import dialogs  # noqa: E402
from signall.app.model import CardStatus, Document, display_name, output_name, run_signing  # noqa: E402
from signall.app.viewer import DocumentView  # noqa: E402
from signall.pdf import SignallError  # noqa: E402
from signall.signing import SignRequest  # noqa: E402


class Cancelled(SignallError):
    pass


def call_on_main(start):
    """From a worker thread, run ``start(done)`` on the main thread and wait for ``done(value)``."""
    event = threading.Event()
    box = {}

    def done(value=None) -> None:
        box["value"] = value
        event.set()

    GLib.idle_add(lambda: start(done) and False)
    event.wait()
    return box["value"]


def main_thread_renderer(pdf, fields):
    """A renderer for :func:`signall.signing.sign` that lays out XFA forms on the GTK main thread."""
    from signall.render import render_xfa_async

    result = call_on_main(lambda done: render_xfa_async(pdf, fields, lambda res, err: done((res, err))))
    rendered, error = result
    if error is not None:
        raise error
    return rendered


_STATUS = {
    "valid": ("object-select-symbolic", "success", "Valid signature"),
    "untrusted": ("dialog-warning-symbolic", "warning", "Signer's certificate is not trusted"),
    "modified": ("dialog-warning-symbolic", "warning", "Document was changed after signing"),
    "invalid": ("dialog-error-symbolic", "error", "Signature is not valid"),
    "error": ("dialog-warning-symbolic", "warning", "Couldn't check this signature"),
    None: ("object-select-symbolic", "dim-label", "Checking…"),
}


class SignallWindow(Adw.ApplicationWindow):
    def __init__(self, app) -> None:
        super().__init__(application=app, default_width=1180, default_height=860, title="Signall",
                         width_request=360, height_request=400)
        self.app = app
        self.doc: Document | None = None
        self.unsaved = False
        self.busy = False
        self._ready = False

        self._build()
        self._install_actions()
        self.connect("close-request", self._on_close_request)
        style = Adw.StyleManager.get_default()
        style.connect("notify::dark", lambda sm, _p: self.view.set_dark(sm.get_dark()))
        self.update_card(app.card)
        self._show_empty()

    # --- Layout -----------------------------------------------------------------

    def _build(self) -> None:
        self.title = Adw.WindowTitle(title="Signall")
        header = Adw.HeaderBar(title_widget=self.title)

        open_button = Gtk.Button(icon_name="document-open-symbolic", tooltip_text="Open (Ctrl+O)",
                                 action_name="win.open")
        header.pack_start(open_button)
        self.sidebar_button = Gtk.ToggleButton(icon_name="sidebar-show-symbolic", tooltip_text="Signatures (F9)",
                                               active=True, visible=False)
        header.pack_start(self.sidebar_button)

        menu = Gio.Menu()
        section = Gio.Menu()
        section.append("_Open…", "win.open")
        section.append("_Save Signed Copy…", "win.save")
        menu.append_section(None, section)
        zoom = Gio.Menu()
        zoom.append("Zoom _In", "win.zoom-in")
        zoom.append("Zoom _Out", "win.zoom-out")
        zoom.append("_Fit Width", "win.zoom-fit")
        menu.append_section(None, zoom)
        other = Gio.Menu()
        other.append("Check Smart _Card…", "win.troubleshoot")
        other.append("_About Signall", "app.about")
        menu.append_section(None, other)
        header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu, primary=True,
                                       tooltip_text="Main Menu"))

        self.draw_button = Gtk.ToggleButton(
            child=Adw.ButtonContent(icon_name="document-edit-symbolic", label="_Add Signature", use_underline=True),
            action_name="win.add-signature", tooltip_text="Draw a signature box on the page", visible=False)
        header.pack_end(self.draw_button)
        self.spinner = Gtk.Spinner(visible=False, tooltip_text="Signing…")
        header.pack_end(self.spinner)

        self.banner = Adw.Banner(button_label="_Check Card")
        self.banner.connect("button-clicked", lambda _b: self.troubleshoot())

        # Empty state
        empty = Adw.StatusPage(icon_name="signall", title="Sign a PDF",
                               description="Open a PDF, or drop one here.\nSign forms like the DD 2875, or draw a "
                                           "signature box anywhere.")
        empty_button = Gtk.Button(label="_Open PDF…", use_underline=True, action_name="win.open",
                                  halign=Gtk.Align.CENTER, css_classes=["pill", "suggested-action"])
        empty.set_child(empty_button)

        # Document state
        self.view = DocumentView(self.app.web_context)
        self.view.on_ready = self._on_view_ready
        self.view.on_error = self._on_view_error
        self.view.on_field = self.sign_field
        self.view.on_box = self._on_box

        self.split = Adw.OverlaySplitView(sidebar=self._build_sidebar(), content=self.view,
                                          min_sidebar_width=260, max_sidebar_width=340)
        self.split.bind_property("show-sidebar", self.sidebar_button, "active",
                                 GObject.BindingFlags.BIDIRECTIONAL | GObject.BindingFlags.SYNC_CREATE)

        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.stack.add_named(empty, "empty")
        self.stack.add_named(self.split, "document")
        self.toasts = Adw.ToastOverlay(child=self.stack)

        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(header)
        toolbar.add_top_bar(self.banner)
        toolbar.set_content(self.toasts)
        self.set_content(toolbar)

        narrow = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 720sp"))
        narrow.add_setter(self.split, "collapsed", True)
        self.add_breakpoint(narrow)

        drop = Gtk.DropTarget.new(Gio.File, Gdk.DragAction.COPY)
        drop.connect("drop", lambda _t, file, _x, _y: self.open_path(Path(file.get_path())) or True)
        self.stack.add_controller(drop)

        keys = Gtk.ShortcutController()
        keys.add_shortcut(Gtk.Shortcut.new(Gtk.ShortcutTrigger.parse_string("Escape"),
                                           Gtk.CallbackAction.new(self._on_escape)))
        self.add_controller(keys)

    def _build_sidebar(self) -> Gtk.Widget:
        self.fields_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"])
        self.fields_hint = Gtk.Label(wrap=True, xalign=0, css_classes=["dim-label"], visible=False)
        self.doc_summary = Gtk.Label(wrap=True, xalign=0, css_classes=["dim-label", "caption"])

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12,
                          margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
        content.append(Gtk.Label(label="Signatures", xalign=0, css_classes=["heading"]))
        content.append(self.fields_list)
        content.append(self.fields_hint)
        content.append(self.doc_summary)
        scrolled = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True, child=content)

        self.card_row = Adw.ActionRow(title="No card", use_markup=False)
        self.card_icon = Gtk.Image(icon_name="auth-smartcard-symbolic")
        self.card_row.add_prefix(self.card_icon)
        card_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, css_classes=["boxed-list"],
                                margin_top=6, margin_bottom=12, margin_start=12, margin_end=12)
        card_list.append(self.card_row)

        sidebar = Adw.ToolbarView(content=scrolled)
        sidebar.add_bottom_bar(card_list)
        return sidebar

    def _install_actions(self) -> None:
        def add(name, callback, enabled=True):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", lambda *_: callback())
            action.set_enabled(enabled)
            self.add_action(action)
            return action

        add("open", self.choose_file)
        self.save_action = add("save", self.save_as, enabled=False)
        add("zoom-in", lambda: self.view.zoom("in"))
        add("zoom-out", lambda: self.view.zoom("out"))
        add("zoom-fit", lambda: self.view.zoom("page-width"))
        add("troubleshoot", self.troubleshoot)
        add("toggle-sidebar", lambda: self.split.set_show_sidebar(not self.split.get_show_sidebar()))
        self.draw_action = Gio.SimpleAction.new_stateful("add-signature", None, GLib.Variant.new_boolean(False))
        self.draw_action.connect("change-state", self._on_draw_changed)
        self.draw_action.set_enabled(False)
        self.add_action(self.draw_action)

    # --- Documents --------------------------------------------------------------

    def choose_file(self) -> None:
        dialog = Gtk.FileDialog(title="Open PDF", modal=True)
        pdfs = Gtk.FileFilter(name="PDF documents")
        pdfs.add_mime_type("application/pdf")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(pdfs)
        dialog.set_filters(filters)
        if self.doc is not None:
            dialog.set_initial_folder(Gio.File.new_for_path(str(self.doc.path.parent)))

        def chosen(dlg, result) -> None:
            try:
                file = dlg.open_finish(result)
            except GLib.Error:
                return  # dismissed
            self.open_path(Path(file.get_path()))

        dialog.open(self, None, chosen)

    def open_path(self, path: Path) -> None:
        if self.unsaved:
            def decided(choice: str) -> None:
                if choice == "discard":
                    self.unsaved = False
                    self.open_path(path)
                elif choice == "save":
                    self.save_as(then=lambda: self.open_path(path))
            dialogs.confirm_discard(self, self.doc.path.name, decided)
            return
        try:
            doc = Document.load(path)
        except (OSError, SignallError) as exc:
            dialogs.show_error(self, "Can't Open This File", str(exc))
            return
        except Exception as exc:  # a PDF the parser can't handle
            dialogs.show_error(self, "Can't Open This File", f"{path.name} could not be read: {exc}")
            return
        self.show_document(doc)

    def show_document(self, doc: Document) -> None:
        self.doc = doc
        self._ready = False
        self._pages = 0
        self.draw_action.change_state(GLib.Variant.new_boolean(False))
        self.title.set_title(doc.path.name)
        self.title.set_subtitle(doc.info.kind.label + (" — not saved" if self.unsaved else ""))
        self.stack.set_visible_child_name("document")
        self.sidebar_button.set_visible(True)
        self.draw_button.set_visible(doc.can_draw_box)
        self.draw_action.set_enabled(doc.can_draw_box)
        self.save_action.set_enabled(self.unsaved)
        data, config = doc.view(dark=Adw.StyleManager.get_default().get_dark())
        self.view.load(data, config)
        self._fill_sidebar()
        if any(r.signed for r in doc.rows):
            self._check_signatures(doc)

    def _show_empty(self) -> None:
        self.stack.set_visible_child_name("empty")
        self.sidebar_button.set_visible(False)
        self.draw_button.set_visible(False)

    def _check_signatures(self, doc: Document) -> None:
        def work() -> None:
            from signall.verify import verify

            try:
                reports, error = verify(doc.data), None
            except Exception as exc:
                reports, error = [], f"{type(exc).__name__}: {exc}"
            GLib.idle_add(done, reports, error)

        def done(reports, error) -> bool:
            if self.doc is doc:
                doc.apply_reports(reports, error)
                self._fill_sidebar()
            return False

        threading.Thread(target=work, name="signall-verify", daemon=True).start()

    def _fill_sidebar(self) -> None:
        doc = self.doc
        self.fields_list.remove_all()
        for row in doc.rows:
            self.fields_list.append(self._field_row(row))
        self.fields_list.set_visible(bool(doc.rows))
        unsigned = [r for r in doc.rows if not r.signed]
        if not doc.rows:
            hint = "This PDF has no signature fields. Use Add Signature to draw one where your signature goes."
        elif not unsigned and doc.can_draw_box:
            hint = "Every field is signed. You can still draw another signature box with Add Signature."
        elif unsigned:
            hint = "Click a highlighted field on the page, or use Sign here."
        else:
            hint = ""
        self.fields_hint.set_label(hint)
        self.fields_hint.set_visible(bool(hint))
        self._fill_summary()

    def _fill_summary(self) -> None:
        doc = self.doc
        pages = self._pages or doc.info.page_count  # a dynamic XFA form's real pages exist once laid out
        facts = [f"{pages} page{'s' if pages != 1 else ''}"]
        if doc.info.usage_rights:
            facts.append("Adobe Reader extensions")
        if doc.info.encrypted:
            facts.append("encrypted")
        self.doc_summary.set_label(" · ".join(facts))

    def _field_row(self, row) -> Gtk.Widget:
        if row.signed:
            icon, style, status = _STATUS.get(row.status, _STATUS[None])
            subtitle = f"{row.signer or 'Unknown signer'}" + (f" · {row.date}" if row.date else "") + f"\n{status}"
            widget = Adw.ActionRow(title=row.label, subtitle=subtitle, use_markup=False)
            widget.add_prefix(Gtk.Image(icon_name=icon, css_classes=[style]))
            if row.status is not None:  # checked: offer the details
                widget.set_activatable(True)
                widget.set_tooltip_text("Show signature details")
                widget.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
                widget.connect("activated", lambda _w, r=row: dialogs.SignatureDetailsDialog(r, _STATUS[r.status]).present(self))
            return widget
        widget = Adw.ActionRow(title=row.label, subtitle="Not signed", use_markup=False)
        widget.add_prefix(Gtk.Image(icon_name="document-edit-symbolic", css_classes=["dim-label"]))
        button = Gtk.Button(label="Sign", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        button.connect("clicked", lambda _b, name=row.name: self.sign_field(name))
        widget.add_suffix(button)
        widget.set_activatable_widget(button)
        return widget

    def _on_view_ready(self, pages: int) -> None:
        self._ready = True
        self._pages = pages
        self._fill_summary()

    def _on_view_error(self, message: str) -> None:
        dialogs.show_error(self, "Can't Show This Document", message.splitlines()[0])

    # --- Card -------------------------------------------------------------------

    def update_card(self, card: CardStatus) -> None:
        if card.state == "ready":
            self.banner.set_revealed(False)
            self.card_row.set_title(card.signer or "Card ready")
            self.card_row.set_subtitle(card.issuer or "")
            self.card_icon.set_css_classes(["success"])
        else:
            text = "Insert your CAC to sign" if card.state == "absent" else card.message
            self.banner.set_title(text)
            self.banner.set_revealed(True)
            self.card_row.set_title("No card" if card.state == "absent" else "Card problem")
            self.card_row.set_subtitle("" if card.state == "absent" else card.message)
            self.card_icon.set_css_classes(["dim-label"] if card.state == "absent" else ["error"])

    def troubleshoot(self) -> None:
        dialogs.TroubleshootDialog().present(self)

    # --- Signing ----------------------------------------------------------------

    def sign_field(self, name: str) -> None:
        self._start(SignRequest(field=name))

    def _on_box(self, page: int, rect: tuple) -> None:
        self.draw_action.change_state(GLib.Variant.new_boolean(False))
        self._start(SignRequest(box=(page, rect)), drawn=True)

    def _on_draw_changed(self, action, value) -> None:
        action.set_state(value)
        on = value.get_boolean()
        self.view.set_draw_mode(on)
        if on:
            self.toasts.add_toast(Adw.Toast(title="Drag a box on the page where the signature should go",
                                            timeout=3))

    def _on_escape(self, *_args) -> bool:
        if self.draw_action.get_state().get_boolean():
            self.draw_action.change_state(GLib.Variant.new_boolean(False))
            return True
        return False

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        self.spinner.set_visible(busy)
        self.spinner.set_spinning(busy)
        self.view.set_sensitive(not busy)
        self.fields_list.set_sensitive(not busy)
        for name in ("open", "add-signature"):
            self.lookup_action(name).set_enabled(not busy and (name != "add-signature" or
                                                               (self.doc is not None and self.doc.can_draw_box)))

    def _start(self, request: SignRequest, drawn: bool = False) -> None:
        if self.busy or self.doc is None:
            return
        card = self.app.card
        if card.state != "ready":
            if drawn:
                self.view.clear_draft()
            heading = "No Card Found" if card.state == "absent" else "Card Problem"
            body = "Insert your CAC into the reader, then try again." if card.state == "absent" else card.message
            dialogs.show_error(self, heading, body, troubleshoot=self.troubleshoot)
            return
        self._set_busy(True)
        doc = self.doc
        self.view.collect(lambda data, fields, _error: self._sign(doc, request, data, fields, drawn))

    def _sign(self, doc: Document, request: SignRequest, viewer_copy: str | None, fields: dict,
              drawn: bool) -> None:
        request.fields = doc.field_changes(fields)
        try:
            request.values = doc.form_changes(viewer_copy) or doc.xfa_values_for(request.fields)
        except Exception:
            request.values = {}

        def ask_pin(_token, cert) -> str:
            pin = call_on_main(lambda done: dialogs.ask_pin(self, display_name(cert.subject), cert.issuer, done))
            if pin is None:
                raise Cancelled("cancelled")
            return pin

        def work():
            return run_signing(doc, request, ask_pin=ask_pin, renderer=main_thread_renderer)

        future = self.app.card_executor.submit(work)
        future.add_done_callback(lambda f: GLib.idle_add(self._signed, doc, f, drawn))

    def _signed(self, doc: Document, future, drawn: bool) -> bool:
        self._set_busy(False)
        try:
            outcome = future.result()
        except Cancelled:
            if drawn:
                self.view.clear_draft()
            return False
        except SignallError as exc:
            if drawn:
                self.view.clear_draft()
            message = str(exc)
            dialogs.show_error(self, "Couldn't Sign", message[:1].upper() + message[1:],
                               troubleshoot=self.troubleshoot if "card" in message else None)
            return False
        except Exception as exc:
            if drawn:
                self.view.clear_draft()
            dialogs.show_error(self, "Couldn't Sign", f"Something went wrong: {exc}")
            return False

        self.unsaved = True
        self.show_document(Document.load(doc.path, outcome.data))
        if outcome.note:
            self.toasts.add_toast(Adw.Toast(title=f"Signed without revocation data: {outcome.note}", timeout=8))
        self.save_as()
        return False

    # --- Saving -----------------------------------------------------------------

    def save_as(self, then=None) -> None:
        if self.doc is None or not self.unsaved:
            return
        dialog = Gtk.FileDialog(title="Save Signed Copy", modal=True, initial_name=output_name(self.doc.path))
        dialog.set_initial_folder(Gio.File.new_for_path(str(self.doc.path.parent)))

        def chosen(dlg, result) -> None:
            try:
                file = dlg.save_finish(result)
            except GLib.Error:
                self.toasts.add_toast(Adw.Toast(title="The signed copy is not saved yet", button_label="_Save",
                                                action_name="win.save", timeout=0))
                return
            path = Path(file.get_path())
            try:
                path.write_bytes(self.doc.data)
            except OSError as exc:
                dialogs.show_error(self, "Couldn't Save", str(exc))
                return
            self.unsaved = False
            self.doc.path = path
            self.title.set_title(path.name)
            self.title.set_subtitle(self.doc.info.kind.label)
            self.save_action.set_enabled(False)
            self.toasts.add_toast(Adw.Toast(title=f"Saved “{path.name}”", timeout=3))
            if then:
                then()

        dialog.save(self, None, chosen)

    def _on_close_request(self, _window) -> bool:
        if not self.unsaved:
            self.view.unload()
            return False

        def decided(choice: str) -> None:
            if choice == "discard":
                self.unsaved = False
                self.close()
            elif choice == "save":
                self.save_as(then=self.close)

        dialogs.confirm_discard(self, self.doc.path.name, decided)
        return True
