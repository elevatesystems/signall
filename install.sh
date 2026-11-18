#!/usr/bin/env bash
# Install Signall for the current user, or update it.
#   ./install.sh               install or update
#   ./install.sh --uninstall   remove it
# Everything goes under ~/.local. sudo is used only to install missing system packages
# and to start the smart card service.
set -euo pipefail

APP_ID=io.github.elevatesystems.Signall
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
HOME_DIR="$DATA/signall"
BIN="$HOME/.local/bin"
PACKAGES=(python3-gobject gobject-introspection gtk4 libadwaita webkitgtk6.0 opensc pcsc-lite pcsc-lite-ccid)

cd "$(dirname "$0")"
say() { printf '\033[1m%s\033[0m\n' "$*"; }

refresh_caches() {
    update-desktop-database "$DATA/applications" 2>/dev/null || true
    gtk-update-icon-cache -q -f -t "$DATA/icons/hicolor" 2>/dev/null || true
}

if [ "${1:-}" = "--uninstall" ]; then
    rm -rf "$HOME_DIR"
    rm -f "$BIN/signall" "$BIN/signall-app" "$DATA/applications/$APP_ID.desktop"
    find "$DATA/icons/hicolor" -name 'signall.png' -o -name 'signall.svg' -o -name 'signall-symbolic.svg' 2>/dev/null \
        | xargs -r rm -f
    refresh_caches
    say "Signall is uninstalled. (System packages such as opensc were left in place.)"
    exit 0
elif [ $# -gt 0 ]; then
    echo "usage: $0 [--uninstall]" >&2
    exit 2
fi

# 1. System packages and the smart card service.
missing=()
for pkg in "${PACKAGES[@]}"; do
    rpm -q "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done
if [ ${#missing[@]} -gt 0 ]; then
    say "Installing system packages: ${missing[*]}"
    sudo dnf install -y "${missing[@]}"
fi
if [ -d /run/systemd/system ] && ! systemctl is-active --quiet pcscd.socket; then
    say "Starting the smart card service (pcscd)"
    sudo systemctl enable --now pcscd.socket
fi

# 2. Signall itself, in its own environment. It uses the system Python, which can see
#    Fedora's GTK libraries.
if [ ! -f src/signall/render/pdfjs/build/pdf.min.mjs ]; then
    say "Downloading pdf.js"
    /usr/bin/python3 scripts/fetch-pdfjs.py
fi
say "Installing Signall into $HOME_DIR"
/usr/bin/python3 -m venv --clear --system-site-packages "$HOME_DIR/venv"
"$HOME_DIR/venv/bin/pip" install --quiet --disable-pip-version-check .

# 3. Commands, the app-search entry, and icons.
mkdir -p "$BIN" "$DATA/applications" "$DATA/icons"
ln -sf "$HOME_DIR/venv/bin/signall" "$BIN/signall"
ln -sf "$HOME_DIR/venv/bin/signall-app" "$BIN/signall-app"
sed "s|^Exec=signall-app|Exec=$HOME_DIR/venv/bin/signall-app|" "data/$APP_ID.desktop" \
    > "$DATA/applications/$APP_ID.desktop"
cp -r data/icons/hicolor "$DATA/icons/"
refresh_caches

say "Done. Open Signall from the app search, or run signall-app."
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "Note: $BIN is not on your PATH, so the signall command needs its full path there." ;;
esac
