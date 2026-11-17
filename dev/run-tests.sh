#!/usr/bin/env bash
# Run a command in the Fedora 40 dev container with a virtual display.
# Usage: dev/run-tests.sh [command...]   (default: pytest)
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
image=signall-dev
docker image inspect "$image" >/dev/null 2>&1 || docker build -t "$image" -f "$repo/dev/Containerfile" "$repo/dev"
extra=()
# Hosts in FIPS mode leak that into containers; test like a regular desktop.
[ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)" = 1 ] && extra+=(-v /dev/null:/proc/sys/crypto/fips_enabled:ro)
cmd=("$@"); [ ${#cmd[@]} -eq 0 ] && cmd=(python3 -m pytest -q)
exec docker run --rm "${extra[@]}" -v "$repo:/src" -w /src \
  -e WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1 -e GTK_A11Y=none -e GDK_BACKEND=x11 \
  -e SIGNALL_OUT="${SIGNALL_OUT:-}" \
  "$image" bash -c '
    Xvfb :99 -screen 0 1280x1024x24 >/dev/null 2>&1 & export DISPLAY=:99
    python3 -m venv --system-site-packages /tmp/venv >/dev/null && . /tmp/venv/bin/activate
    pip install -q -e ".[test]" 2>&1 | grep -v -i "notice" || true
    exec dbus-run-session -- "$@"' _ "${cmd[@]}"
