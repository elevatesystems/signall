#!/usr/bin/env bash
# Build the Signall RPM for the Fedora release this runs on (run it in a Fedora container).
# Usage: packaging/build-rpm.sh [--srpm] [OUTDIR]     (default: dist/)
#   --srpm   build only the source RPM, which is what COPR builds from
set -euo pipefail
cd "$(dirname "$0")/.."
mode=-bb
[ "${1:-}" = --srpm ] && { mode=-bs; shift; }
out=$(realpath -m "${1:-dist}")

if [ "$(id -u)" = 0 ]; then
    dnf -y -q install rpm-build python3-devel python3-pip gcc git desktop-file-utils libappstream-glib
fi

version=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/signall/__init__.py)
rpm_version=${version/.dev/\~dev}   # 0.2.0.dev0 -> 0.2.0~dev0, which sorts before 0.2.0
[ -f src/signall/render/pdfjs/build/pdf.min.mjs ] || python3 scripts/fetch-pdfjs.py

top=$(mktemp -d)
trap 'rm -rf "$top"' EXIT
mkdir -p "$top/SOURCES" "$top/SPECS" "$out"
mapfile -t files < <(git -c safe.directory='*' ls-files)
tar czf "$top/SOURCES/signall-$rpm_version.tar.gz" --transform "s,^,signall-$rpm_version/," \
    "${files[@]}" src/signall/render/pdfjs
# The version goes into the spec itself so a source RPM rebuilds anywhere.
sed "s/%{signall_version}/$rpm_version/" packaging/signall.spec > "$top/SPECS/signall.spec"
rpmbuild "$mode" --define "_topdir $top" "$top/SPECS/signall.spec"
if [ "$mode" = -bs ]; then cp "$top"/SRPMS/*.rpm "$out/"; else cp "$top"/RPMS/*/*.rpm "$out/"; fi
ls -1 "$out"/*.rpm
