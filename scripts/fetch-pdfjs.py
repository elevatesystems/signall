#!/usr/bin/env python3
"""Download the pinned pdf.js release into src/signall/render/pdfjs/.

pdf.js is not vendored in the repository; run this once after cloning
(packaging does the same at build time).
"""
import hashlib
import io
import pathlib
import sys
import tarfile
import urllib.request

VERSION = "4.10.38"
URL = f"https://registry.npmjs.org/pdfjs-dist/-/pdfjs-dist-{VERSION}.tgz"
SHA256 = "1011b38553532d7078c59f26b15a471f8dae00f101b60e2add9b8511737a1ce0"
KEEP = (
    "package/build/pdf.min.mjs",
    "package/build/pdf.worker.min.mjs",
    "package/web/pdf_viewer.mjs",
    "package/web/pdf_viewer.css",
    "package/standard_fonts/",
    "package/LICENSE",
)

DEST = pathlib.Path(__file__).resolve().parent.parent / "src" / "signall" / "render" / "pdfjs"


def main() -> int:
    if (DEST / "VERSION").is_file() and (DEST / "VERSION").read_text().strip() == VERSION:
        print(f"pdf.js {VERSION} already present in {DEST}")
        return 0
    print(f"Downloading pdf.js {VERSION}…")
    data = urllib.request.urlopen(URL, timeout=60).read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        print(f"Checksum mismatch: expected {SHA256}, got {digest}", file=sys.stderr)
        return 1
    DEST.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.startswith(KEEP):
                continue
            rel = pathlib.PurePosixPath(member.name).relative_to("package")
            if ".." in rel.parts:
                continue
            out = DEST / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(tar.extractfile(member).read())
    (DEST / "VERSION").write_text(VERSION + "\n")
    print(f"Installed pdf.js {VERSION} into {DEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
