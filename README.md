<img src="assets/icon.svg" width="64" height="64" alt="">

# signall

Sign PDFs with a US DoD Common Access Card (CAC) on Linux. Signall is a native GNOME app, and its signatures validate in Adobe Acrobat. It works on plain PDFs, AcroForms, and dynamic XFA forms such as DD Form 2875.

**Status:** early development; the command-line core works, the GNOME app does not exist yet. See [docs/design.md](docs/design.md).

## Try the command line

Needs Fedora 40 or newer with `python3-gobject`, `gtk4`, `webkitgtk6.0`, `opensc`, and `pcsc-lite`.

```sh
python3 scripts/fetch-pdfjs.py          # downloads the pinned pdf.js release
python3 -m venv --system-site-packages .venv && . .venv/bin/activate
pip install -e .

signall tokens                          # find the card and its signing certificate
signall inspect form.pdf                # list signature fields
signall sign form.pdf                   # sign the first empty field (asks for the PIN)
signall sign cert.pdf --box 1:180,78,373,114   # add a signature box on page 1
signall verify "form - signed.pdf"
```

## Tests

`dev/run-tests.sh` runs the test suite in a Fedora 40 container with a virtual display and a SoftHSM2 token that behaves like a CAC. It needs Docker or Podman (with the `docker` command).

## License

MIT; see [LICENSE](LICENSE). pdf.js (downloaded at build time) is Apache-2.0.
