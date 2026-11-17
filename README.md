<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/signall-lockup-light.svg">
    <img src="assets/signall-lockup.svg" height="72" alt="Signall">
  </picture>
</h1>

Sign PDFs with a US DoD Common Access Card (CAC) on Linux. Signall is a native GNOME app, and its signatures validate in Adobe Acrobat. It works on plain PDFs, AcroForms, and dynamic XFA forms such as DD Form 2875.

**Status:** early development; the command-line core works, the GNOME app does not exist yet. See [docs/design.md](docs/design.md).

## Try the command line

Needs Fedora 40 or newer with `python3-gobject`, `gtk4`, `webkitgtk6.0`, `opensc`, and `pcsc-lite`.

Build the virtual environment with the system Python (`/usr/bin/python3`), so that it can see Fedora's PyGObject. A Python from asdf, pyenv, or similar tools cannot, and may also be older than the 3.12 that Signall requires. In fish, activate with `source .venv/bin/activate.fish`.

```sh
python3 scripts/fetch-pdfjs.py          # downloads the pinned pdf.js release
/usr/bin/python3 -m venv --system-site-packages .venv && . .venv/bin/activate
pip install -e .

signall doctor                          # check the reader, card, certificates, and network
signall tokens                          # find the card and its signing certificate
signall inspect form.pdf                # list signature fields
signall sign form.pdf                   # sign the first empty field (asks for the PIN)
signall sign cert.pdf --box 1:180,78,373,114   # add a signature box on page 1
signall verify "form - signed.pdf"
```

## Try the app

With the same virtual environment, run `signall-app`, or `signall-app form.pdf`. Open a PDF, type into the form if it has one, then click a highlighted signature field or use **Add Signature** to draw a box. Signall asks for your PIN and saves a signed copy next to the original.

To add Signall to the GNOME app grid and to "Open With" for PDFs:

```sh
mkdir -p ~/.local/share/applications
sed "s|^Exec=signall-app|Exec=$PWD/.venv/bin/signall-app|" data/io.github.elevatesystems.Signall.desktop \
    > ~/.local/share/applications/io.github.elevatesystems.Signall.desktop
cp -r data/icons ~/.local/share/
```

## Tests

`dev/run-tests.sh` runs the test suite in a Fedora 40 container with a virtual display and a SoftHSM2 token that behaves like a CAC. It needs Docker or Podman (with the `docker` command).

## License

MIT; see [LICENSE](LICENSE). pdf.js (downloaded at build time) is Apache-2.0.
