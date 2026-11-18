<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/signall-lockup-light.svg">
    <img src="assets/signall-lockup.svg" height="72" alt="Signall">
  </picture>
</h1>

Sign PDFs with a US DoD Common Access Card (CAC) on Linux. Signall is a native GNOME app, and its signatures validate in Adobe Acrobat. It signs:

- **Any PDF:** draw a box where the signature goes.
- **PDF forms:** fill in the fields and sign in the form's own signature field.
- **XFA forms** such as DD Form 2875 (SAAR) and DD Form 2842, including forms that several people sign in turn. No other Linux tool can sign dynamic XFA forms.

Signatures carry the DoD certificate chain and revocation (OCSP) data, as Acrobat's do. The DoD root and intermediate certificates are bundled, so nothing else needs to be installed.

**Status:** early development. The command line has been tested with a real CAC on Fedora 40; the app is new and has so far been tested with a simulated card. There is no package yet, so install from source as shown below. See [docs/design.md](docs/design.md) for details and known gaps.

## Install

Signall needs Fedora 40 or newer (GNOME 46 or newer) and a CAC reader.

1. Install the system packages, and start the smart card service:

   ```sh
   sudo dnf install git python3-gobject gtk4 libadwaita webkitgtk6.0 opensc pcsc-lite pcsc-lite-ccid
   sudo systemctl enable --now pcscd.socket
   ```

2. Get the code and set it up in a virtual environment:

   ```sh
   git clone https://github.com/elevatesystems/signall.git && cd signall
   python3 scripts/fetch-pdfjs.py          # downloads the pinned pdf.js release
   /usr/bin/python3 -m venv --system-site-packages .venv
   .venv/bin/pip install -e .
   ```

   Use the system Python (`/usr/bin/python3`): it is the one that can see Fedora's GTK libraries. A Python from asdf, pyenv, or similar tools cannot.

3. Add Signall to the GNOME app search and to "Open With" for PDFs:

   ```sh
   mkdir -p ~/.local/share/applications
   sed "s|^Exec=signall-app|Exec=$PWD/.venv/bin/signall-app|" data/io.github.elevatesystems.Signall.desktop \
       > ~/.local/share/applications/io.github.elevatesystems.Signall.desktop
   cp -r data/icons ~/.local/share/
   ```

   The shortcut runs Signall from this folder, so don't move or delete it.

**Update:** `git pull`, then `.venv/bin/pip install -e .` again.
**Uninstall:** delete `~/.local/share/applications/io.github.elevatesystems.Signall.desktop`, the `signall` icons under `~/.local/share/icons/hicolor`, and the `signall` folder.

## Use the app

Open **Signall** from the app search, or right-click a PDF and choose **Open With → Signall**. You can also drag a PDF onto the window.

- **Fill in the form**, if it has one, by typing into it.
- **Sign a field:** click a highlighted signature field, or its **Sign** button in the sidebar.
- **Sign anywhere:** click **Add Signature**, then drag a box on the page. Dynamic XFA forms such as the DD 2875 only accept signatures in their own fields.
- **Enter your PIN** when asked. Signall then offers to save a signed copy named "*name* - signed.pdf"; the original is left unchanged.

The sidebar shows each signature field and whether existing signatures are valid. If the card isn't found, use **Check Smart Card** in the menu (see [Troubleshooting](#troubleshooting)).

Your PIN goes only to the card. Signall never stores or logs it.

## Use the command line

The command line does the same things. Activate the virtual environment first (`. .venv/bin/activate`, or `source .venv/bin/activate.fish` in fish).

```sh
signall doctor                          # check the reader, card, certificates, and network
signall tokens                          # find the card and its signing certificate
signall inspect form.pdf                # list signature fields
signall sign form.pdf                   # sign the first empty field (asks for the PIN)
signall sign form.pdf --field Supervisor[0].Sig[0]               # sign a specific field
signall sign form.pdf --set form1.page1.Part1.Organization="My Org"   # fill a value, then sign
signall sign cert.pdf --box 1:180,78,373,114                     # draw a box on page 1
signall verify "form - signed.pdf"
```

- `--box PAGE:x0,y0,x1,y1` is in points (1/72 inch) from the bottom-left corner of the page.
- `--set` takes an XFA data path for XFA forms, or a field name for other PDF forms. Repeat it for each value.
- `--offline` signs without contacting the DoD revocation servers. The signature then lacks revocation data.
- `-o FILE` chooses the output file. By default it's "*name* - signed.pdf", and `--force` replaces an existing one.
- `verify` exits with 0 if every signature is valid, 1 if a signature is intact but not trusted, and 2 if one is invalid.

Run `signall COMMAND --help` for all options.

## Troubleshooting

Start with **Check Smart Card** in the app's menu, or `signall doctor`. It checks each step from the reader to the DoD servers and suggests a fix for each problem. Its report never includes your name or EDIPI, so you can paste it into a bug report.

Common causes:

- **pcscd isn't running:** `sudo systemctl enable --now pcscd.socket`.
- **A virtual machine has the reader:** virt-manager, GNOME Boxes, or VirtualBox may have the USB reader passed through to a VM. Give it back to the host, or shut the VM down.
- **GnuPG holds the reader:** `gpgconf --kill scdaemon`.
- **Wrong PIN:** the card locks after a few wrong tries, and only a CAC office (RAPIDS) can unlock it.

## Development

`dev/run-tests.sh` runs the test suite in a Fedora 40 container with a virtual display and a SoftHSM2 token that behaves like a CAC. It needs Docker or Podman (with the `docker` command). `scripts/update-dod-certs.py` refreshes the bundled DoD certificates from DISA.

## License

MIT; see [LICENSE](LICENSE). pdf.js (downloaded at build time) is Apache-2.0.
