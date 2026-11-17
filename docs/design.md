# Signall design

Signall is a native GNOME app for signing PDFs with a US DoD Common Access Card (CAC) on Linux. The signatures it produces should validate in Adobe Acrobat, including signatures in dynamic XFA forms such as DD Form 2875, which no other Linux tool can sign.

Targets: Fedora 40+ and GNOME 46+.

## Document types

| Type | Example | What signing needs |
|---|---|---|
| Plain PDF, no signature field | Training certificates | The user draws a box, and Signall creates a signature field and signs it. |
| Static XFA with an AcroForm fallback | DD 2842 | Fill and sign the existing `/Sig` fields. These forms are often AES-encrypted with an empty user password and carry Adobe usage rights (`/Perms/UR3`). |
| Dynamic XFA (`/NeedsRendering true`) | DD 2875 (SAAR) | The PDF holds only a "Please wait…" page. The real form, including its signature fields, exists only as XFA 3.3 XML. Several people sign in sequence. |

### How a dynamic XFA form is signed

This is what Acrobat does, and Signall copies it. The approach has been checked in Acrobat Reader, which reports "Signature is valid" and lets a later signer countersign in Acrobat.

1. **Leave the original bytes untouched.** All changes go into one incremental update that also contains the signature.
2. **Keep `/XFA`, `/NeedsRendering`, and `/Perms/UR3`.** Without UR3, Reader cannot save or sign the form. The changes below stay within what UR3 permits, so Reader shows no "extended features" warning.
3. **Write the filled data** into a new `datasets` packet. This includes the signature date fields (`signedDate`).
4. **Write pre-rendered page content** for every page. Signall renders the XFA layout and adds the result as real page content.
   - **Why:** once signature widgets exist, non-Adobe viewers (browsers, Okular, MuPDF) stop treating the file as XFA and draw the page content instead. Without this step, a recipient would see "Please wait…".
5. **Create an AcroForm `/Sig` widget for every XFA signature field**, named by its full SOM path (for example `form1[0].page1[0].Part1[0].userSig[0].userSig[0]`). Intermediate field nodes carry only `/T`, `/Kids`, and `/Parent`. Acrobat binds these widgets to the XFA fields by name.
6. **Sign** with `adbe.pkcs7.detached` and embed revocation data.

**Known gap:** Acrobat writes a `checksum` attribute on the XFA `form` packet. The algorithm is unknown; it is not a SHA-1 or MD5 of the raw or canonicalized packets. Without it, Acrobat recomputes two script-driven page counters when it opens the file and reports them as an allowed form fill after signing. The signature still validates.

## CAC and PKI

- **Stack:** pcscd and the CCID driver talk to the reader. OpenSC (`opensc-pkcs11.so`) provides the PKCS#11 module, and p11-kit-proxy exposes it to applications. CoolKey is obsolete.
- **Signing certificate:** PIV slot 9C, "Digital Signature". It is issued by a `DOD EMAIL CA-xx` and has key usage `digitalSignature` and `nonRepudiation`. Signall picks it automatically; users otherwise face 3–6 near-identical certificates.
- **PIN on every signature:** the 9C key has `CKA_ALWAYS_AUTHENTICATE`, so every signature needs a fresh `C_Login(CKU_CONTEXT_SPECIFIC)`. NSS-based tools (Okular, GNOME Papers, Firefox) mishandle this and end up in PIN loops or hangs. Signall calls PKCS#11 directly and does the context login itself.
- **Algorithms:** RSA-2048 with SHA-256 today. The DoD is moving to RSA-3072/4096 with SHA-384 by the end of 2027. Do not hard-code either.
- **Trust:** Signall bundles the DoD root and intermediate CAs from DISA's signed PKCS#7 bundle (`src/signall/trust/`). `scripts/update-dod-certs.py` refreshes them: it checks DISA's signature on the bundle's checksums, the checksums themselves, and that the roots match the fingerprints pinned in the script; a new DoD root needs a human to confirm and pin it. Only the roots are trust anchors. Intermediates are kept after they expire, because documents signed under them still need them. The system trust store is used as well. Revocation uses OCSP at `ocsp.disa.mil` and CRLs from `crl.disa.mil`. Signall embeds revocation data so that recipients can validate the signature without extra setup.
- **Known conflicts:**
  - GnuPG's `scdaemon` can grab the reader exclusively. Set `pcsc-shared`, or kill scdaemon.
  - A Flatpak build would need `--socket=pcsc` and a PKCS#11 module inside the sandbox. For that reason, ship an RPM first.

## Architecture

```
GTK4 + libadwaita shell (Python, PyGObject)
├─ document view: pdf.js in WebKitGTK 6, bundled and offline
│    renders AcroForm and XFA forms, handles form filling, places signature boxes,
│    and prints XFA layouts to PDF for pre-rendering
└─ signall core (Python library + CLI, testable without a display)
     ├─ inspect: classify the document, find existing signatures and their validity
     ├─ fill:    AcroForm values and the XFA datasets packet
     ├─ sign:    pyHanko incremental signing, Acrobat-style appearance,
     │           embedded OCSP/CRL data, field locking
     ├─ token:   PKCS#11 via p11-kit/OpenSC, 9C auto-selection, context login,
     │           card insert/remove detection
     ├─ trust:   bundled DoD roots and intermediates
     └─ doctor:  checks pcscd, reader, card, certificates, trust, scdaemon, OCSP/CRL reachability
```

- **Why Python:** pyHanko is the only mature open-source engine that covers incremental multi-party signing, encrypted documents, field creation, PAdES, and LTV. Rust would mean writing that stack from scratch. PyGObject with libadwaita still gives a fully native GNOME UI.
- **Why pdf.js:** it is the only free renderer that handles dynamic XFA. Using one renderer for every document type keeps a single code path.
- **The PIN goes only into Signall's own native dialog.** Signall never logs it or stores it.

## Status

Done (Phase 0 core): `signall inspect | sign | verify | tokens` for all three document types; the dynamic XFA signing approach above, with layouts rendered by pdf.js in WebKitGTK; signature-field positions read from the live layout; the Acrobat-style appearance; field locks taken from the form's XFA manifests; the per-signature PIN for the 9C key; usage-rights signatures kept intact in encrypted forms. Tests run in a Fedora 40 container (`dev/run-tests.sh`) against a SoftHSM2 token set up like a CAC.

Phase 2 so far:
- **Real hardware:** tested on Fedora 40 with an Identiv SCR3500 A reader, a PIV CAC (OpenSC `piv_II` driver), and OpenSC 0.25.0, through both p11-kit-proxy and `opensc-pkcs11.so`. Signall picks the 9C certificate (DOD EMAIL CA, digitalSignature + nonRepudiation) and asks for the PIN exactly once per signature. A DD 2875 and a plain PDF with a drawn box both verify as valid.
- **`signall doctor`** checks the PKCS#11 module, pcscd, the reader, the card, the signing certificate and its expiry, the chain to a trusted root, GnuPG's scdaemon, and whether the OCSP and CRL servers are reachable. It detects a reader that is passed through to a virtual machine (virt-manager, GNOME Boxes, QEMU, VirtualBox, VMware) and says how to get it back. Its output never includes the cardholder's name or EDIPI.
- **Bundled DoD certificates:** Signall works on a machine with no DoD certificates installed: chains, revocation data, `verify`, and `doctor` all use the bundled roots (DoD Root CA 3–6) and intermediates (bundle v5.14).
- **Chain and revocation data:** like Acrobat, every signature carries the signer's CA chain up to the root and, when online, OCSP responses for the signer and its issuing CA in the `adbe-revocationInfoArchival` attribute. The chain comes from the system trust store or the certificate's AIA URL. Only self-signed certificates in the trust store anchor the chain, so the intermediate's status is covered even when the store lists DoD intermediates as anchors. DoD's OCSP responder answers for both certificates, so no CRLs are downloaded. Signall refuses to sign with a revoked certificate. Offline (`--offline`, or when the servers can't be reached), it embeds the chain without revocation data and says so. `signall verify` reports whether revocation data is embedded and checks it as of the signing time.

- **Change analysis for XFA countersignatures:** a later signer re-renders the pages. Acrobat accepts this, but pyHanko's generic change analysis (used by `signall verify`) reports it as "other" changes. An XFA-aware policy has to distinguish an honest re-render from tampering with what non-Adobe viewers display.
- **XFA `form` packet checksum** (see above).
- **AcroForm text fields** cannot be filled yet; `--set` fills XFA data only.

## Brand

- **App icon:** the freedesktop icon name is `signall`, installed from `data/icons/hicolor/`. The 16–32 px PNGs come from a simplified drawing; 48 px and up use `scalable/apps/signall.svg`. Keep that split if you regenerate the icons. Headerbars and panels use `signall-symbolic`.
- **Colors:** ink navy `#1B2A4A` (text, outlines), sky `#8EC5EA` (icon tile), cream `#FBF3E4`, chip gold `#F2B33D`, and coral `#F26B5B`, the single accent color. Use navy text on cream and cream text on navy.
- **Wordmark:** Fraunces Bold, already converted to outlines in `assets/signall-lockup*.svg`. UI text follows the platform font.

## Roadmap

1. ~~**Core CLI**~~ (done, see Status).
2. **Real hardware:** `signall doctor`, signing with a real CAC, embedding revocation data, and validating the results in Acrobat.
3. **GTK app:** open, fill, click a signature field or draw a box, enter the PIN, save. A sidebar shows signature status.
4. **Ship:** a validation panel, card hot-plug support, a Nautilus "Sign" action, and an RPM via COPR. Flatpak comes later.
