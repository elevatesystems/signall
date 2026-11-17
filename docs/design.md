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
- **Trust:** the DoD Root CAs come from DISA's PKCS#7 bundle. Revocation uses OCSP at `ocsp.disa.mil` and CRLs from `crl.disa.mil`. Signall embeds revocation data so that recipients can validate the signature without extra setup.
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
     └─ doctor:  checks pcscd, reader, driver, certificates, scdaemon, OCSP reachability
```

- **Why Python:** pyHanko is the only mature open-source engine that covers incremental multi-party signing, encrypted documents, field creation, PAdES, and LTV. Rust would mean writing that stack from scratch. PyGObject with libadwaita still gives a fully native GNOME UI.
- **Why pdf.js:** it is the only free renderer that handles dynamic XFA. Using one renderer for every document type keeps a single code path.
- **The PIN goes only into Signall's own native dialog.** Signall never logs it or stores it.

## Roadmap

1. **Core CLI:** `signall inspect | sign | verify` for all three document types. Includes the Acrobat-style appearance, the pre-render pipeline, and a SoftHSM2 test token configured to behave like a CAC.
2. **Real hardware:** `signall doctor`, signing with a real CAC, and validating the results in Acrobat.
3. **GTK app:** open, fill, click a signature field or draw a box, enter the PIN, save. A sidebar shows signature status.
4. **Ship:** a validation panel, card hot-plug support, a Nautilus "Sign" action, and an RPM via COPR. Flatpak comes later.
