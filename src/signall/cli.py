"""Command-line interface: ``signall inspect | sign | verify | tokens | doctor``."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from signall import __version__
from signall.pdf import SignallError


def _read(path: str) -> bytes:
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise SignallError(f"can't read {path}: {exc.strerror}") from exc


def cmd_inspect(args) -> int:
    from signall.document import inspect

    info = inspect(_read(args.file))
    signed = {f.name: f for f in info.signature_fields if f.signed}
    if args.json:
        print(json.dumps({
            "kind": info.kind.value, "pages": info.page_count, "encrypted": info.encrypted,
            "usage_rights": info.usage_rights, "title": info.title, "revisions": info.revisions,
            "signature_fields": [
                {"name": f.name, "signed": f.signed, "signer": f.signer} for f in info.signature_fields
            ],
            "xfa_signature_fields": [
                {"som": f.som, "caption": f.caption.text if f.caption else None,
                 "signed": f.som in signed, "locks": list(f.lock_fields)}
                for f in info.xfa_signature_fields
            ],
        }, indent=2))
        return 0
    print(f"{args.file}")
    print(f"  Type:        {info.kind.label}")
    if info.title:
        print(f"  Title:       {info.title}")
    print(f"  Pages:       {info.page_count}")
    extras = [x for x, on in (("encrypted", info.encrypted), ("Adobe usage rights", info.usage_rights)) if on]
    if extras:
        print(f"  Notes:       {', '.join(extras)}")
    print("  Signature fields:")
    rows = info.xfa_signature_fields or info.signature_fields
    if not rows:
        print("    (none; use `signall sign --box` to add one)")
    for f in rows:
        fq = getattr(f, "som", None) or f.name
        label = f" ({f.caption.text})" if getattr(f, "caption", None) and f.caption.text else ""
        state = f"signed by {signed[fq].signer}" if fq in signed else "empty"
        print(f"    {fq}{label}: {state}")
    return 0


def _pin_from(args):
    def provide(token, cert) -> str:
        if args.pin_file:
            return Path(args.pin_file).read_text().strip()
        if not sys.stdin.isatty():
            raise SignallError("no terminal to ask for the PIN on; use --pin-file")
        print(f"Signing as {cert.subject} (card: {token.label})", file=sys.stderr)
        return getpass.getpass("PIN: ")
    return provide


def cmd_sign(args) -> int:
    from signall.signing import SignRequest, parse_box, sign

    data = _read(args.file)
    out = Path(args.output) if args.output else Path(args.file).with_name(Path(args.file).stem + " - signed.pdf")
    if out.exists() and not args.force:
        raise SignallError(f"{out} already exists; use --force to replace it")
    values = {}
    for item in args.set or []:
        key, sep, value = item.partition("=")
        if not sep:
            raise SignallError(f"--set needs PATH=VALUE, got {item!r}")
        values[key.strip()] = value
    fields = {}
    if values:
        from signall.document import Kind, inspect

        if inspect(data).kind in (Kind.PLAIN, Kind.ACROFORM):
            fields, values = values, {}  # no XFA data: --set names AcroForm fields
    request = SignRequest(
        field=args.field, box=parse_box(args.box) if args.box else None, values=values, fields=fields,
        reason=args.reason, location=args.location,
    )

    from signall.chain import prepare_embedding
    from signall.verify import load_certificates

    extra_roots = [c for path in (args.trust or []) for c in load_certificates(path)]
    embedding = None

    def chain_for(cert):
        nonlocal embedding
        embedding = prepare_embedding(cert, online=not args.offline, extra_roots=extra_roots)
        if embedding.note:
            print(f"signall: warning: {embedding.note}", file=sys.stderr)
        return embedding.chain

    if args.p12:
        from pyhanko.sign import signers

        passphrase = Path(args.pin_file).read_bytes().strip() if args.pin_file else getpass.getpass("Passphrase: ").encode()
        signer = signers.SimpleSigner.load_pkcs12(args.p12, passphrase=passphrase)
        if signer is None:
            raise SignallError(f"could not open {args.p12} (wrong passphrase?)")
        extra_roots += list(signer.cert_registry)  # the CA certificates that came with the file
        signer.cert_registry.register_multiple(chain_for(signer.signing_cert))
        signed = sign(data, signer, request, validation_context=embedding.context)
    else:
        from signall.token import find_module, open_signer

        with open_signer(find_module(args.module), _pin_from(args), chain_for=chain_for) as signer:
            signed = sign(data, signer, request, validation_context=embedding.context)

    out.write_bytes(signed)
    print(f"Signed: {out}")
    return 0


def cmd_verify(args) -> int:
    from signall.verify import load_certificates, verify

    roots = [c for path in (args.trust or []) for c in load_certificates(path)]
    reports = verify(_read(args.file), roots, online=args.online)
    if not reports:
        print("No signatures.")
        return 1
    worst = 0
    for r in reports:
        state = "VALID" if r.ok else ("INTACT, UNTRUSTED" if r.intact and r.changes_after != "other" else "INVALID")
        worst = max(worst, 0 if r.ok else (2 if not r.intact or r.changes_after == "other" else 1))
        print(f"{r.field}")
        print(f"  {state}: signed by {r.signer}" + (f" at {r.signing_time}" if r.signing_time else ""))
        print(f"  unchanged since signing: {'yes' if r.intact else 'NO'}; "
              f"certificate trusted: {'yes' if r.trusted else 'no'}; later changes: {r.changes_after}")
        print(f"  revocation data: {r.revocation}")
    return worst


def cmd_tokens(args) -> int:
    from signall.token import choose_signing_certificate, find_module, list_certificates, list_tokens

    module = find_module(args.module)
    tokens = list_tokens(module)
    print(f"PKCS#11 module: {module}")
    if not tokens:
        print("No cards found. Is the card inserted, and is pcscd running (systemctl status pcscd.socket)?")
        return 1
    for token in tokens:
        print(f"Card: {token.label} ({token.manufacturer} {token.model})")
        certs = list_certificates(module, token if len(tokens) > 1 else None)
        try:
            chosen = choose_signing_certificate(certs)
        except SignallError:
            chosen = None
        for c in certs:
            mark = "*" if chosen is not None and c.cert_id == chosen.cert_id else " "
            usage = ", ".join(sorted(c.key_usage)) or "-"
            print(f"  {mark} {c.subject}  (issuer {c.issuer}; {usage}; expires {c.not_after:%Y-%m-%d})")
        if chosen is not None:
            print("  * = used for signing")
    return 0


def cmd_doctor(args) -> int:
    from signall.doctor import Status, run_checks

    checks = run_checks(args.module, online=not args.offline)
    width = max(len(c.name) for c in checks)
    for c in checks:
        print(f"{c.status.value:<5} {c.name:<{width}}  {c.detail}")
        if c.fix and c.status in (Status.FAIL, Status.WARN):
            print(f"{'':<5} {'':<{width}}  fix: {c.fix}")
    failed = any(c.status is Status.FAIL for c in checks)
    print("\nProblems found; fix the FAIL lines first." if failed else "\nReady to sign.")
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="signall", description="Sign PDFs with a smart card (CAC/PIV).")
    parser.add_argument("--version", action="version", version=f"signall {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("inspect", help="describe a PDF and its signature fields")
    p.add_argument("file")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("sign", help="sign a PDF")
    p.add_argument("file")
    p.add_argument("-o", "--output", help="where to write the signed PDF (default: '<name> - signed.pdf')")
    p.add_argument("--force", action="store_true", help="replace the output file if it exists")
    p.add_argument("--field", help="signature field to sign (default: the first empty one)")
    p.add_argument("--box", help="add a signature box instead: PAGE:x0,y0,x1,y1 in points from the bottom-left")
    p.add_argument("--set", action="append", metavar="PATH=VALUE", help="fill a form value before signing: an XFA data path, or a field name in a PDF without XFA")
    p.add_argument("--reason")
    p.add_argument("--location")
    p.add_argument("--module", help="PKCS#11 module (default: p11-kit proxy or OpenSC)")
    p.add_argument("--p12", help="sign with a PKCS#12 file instead of a card (for testing)")
    p.add_argument("--pin-file", help="read the PIN or passphrase from a file instead of asking")
    p.add_argument("--offline", action="store_true",
                   help="don't fetch revocation data (OCSP/CRL) to embed in the signature")
    p.add_argument("--trust", action="append", metavar="CERT",
                   help="extra trusted root or CA certificate(s) (PEM or DER)")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="check the signatures in a PDF")
    p.add_argument("file")
    p.add_argument("--trust", action="append", metavar="CERT", help="extra trusted root certificate(s) (PEM or DER)")
    p.add_argument("--online", action="store_true", help="check revocation online (OCSP/CRL)")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("tokens", help="list smart cards and their certificates")
    p.add_argument("--module", help="PKCS#11 module (default: p11-kit proxy or OpenSC)")
    p.set_defaults(func=cmd_tokens)

    p = sub.add_parser("doctor", help="check the card reader, card, certificates, and network")
    p.add_argument("--module", help="PKCS#11 module (default: p11-kit proxy or OpenSC)")
    p.add_argument("--offline", action="store_true", help="skip the revocation server check")
    p.set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except SignallError as exc:
        print(f"signall: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
