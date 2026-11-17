#!/usr/bin/env python3
"""Refresh the bundled DoD PKI certificates in src/signall/trust/.

Downloads DISA's PKCS#7 certificate bundle, checks it, and writes
dod-roots.pem and dod-intermediates.pem. Run it when DISA issues new CAs
(the bundle version goes up) and commit the result.

Checks, in order:
1. The checksum file is signed by DISA's PKE code-signing credential
   (openssl smime -verify), whose chain ends at a pinned DoD root.
2. Every file in the bundle matches the signed checksums.
3. The bundle's roots are exactly the pinned roots. A new or changed root
   stops the script: confirm its fingerprint independently (for example
   against https://crl.disa.mil) and add it to PINNED_ROOTS by hand.
4. Each intermediate chains to a pinned root. Expired intermediates are kept (and checked as of
   their last valid day): they are needed to verify documents signed while they were valid.

Needs openssl and asn1crypto/pyhanko-certvalidator (the Signall venv).
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import io
import pathlib
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

URL = "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip"

# SHA-256 fingerprints, confirmed on 2026-11-17 against DISA's signed bundle v5.14, the Fedora
# system trust store, and (Root CA 6) DISA's cross-certificates at crl.disa.mil.
PINNED_ROOTS = {
    "DoD Root CA 3": "b107b33f453e5510f68e513110c6f6944bacc263df0137f821c1b3c2f8f863d2",
    "DoD Root CA 4": "559a5189452b13f8233f0022363c06f26e3c517c1d4b77445035959df3244f74",
    "DoD Root CA 5": "1f4ede9dc2a241f6521bf518424acd49ebe84420e69daf5bac57af1f8ee294a9",
    "DoD Root CA 6": "2a5e41aca93df7cc496d2369b7a0a037045d502f1abaaf76975fc07c6660cf93",
}

DEST = pathlib.Path(__file__).resolve().parent.parent / "src" / "signall" / "trust"


class BundleError(Exception):
    pass


def _cn(cert) -> str:
    return cert.subject.native.get("common_name", cert.subject.human_friendly)


def _pem(cert) -> str:
    from asn1crypto import pem

    return pem.armor("CERTIFICATE", cert.dump()).decode()


def _check_signature(folder: pathlib.Path, name: str) -> dict[str, str]:
    """Verify the signed checksum file; return {file name: sha256}."""
    from asn1crypto import pem, x509

    chain_file = folder / "DoD_PKE_CA_chain.pem"
    chain = [x509.Certificate.load(der) for _, _, der in pem.unarmor(chain_file.read_bytes(), multiple=True)]
    anchors = [c for c in chain if c.self_signed in ("yes", "maybe")]
    if len(anchors) != 1 or PINNED_ROOTS.get(_cn(anchors[0])) != anchors[0].sha256.hex():
        raise BundleError("the code-signing chain does not end at a pinned DoD root")
    result = subprocess.run(
        ["openssl", "smime", "-verify", "-inform", "DER", "-in", str(folder / f"{name}.sha256"),
         "-CAfile", str(chain_file), "-purpose", "any"],
        capture_output=True,
    )
    if result.returncode != 0:
        raise BundleError(f"bad signature on the checksum file: {result.stderr.decode().strip()}")
    sums = {}
    for line in result.stdout.decode().replace("\r", "").splitlines():
        digest, _, file_name = line.strip().partition(" ")
        if digest:
            sums[file_name.lstrip(" *")] = digest.lower()
    return sums


def _check_files(folder: pathlib.Path, sums: dict[str, str]) -> None:
    for file_name, digest in sums.items():
        path = folder / file_name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise BundleError(f"{file_name} does not match its signed checksum")


async def _chains(cert, context) -> bool:
    from pyhanko_certvalidator import CertificateValidator
    from pyhanko_certvalidator.errors import PathBuildingError, PathValidationError

    try:
        await CertificateValidator(cert, validation_context=context).async_validate_usage(set())
        return True
    except (PathBuildingError, PathValidationError):
        return False


def _select(certs, now: datetime.datetime):
    from pyhanko_certvalidator import ValidationContext
    from pyhanko_certvalidator.policy_decl import (
        CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule,
    )

    roots = [c for c in certs if c.self_signed in ("yes", "maybe")]
    found = {_cn(c): c.sha256.hex() for c in roots}
    if found != PINNED_ROOTS:
        changed = sorted(set(found.items()) ^ set(PINNED_ROOTS.items()))
        raise BundleError(f"the bundle's roots differ from the pinned ones: {changed}")
    others = [c for c in certs if c.self_signed == "no"]
    no_check = RevocationCheckingRule.NO_CHECK
    keep, dropped = [], []
    for cert in others:
        moment = min(now, cert.not_valid_after - datetime.timedelta(days=1))
        context = ValidationContext(
            trust_roots=roots, other_certs=others, moment=moment,
            revinfo_policy=CertRevTrustPolicy(RevocationCheckingPolicy(no_check, no_check)),
        )
        (keep if asyncio.run(_chains(cert, context)) else dropped).append(cert)
    return sorted(roots, key=_cn), sorted(keep, key=lambda c: (_cn(c), c.sha256.hex())), dropped


def _write(path: pathlib.Path, certs, title: str, version: str) -> None:
    lines = [
        f"# {title}",
        f"# From DISA's PKCS#7 bundle {version} ({URL}),",
        "# verified and written by scripts/update-dod-certs.py. Do not edit by hand.",
        "",
    ]
    for cert in certs:
        lines += [f"# {_cn(cert)} (issuer {cert.issuer.native.get('common_name')}; "
                  f"expires {cert.not_valid_after:%Y-%m-%d}; SHA-256 {cert.sha256.hex()})", _pem(cert)]
    path.write_text("\n".join(lines))


def main() -> int:
    from asn1crypto import cms

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--zip", help="use a bundle already downloaded instead of fetching it")
    args = parser.parse_args()

    data = pathlib.Path(args.zip).read_bytes() if args.zip else urllib.request.urlopen(
        urllib.request.Request(URL, headers={"User-Agent": "signall-update-dod-certs"}), timeout=60).read()
    with tempfile.TemporaryDirectory(prefix="signall-dod-") as tmp:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for member in archive.namelist():
                target = (pathlib.Path(tmp) / member).resolve()
                if pathlib.Path(tmp).resolve() not in target.parents:
                    raise BundleError(f"unsafe path in the archive: {member}")
            archive.extractall(tmp)
        (folder,) = [p for p in pathlib.Path(tmp).iterdir() if p.is_dir()]
        name = folder.name  # Certificates_PKCS7_v5_14_DoD
        version = name.removeprefix("Certificates_PKCS7_").removesuffix("_DoD").replace("_", ".")
        try:
            sums = _check_signature(folder, name)
            _check_files(folder, sums)
            bundle = cms.ContentInfo.load((folder / f"{name}.der.p7b").read_bytes())
            certs = [c.chosen for c in bundle["content"]["certificates"]]
            roots, intermediates, dropped = _select(certs, datetime.datetime.now(datetime.timezone.utc))
        except BundleError as exc:
            print(f"Refusing the bundle: {exc}", file=sys.stderr)
            return 1

    DEST.mkdir(parents=True, exist_ok=True)
    _write(DEST / "dod-roots.pem", roots, "DoD root CAs", version)
    _write(DEST / "dod-intermediates.pem", intermediates, "DoD intermediate CAs (helpers only, never trust anchors)",
           version)
    (DEST / "VERSION").write_text(version + "\n")
    print(f"Bundle {version}: {len(roots)} roots, {len(intermediates)} intermediates written to {DEST}")
    for cert in dropped:
        print(f"  skipped {_cn(cert)} (does not chain to a pinned root)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
