"""Check the signatures in a PDF."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from asn1crypto import pem, x509
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from signall.pdf import open_reader

SYSTEM_BUNDLES = (
    "/etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem",
    "/etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/certs/ca-certificates.crt",
)


@dataclass
class SignatureReport:
    field: str
    signer: str
    signing_time: str | None
    intact: bool          # the signed bytes are unchanged and the math checks out
    trusted: bool         # the certificate chains to a trusted root
    covers_whole_file: bool
    changes_after: str    # "none", "form filling", "annotations", "other"

    @property
    def ok(self) -> bool:
        return self.intact and self.trusted and self.changes_after != "other"


def load_certificates(path: str | Path) -> list[x509.Certificate]:
    data = Path(path).read_bytes()
    if pem.detect(data):
        return [x509.Certificate.load(der) for _, _, der in pem.unarmor(data, multiple=True)]
    return [x509.Certificate.load(data)]


def system_trust_roots() -> list[x509.Certificate]:
    roots, seen = [], set()
    for bundle in SYSTEM_BUNDLES:
        if not Path(bundle).is_file():
            continue
        for cert in load_certificates(bundle):
            if cert.sha256 not in seen:
                seen.add(cert.sha256)
                roots.append(cert)
    return roots


_CHANGES = {"NONE": "none", "LTA_UPDATES": "none", "FORM_FILLING": "form filling",
            "ANNOTATIONS": "annotations", "OTHER": "other"}


def verify(data: bytes, extra_roots: list[x509.Certificate] = (), online: bool = False) -> list[SignatureReport]:
    reader = open_reader(data)
    context = ValidationContext(
        trust_roots=system_trust_roots() + list(extra_roots), allow_fetching=online,
    )
    reports = []
    logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
    for emb in reader.embedded_signatures:
        status = validate_pdf_signature(emb, signer_validation_context=context)
        cert = status.signing_cert
        reports.append(SignatureReport(
            field=emb.field_name,
            signer=cert.subject.native.get("common_name", cert.subject.human_friendly),
            signing_time=status.signer_reported_dt.isoformat() if status.signer_reported_dt else None,
            intact=bool(status.intact and status.valid),
            trusted=bool(status.trusted),
            covers_whole_file=status.coverage.name == "ENTIRE_FILE",
            changes_after=_CHANGES.get(status.modification_level.name, "other") if status.modification_level else "none",
        ))
    return reports
