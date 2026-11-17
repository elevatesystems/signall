"""DoD PKI certificates bundled with Signall.

The files come from DISA's signed PKCS#7 bundle; scripts/update-dod-certs.py
verifies and refreshes them. Only the roots are trust anchors. The
intermediates help build chains offline, and for documents signed under CAs
that have since expired.
"""
from __future__ import annotations

from functools import cache
from importlib import resources

from asn1crypto import pem, x509


def _load(name: str) -> tuple[x509.Certificate, ...]:
    data = resources.files(__package__).joinpath(name).read_bytes()
    return tuple(x509.Certificate.load(der) for _, _, der in pem.unarmor(data, multiple=True))


@cache
def dod_roots() -> tuple[x509.Certificate, ...]:
    return _load("dod-roots.pem")


@cache
def dod_intermediates() -> tuple[x509.Certificate, ...]:
    return _load("dod-intermediates.pem")


def bundle_version() -> str:
    return resources.files(__package__).joinpath("VERSION").read_text().strip()
