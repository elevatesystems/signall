"""Certificate chains and revocation data to embed in signatures.

Acrobat puts the signer's certificate chain and OCSP/CRL responses into every
signature (the latter in the ``adbe-revocationInfoArchival`` signed
attribute). A recipient can then validate the signature without fetching
anything, and the signature stays verifiable after the certificate expires.
Signall does the same.

A CAC holds no CA certificates, so the chain comes from the system trust store
or, when online, from the certificate's AIA "CA Issuers" URL. For DoD
certificates, OCSP (``ocsp.disa.mil``) answers for both the signer and its
issuing CA, so no CRLs (which run to tens of megabytes) are downloaded.
"""
from __future__ import annotations

import asyncio
import datetime
from dataclasses import dataclass, field

from asn1crypto import x509

from signall.pdf import SignallError

FETCH_TIMEOUT_SECONDS = 10


def split_trust_store(certs: list[x509.Certificate]) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    """(roots, intermediates). Only self-signed certificates anchor trust; the rest help build paths.

    Some trust stores (for example after installing the DoD bundle) list
    intermediate CAs as anchors. A path would then stop at the intermediate,
    and neither the root nor the intermediate's revocation status would be
    embedded.
    """
    roots, intermediates = [], []
    for cert in certs:
        (roots if cert.self_signed in ("yes", "maybe") else intermediates).append(cert)
    return roots, intermediates


def validation_context(*, fetch: bool, require_revocation: bool, extra_roots=(), ocsps=(), crls=(),
                       moment: datetime.datetime | None = None):
    from pyhanko_certvalidator import ValidationContext
    from pyhanko_certvalidator.policy_decl import (
        CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule,
    )

    from signall.verify import system_trust_roots

    roots, intermediates = split_trust_store(system_trust_roots() + list(extra_roots))
    backend = None
    if fetch:
        from pyhanko_certvalidator.fetchers.requests_fetchers import RequestsFetcherBackend

        backend = RequestsFetcherBackend(per_request_timeout=FETCH_TIMEOUT_SECONDS)
    rule = RevocationCheckingRule.CRL_OR_OCSP_REQUIRED if require_revocation else RevocationCheckingRule.NO_CHECK
    return ValidationContext(
        trust_roots=roots, other_certs=intermediates, allow_fetching=fetch,
        fetcher_backend=backend,
        revinfo_policy=CertRevTrustPolicy(RevocationCheckingPolicy(rule, rule)),
        ocsps=list(ocsps), crls=list(crls), moment=moment,
    )


@dataclass
class Embedding:
    """What to put into a signature besides the signer's own certificate."""
    chain: list[x509.Certificate] = field(default_factory=list)
    """Issuing CAs up to and including the root (empty if no chain could be built)."""
    context: object | None = None
    """Validation context holding the revocation data; None means embed none."""
    note: str | None = None
    """Why the chain or the revocation data is missing, for the user."""


async def _path(cert: x509.Certificate, context):
    from pyhanko_certvalidator import CertificateValidator

    return await CertificateValidator(cert, validation_context=context).async_validate_usage(set())


def _issuers(path) -> list[x509.Certificate]:
    certs = list(path)  # root first, signer last
    return certs[:-1][::-1]


def prepare_embedding(cert: x509.Certificate, *, online: bool, extra_roots=(), known_ocsps=(), known_crls=(),
                      moment: datetime.datetime | None = None) -> Embedding:
    """Build the chain for ``cert`` and collect its revocation data.

    Raises SignallError if the certificate has been revoked. Any other
    problem (no network, unknown root) gives a chain and/or revocation data
    that is as complete as possible, plus a note saying what is missing.
    """
    from pyhanko_certvalidator.errors import PathBuildingError, PathValidationError, RevokedError

    want_revocation = online or bool(known_ocsps) or bool(known_crls)
    problem = None
    if want_revocation:
        context = validation_context(fetch=online, require_revocation=True, extra_roots=extra_roots,
                                     ocsps=known_ocsps, crls=known_crls, moment=moment)
        try:
            path = asyncio.run(_path(cert, context))
            return Embedding(chain=_issuers(path), context=context)
        except RevokedError as exc:
            raise SignallError("your signing certificate has been revoked; get a new one at a RAPIDS ID card "
                               "office") from exc
        except PathBuildingError:
            problem = "no chain to a trusted root (are the DoD root certificates installed?)"
        except PathValidationError as exc:
            problem = f"the revocation check failed ({_short(exc)})"
        except OSError as exc:
            problem = f"the revocation servers could not be reached ({exc})"

    # Offline, or the online attempt failed: embed whatever chain the local trust store gives.
    context = validation_context(fetch=False, require_revocation=False, extra_roots=extra_roots, moment=moment)
    try:
        chain = _issuers(asyncio.run(_path(cert, context)))
    except (PathBuildingError, PathValidationError):
        chain = []
        if problem is None:
            problem = "no chain to a trusted root in the local trust store"
    if problem is None:
        problem = "offline"
    return Embedding(chain=chain, note=f"no revocation data embedded: {problem}")


def _short(exc: Exception) -> str:
    text = str(exc.args[0] if exc.args else exc)
    return text if len(text) <= 200 else text[:197] + "..."
