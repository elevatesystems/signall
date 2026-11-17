"""Certificate chains and Acrobat-style revocation data in signatures."""
import pytest

from signall import verify as verify_module
from signall.chain import prepare_embedding, split_trust_store
from signall.pdf import SignallError, open_reader
from signall.signing import SignRequest, sign
from signall.verify import embedded_revocation_info, verify

from conftest import ocsp_response

BOX = SignRequest(box=(0, (72, 72, 288, 108)))


@pytest.fixture(autouse=True)
def no_system_trust(monkeypatch):
    """Keep the host's trust store out of these tests."""
    monkeypatch.setattr(verify_module, "system_trust_roots", lambda: [])


def _names(certs):
    return [c.subject.native["common_name"] for c in certs]


def _good_ocsps(pki):
    return [ocsp_response(pki.signing, pki.email_ca), ocsp_response(pki.email_ca, pki.root)]


def test_split_trust_store(pki):
    roots, intermediates = split_trust_store([pki.email_ca.asn1, pki.root.asn1, pki.id_ca.asn1])
    assert _names(roots) == ["Signall Test Root CA"]
    assert _names(intermediates) == ["SIGNALL TEST EMAIL CA-1", "SIGNALL TEST ID CA-1"]


def test_embedding_with_revocation_data(pki):
    # The intermediate is in the trust store as an anchor (as DoD bundles often install it); the
    # chain must still run up to the root, so that the intermediate's status is checked too.
    embedding = prepare_embedding(pki.signing.asn1, online=False, extra_roots=[pki.root.asn1, pki.email_ca.asn1],
                                  known_ocsps=_good_ocsps(pki))
    assert embedding.note is None
    assert _names(embedding.chain) == ["SIGNALL TEST EMAIL CA-1", "Signall Test Root CA"]
    assert embedding.context is not None


def test_revoked_certificate_is_refused(pki):
    ocsps = [ocsp_response(pki.signing, pki.email_ca, revoked=True), ocsp_response(pki.email_ca, pki.root)]
    with pytest.raises(SignallError, match="revoked"):
        prepare_embedding(pki.signing.asn1, online=False, extra_roots=[pki.root.asn1, pki.email_ca.asn1],
                          known_ocsps=ocsps)


def test_offline_embeds_chain_only(pki):
    embedding = prepare_embedding(pki.signing.asn1, online=False, extra_roots=[pki.root.asn1, pki.email_ca.asn1])
    assert _names(embedding.chain) == ["SIGNALL TEST EMAIL CA-1", "Signall Test Root CA"]
    assert embedding.context is None
    assert embedding.note == "no revocation data embedded: offline"


def test_missing_revocation_data_still_embeds_chain(pki):
    # Only the signer's own response: the intermediate's status is unknown.
    embedding = prepare_embedding(pki.signing.asn1, online=False, extra_roots=[pki.root.asn1, pki.email_ca.asn1],
                                  known_ocsps=[ocsp_response(pki.signing, pki.email_ca)])
    assert embedding.context is None
    assert "revocation check failed" in embedding.note
    assert len(embedding.chain) == 2


def test_unknown_root(pki):
    embedding = prepare_embedding(pki.signing.asn1, online=False, known_ocsps=_good_ocsps(pki))
    assert embedding.chain == [] and embedding.context is None
    assert "no chain to a trusted root" in embedding.note


def test_signature_carries_chain_and_revocation_data(pki, plain_pdf, root_pem):
    embedding = prepare_embedding(pki.signing.asn1, online=False, extra_roots=[pki.root.asn1, pki.email_ca.asn1],
                                  known_ocsps=_good_ocsps(pki))
    signer = pki.signer()
    signer.cert_registry.register_multiple(embedding.chain)
    signed = sign(plain_pdf, signer, BOX, validation_context=embedding.context)

    (emb,) = open_reader(signed).embedded_signatures
    certs = [c.chosen for c in emb.signed_data["certificates"]]
    assert len({c.sha256 for c in certs}) == len(certs), "a certificate is embedded twice"
    assert {"SIGNALL TEST EMAIL CA-1", "Signall Test Root CA"} <= set(_names(certs))
    ocsps, crls = embedded_revocation_info(emb)
    assert len(ocsps) == 2 and crls == []

    (report,) = verify(signed, [pki.root.asn1])
    assert report.ok
    assert report.revocation == "good at signing time"


def test_signature_without_revocation_data(pki, plain_pdf):
    signed = sign(plain_pdf, pki.signer(), BOX)
    (report,) = verify(signed, [pki.root.asn1])
    assert report.ok and report.revocation == "not embedded"
