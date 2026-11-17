"""PKCS#11 tests against a SoftHSM token shaped like a CAC."""
import pytest

from signall.pdf import SignallError, open_reader
from signall.signing import SignRequest, sign
from signall.token import choose_signing_certificate, list_certificates, list_tokens, open_signer
from signall.verify import load_certificates, verify

from conftest import TOKEN_PIN


def test_lists_card(softhsm):
    (token,) = list_tokens(softhsm)
    assert token.label == "SIGNALL TEST CAC"
    certs = list_certificates(softhsm)
    assert len(certs) == 3


def test_picks_digital_signature_certificate(softhsm):
    chosen = choose_signing_certificate(list_certificates(softhsm))
    assert chosen.cert_id == b"\x02"
    assert chosen.issuer == "SIGNALL TEST EMAIL CA-1"


def test_signs_with_card(softhsm, plain_pdf, root_pem, pki):
    asked = []

    def pin(token, cert):
        asked.append(cert.subject)
        return TOKEN_PIN

    with open_signer(softhsm, pin, ca_chain=[pki.email_ca.asn1]) as signer:
        assert signer._context_pin == TOKEN_PIN  # the key wants the PIN again at signing time
        signed = sign(plain_pdf, signer, SignRequest(box=(0, (72, 72, 288, 108))))
    assert asked == ["DOE.JANE.Q.0000000001"]  # one prompt per signature
    (emb,) = open_reader(signed).embedded_signatures
    certs = [c.chosen.sha256 for c in emb.signed_data["certificates"]]
    assert len(certs) == len(set(certs)) == 2  # the signer once, plus its CA
    (report,) = verify(signed, load_certificates(root_pem))
    assert report.intact and report.trusted


def test_card_refuses_signature_without_fresh_pin(softhsm, plain_pdf):
    with open_signer(softhsm, lambda t, c: TOKEN_PIN) as signer:
        signer._context_pin = None
        with pytest.raises(Exception):
            sign(plain_pdf, signer, SignRequest(box=(0, (72, 72, 288, 108))))


def test_wrong_pin(softhsm):
    with pytest.raises(SignallError, match="incorrect PIN"):
        with open_signer(softhsm, lambda t, c: "000000"):
            pass
