import json

from signall.cli import main


def test_inspect_json(dd2875, tmp_path, capsys):
    path = tmp_path / "form.pdf"
    path.write_bytes(dd2875)
    assert main(["inspect", "--json", str(path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["kind"] == "dynamic-xfa"
    assert len(out["xfa_signature_fields"]) == 7


def test_sign_and_verify_with_p12(pki, root_pem, plain_pdf, tmp_path, capsys):
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12

    p12 = tmp_path / "id.p12"
    p12.write_bytes(pkcs12.serialize_key_and_certificates(
        b"test", pki.signing.key, pki.signing.cert, [pki.email_ca.cert], BestAvailableEncryption(b"pass")))
    secret = tmp_path / "pass"
    secret.write_text("pass")
    src = tmp_path / "cert.pdf"
    src.write_bytes(plain_pdf)

    assert main(["sign", str(src), "--p12", str(p12), "--pin-file", str(secret), "--box", "1:72,72,288,108",
                 "--offline", "--trust", str(root_pem)]) == 0
    assert "no revocation data embedded: offline" in capsys.readouterr().err
    out = tmp_path / "cert - signed.pdf"
    assert out.is_file()
    assert main(["verify", str(out), "--trust", str(root_pem)]) == 0
    assert "VALID" in capsys.readouterr().out
    assert main(["sign", str(src), "--p12", str(p12), "--pin-file", str(secret), "--box", "1:72,72,288,108"]) == 2
