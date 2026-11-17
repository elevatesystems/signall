"""The bundled DoD PKI certificates."""
import importlib.util
from pathlib import Path

from signall.trust import bundle_version, dod_intermediates, dod_roots
from signall.verify import trust_certificates


def _pinned_roots() -> dict[str, str]:
    script = Path(__file__).parent.parent / "scripts" / "update-dod-certs.py"
    spec = importlib.util.spec_from_file_location("update_dod_certs", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.PINNED_ROOTS


def test_roots_are_the_pinned_ones():
    found = {c.subject.native["common_name"]: c.sha256.hex() for c in dod_roots()}
    assert found == _pinned_roots()
    assert all(c.self_signed in ("yes", "maybe") for c in dod_roots())
    assert bundle_version().startswith("v")


def test_intermediates_chain_to_bundled_certificates():
    subjects = {c.subject.dump() for c in (*dod_roots(), *dod_intermediates())}
    assert dod_intermediates()
    for cert in dod_intermediates():
        assert cert.self_signed == "no"
        assert cert.issuer.dump() in subjects, cert.subject.native["common_name"]


def test_trust_certificates_include_bundle_once(monkeypatch):
    from signall import verify

    root = dod_roots()[0]
    monkeypatch.setattr(verify, "system_trust_roots", lambda: [root])  # also in the system store
    certs = trust_certificates([root])
    assert len(certs) == len(dod_roots()) + len(dod_intermediates())
