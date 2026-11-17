"""signall doctor: probes against fake /sys and /proc trees, and the full run against SoftHSM."""
import http.server
import socket
import threading
from pathlib import Path

import pytest

from signall import doctor
from signall.cli import main
from signall.doctor import Environment, Status, find_usb_readers, pcscd_reachable, run_checks, scdaemon_state


def _usb_reader(sysfs: Path, name="3-4", bus=3, dev=15, product="SCR3500 A Contact Reader"):
    d = sysfs / name
    d.mkdir(parents=True)
    for key, value in dict(busnum=bus, devnum=dev, idVendor="04e6", idProduct="5814",
                           manufacturer="Identiv", product=product).items():
        (d / key).write_text(f"{value}\n")
    intf = sysfs / f"{name}:1.0"
    intf.mkdir()
    (intf / "bInterfaceClass").write_text("0b\n")
    return f"/dev/bus/usb/{bus:03d}/{dev:03d}"


def _process(proc: Path, pid: int, argv: list[str], opens: str | None = None, comm: str | None = None):
    d = proc / str(pid)
    (d / "fd").mkdir(parents=True)
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
    (d / "comm").write_text((comm or Path(argv[0]).name) + "\n")
    if opens:
        (d / "fd" / "41").symlink_to(opens)


@pytest.fixture
def env(tmp_path):
    (tmp_path / "sys").mkdir()
    (tmp_path / "proc").mkdir()
    (tmp_path / "gnupg").mkdir()
    return Environment(pcscd_socket=str(tmp_path / "pcscd.comm"), sysfs_usb=str(tmp_path / "sys"),
                       proc=str(tmp_path / "proc"), gnupg_home=str(tmp_path / "gnupg"))


def test_finds_reader_redirected_to_vm(env):
    device = _usb_reader(Path(env.sysfs_usb))
    other = Path(env.sysfs_usb) / "1-1:1.0"
    other.mkdir()
    (other / "bInterfaceClass").write_text("03\n")  # a keyboard
    _process(Path(env.proc), 100, ["/usr/sbin/pcscd", "--foreground"], opens=device)
    _process(Path(env.proc), 200, ["/usr/bin/python3", "/usr/bin/virt-manager"], opens=device, comm="virt-manager")

    (reader,) = find_usb_readers(env)
    assert reader.name == "Identiv SCR3500 A Contact Reader"
    assert reader.device == "/dev/bus/usb/003/015"
    assert reader.holders == ["virt-manager"]  # pcscd is expected and not reported
    assert reader.vm_program == "virt-manager"


def test_pcscd_down_and_reader_in_vm(env, tmp_path):
    device = _usb_reader(Path(env.sysfs_usb))
    _process(Path(env.proc), 200, ["/usr/bin/python3", "/usr/bin/virt-manager"], opens=device)
    module = tmp_path / "opensc-pkcs11.so"
    module.write_bytes(b"")  # never loaded: pcscd is checked first

    checks = {c.name: c for c in run_checks(str(module), online=False, env=env)}
    assert checks["pcscd"].status is Status.FAIL
    assert "systemctl enable --now pcscd.socket" in checks["pcscd"].fix
    assert checks["Card reader"].status is Status.FAIL
    assert "virtual machine" in checks["Card reader"].detail
    assert "Redirect USB device" in checks["Card reader"].fix
    assert checks["Card"].status is Status.SKIP
    assert checks["Revocation servers"].status is Status.SKIP


def test_no_module(env, monkeypatch):
    from signall import token
    from signall.pdf import SignallError

    def missing(_explicit=None):
        raise SignallError("no PKCS#11 module found")

    monkeypatch.setattr(token, "find_module", missing)
    checks = run_checks(online=False, env=env)
    assert checks[0].status is Status.FAIL
    assert [c.status for c in checks[1:6]] == [Status.SKIP] * 5


def test_pcscd_socket(tmp_path):
    path = str(tmp_path / "pcscd.comm")
    assert not pcscd_reachable(path)
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(path)  # the file exists, but nobody listens: a stopped pcscd.socket looks like this
    assert not pcscd_reachable(path)
    stale.close()
    Path(path).unlink()
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(path)
        server.listen()
        assert pcscd_reachable(path)


def test_scdaemon(env):
    assert scdaemon_state(env) == (False, False)
    _process(Path(env.proc), 300, ["scdaemon", "--multi-server"])
    assert scdaemon_state(env) == (True, False)
    (Path(env.gnupg_home) / "scdaemon.conf").write_text("# comment\npcsc-shared\n")
    assert scdaemon_state(env) == (True, True)


def test_url_reachable():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(405)  # any answer means the server is reachable
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert doctor.url_reachable(f"http://127.0.0.1:{server.server_port}/ocsp")
    finally:
        server.shutdown()
        server.server_close()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
    assert not doctor.url_reachable(f"http://127.0.0.1:{closed_port}/", timeout=2)


def test_doctor_with_token(softhsm, pki, env, monkeypatch, capsys):
    from signall import verify

    # The card holds no CA certificates, so the trust store has to supply the intermediate.
    monkeypatch.setattr(verify, "system_trust_roots", lambda: [pki.root.asn1, pki.email_ca.asn1])
    checks = {c.name: c for c in run_checks(softhsm, online=False, env=env)}
    assert "pcscd" not in checks  # SoftHSM doesn't use it
    for name in ("PKCS#11 module", "Card reader", "Card", "Signing certificate", "Trust", "GnuPG scdaemon"):
        assert checks[name].status is Status.OK, checks[name]
    assert "SIGNALL TEST EMAIL CA-1" in checks["Signing certificate"].detail
    assert "non_repudiation" in checks["Signing certificate"].detail
    assert checks["Trust"].detail == "chains to SIGNALL TEST EMAIL CA-1"

    monkeypatch.setattr(verify, "system_trust_roots", lambda: [pki.root.asn1])
    checks = {c.name: c for c in run_checks(softhsm, online=False, env=env)}
    assert checks["Trust"].status is Status.WARN  # no intermediate

    monkeypatch.setattr(verify, "system_trust_roots", lambda: [])
    checks = {c.name: c for c in run_checks(softhsm, online=False, env=env)}
    assert checks["Trust"].status is Status.WARN

    monkeypatch.setattr(doctor, "Environment", lambda: env)
    assert main(["doctor", "--module", softhsm, "--offline"]) == 0
    out = capsys.readouterr().out
    assert "DOE" not in out and "0000000001" not in out  # never print the cardholder's name or EDIPI
    assert "Ready to sign." in out
