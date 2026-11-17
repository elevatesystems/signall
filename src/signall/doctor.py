"""Diagnose the smart card stack: ``signall doctor``.

Each check reports ok, warn, fail, or skip, and says how to fix a problem.
The checks follow the stack from the bottom up (PKCS#11 module, pcscd, reader,
card, certificate, trust, conflicting software, network), and a check is
skipped when one it depends on has failed.

The output never includes the cardholder's name or EDIPI, so users can paste
it into a bug report.
"""
from __future__ import annotations

import asyncio
import datetime
import enum
import os
import re
import socket
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from signall import __version__
from signall.pdf import SignallError

PCSCD_SOCKET = "/run/pcscd/pcscd.comm"
DEFAULT_REVOCATION_URLS = ("http://ocsp.disa.mil", "http://crl.disa.mil")
EXPIRY_WARNING_DAYS = 30
NETWORK_TIMEOUT_SECONDS = 8

# Programs that take a USB reader away from the host to pass it to a virtual machine.
VM_PROGRAMS = {
    "virt-manager": "virt-manager", "virt-viewer": "virt-viewer", "remote-viewer": "remote-viewer",
    "gnome-boxes": "GNOME Boxes", "spicy": "spicy", "VirtualBox": "VirtualBox",
    "VirtualBoxVM": "VirtualBox", "VBoxHeadless": "VirtualBox", "vmware-vmx": "VMware",
}
VM_FIX = {
    "virt-manager": "In virt-manager, open Virtual Machine > Redirect USB device and untick the reader, "
                    "or shut down the virtual machine.",
    "GNOME Boxes": "In GNOME Boxes, open the machine's Preferences > Devices & Shares and turn off the reader, "
                   "or shut down the virtual machine.",
}


class Status(enum.Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "FAIL"
    SKIP = "skip"


@dataclass
class Check:
    name: str
    status: Status
    detail: str
    fix: str | None = None


@dataclass
class UsbReader:
    name: str
    vendor_id: str
    product_id: str
    device: str                                    # /dev/bus/usb/BBB/DDD
    holders: list[str] = field(default_factory=list)  # programs other than pcscd that have it open

    @property
    def vm_program(self) -> str | None:
        for holder in self.holders:
            if holder in VM_PROGRAMS:
                return VM_PROGRAMS[holder]
            if holder.startswith("qemu-system"):
                return "QEMU"
        return None


@dataclass
class Environment:
    """Where to look; tests point these at fake trees."""
    pcscd_socket: str = PCSCD_SOCKET
    sysfs_usb: str = "/sys/bus/usb/devices"
    proc: str = "/proc"
    gnupg_home: str = field(default_factory=lambda: os.environ.get("GNUPGHOME") or str(Path.home() / ".gnupg"))
    now: datetime.datetime | None = None


# --- probes ---------------------------------------------------------------------------------

def pcscd_reachable(path: str) -> bool:
    """True when something accepts connections on the pcscd socket (socket activation counts)."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        try:
            s.connect(path)
        except OSError:
            return False
    return True


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return ""


def _program_name(proc: Path, pid: str) -> str:
    """The program behind a process; looks past the interpreter for Python scripts."""
    try:
        argv = (proc / pid / "cmdline").read_bytes().split(b"\0")
    except OSError:
        argv = []
    argv = [a.decode(errors="replace") for a in argv if a]
    if argv:
        first = Path(argv[0]).name
        if first.startswith("python") and len(argv) > 1 and not argv[1].startswith("-"):
            return Path(argv[1]).name
        return first
    return _read(proc / pid / "comm")


def _device_holders(proc: Path, device: str) -> list[str]:
    holders = []
    for pid_dir in proc.glob("[0-9]*"):
        fd_dir = pid_dir / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except OSError:
            continue  # another user's process, or it exited
        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if target == device:
                name = _program_name(proc, pid_dir.name)
                if name != "pcscd" and name not in holders:
                    holders.append(name)
                break
    return holders


def find_usb_readers(env: Environment) -> list[UsbReader]:
    """USB devices with a smart card (CCID, class 0x0b) interface, and who has them open."""
    root = Path(env.sysfs_usb)
    readers: dict[str, UsbReader] = {}
    for intf in sorted(root.glob("*:*")):
        if _read(intf / "bInterfaceClass").lower() != "0b":
            continue
        dev = root / intf.name.split(":")[0]
        if dev.name in readers:
            continue
        try:
            bus, num = int(_read(dev / "busnum")), int(_read(dev / "devnum"))
        except ValueError:
            continue
        device = f"/dev/bus/usb/{bus:03d}/{num:03d}"
        name = " ".join(x for x in (_read(dev / "manufacturer"), _read(dev / "product")) if x) or "USB smart card reader"
        readers[dev.name] = UsbReader(
            name=name, vendor_id=_read(dev / "idVendor"), product_id=_read(dev / "idProduct"),
            device=device, holders=_device_holders(Path(env.proc), device),
        )
    return list(readers.values())


def scdaemon_state(env: Environment) -> tuple[bool, bool]:
    """(running, shares the reader) for GnuPG's scdaemon."""
    running = any(_read(p / "comm") == "scdaemon" for p in Path(env.proc).glob("[0-9]*"))
    conf = Path(env.gnupg_home) / "scdaemon.conf"
    shared = any(line.strip() == "pcsc-shared" for line in _read(conf).splitlines())
    return running, shared


def url_reachable(url: str, timeout: float = NETWORK_TIMEOUT_SECONDS) -> bool:
    """True if the server answers an HTTP HEAD request at all (any status code counts)."""
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": f"signall/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout):
            return True
    except urllib.error.HTTPError:
        return True
    except (urllib.error.URLError, OSError, ValueError):
        return False


# --- checks ---------------------------------------------------------------------------------

def _trust_check(cert, env: Environment) -> Check:
    from pyhanko_certvalidator import CertificateValidator
    from pyhanko_certvalidator.errors import PathBuildingError, PathValidationError

    from signall.chain import validation_context

    issuer = cert.issuer.native.get("common_name", "its issuer")
    context = validation_context(fetch=False, require_revocation=False, moment=env.now)
    validator = CertificateValidator(cert, validation_context=context)
    install = ("Signall bundles the DoD root and intermediate CAs; for other certificates, add the root CA to "
               "the system trust store (copy it to /etc/pki/ca-trust/source/anchors/, then run "
               "`sudo update-ca-trust`). For DoD CAs newer than Signall's bundle, update Signall.")
    try:
        path = asyncio.run(validator.async_validate_usage(set()))
    except PathBuildingError:
        return Check("Trust", Status.WARN,
                     f"no chain from {issuer} to a trusted root; `signall verify` will call your signatures "
                     "untrusted, and no revocation data can be embedded", install)
    except PathValidationError as exc:
        return Check("Trust", Status.WARN, f"the chain to a trusted root is not valid: {exc}", install)
    anchor = path.trust_anchor.authority.name.native.get("common_name", "a trusted root")
    return Check("Trust", Status.OK, f"chains to {anchor}")


def _network_check(urls: list[str]) -> Check:
    hosts = {}
    for url in urls:
        parts = urlsplit(url)
        if parts.scheme in ("http", "https") and parts.hostname:
            hosts.setdefault(parts.hostname, url)
    if not hosts:
        hosts = {urlsplit(u).hostname: u for u in DEFAULT_REVOCATION_URLS}
    with ThreadPoolExecutor(max_workers=len(hosts)) as pool:
        results = dict(zip(hosts, pool.map(url_reachable, hosts.values())))
    up = [h for h, ok in results.items() if ok]
    down = [h for h, ok in results.items() if not ok]
    if not down:
        return Check("Revocation servers", Status.OK, f"{', '.join(up)} reachable")
    return Check("Revocation servers", Status.WARN,
                 f"can't reach {', '.join(down)}" + (f" ({', '.join(up)} reachable)" if up else ""),
                 "Signing works offline, but revocation checks need these servers. DoD servers often refuse "
                 "connections from outside the US and from some networks; try another network or a VPN.")


def _reader_without_pcscd(usb: list[UsbReader]) -> Check:
    if not usb:
        return Check("Card reader", Status.FAIL, "no USB smart card reader is connected",
                     "Plug in the card reader.")
    return _usb_reader_problem(usb) or Check(
        "Card reader", Status.SKIP, f"{usb[0].name} is connected; pcscd has to be running to use it")


def _usb_reader_problem(usb: list[UsbReader]) -> Check | None:
    for reader in usb:
        vm = reader.vm_program
        if vm:
            return Check("Card reader", Status.FAIL,
                         f"{reader.name} is passed through to a virtual machine ({vm} has it)",
                         VM_FIX.get(vm, f"Stop USB redirection of the reader in {vm}, or shut down the "
                                        "virtual machine."))
        if reader.holders:
            return Check("Card reader", Status.FAIL,
                         f"{reader.name} is held by another program ({', '.join(reader.holders)})",
                         "Close that program, then unplug and replug the reader.")
    return None


def run_checks(module: str | None = None, online: bool = True, env: Environment | None = None) -> list[Check]:
    from signall.token import choose_signing_certificate, find_module

    env = env or Environment()
    checks: list[Check] = []

    try:
        module_path = find_module(module)
    except SignallError as exc:
        return [Check("PKCS#11 module", Status.FAIL, str(exc), "sudo dnf install opensc p11-kit"),
                *_skipped(("pcscd", "Card reader", "Card", "Signing certificate", "Trust"), "a PKCS#11 module"),
                *_late_checks(env, online, [])]
    checks.append(Check("PKCS#11 module", Status.OK, module_path))

    uses_pcscd = "softhsm" not in Path(module_path).name.lower()
    if uses_pcscd:
        if pcscd_reachable(env.pcscd_socket):
            checks.append(Check("pcscd", Status.OK, "running"))
        else:
            checks.append(Check("pcscd", Status.FAIL, "not running",
                                "sudo dnf install pcsc-lite pcsc-lite-ccid && sudo systemctl enable --now pcscd.socket"))
            checks.append(_reader_without_pcscd(find_usb_readers(env)))
            return checks + _skipped(("Card", "Signing certificate", "Trust"), "pcscd") + _late_checks(env, online, [])

    try:
        import pkcs11
        from pkcs11 import SlotFlag, TokenFlag

        lib = pkcs11.lib(module_path)
        slots = list(lib.get_slots(token_present=False))
    except Exception as exc:  # noqa: BLE001 - any loader failure is worth reporting as is
        checks.append(Check("Card reader", Status.FAIL, f"the PKCS#11 module failed to load: {exc}",
                            "Reinstall it: sudo dnf reinstall opensc p11-kit"))
        return checks + _skipped(("Card", "Signing certificate", "Trust"), "the PKCS#11 module") + \
            _late_checks(env, online, [])

    if not slots:
        usb = find_usb_readers(env) if uses_pcscd else []
        problem = _usb_reader_problem(usb)
        if problem is None and usb:
            problem = Check("Card reader", Status.FAIL, f"{usb[0].name} is connected but pcscd can't see it",
                            "Check that pcsc-lite-ccid is installed (sudo dnf install pcsc-lite-ccid), "
                            "then unplug and replug the reader.")
        checks.append(problem or Check("Card reader", Status.FAIL, "no card reader found",
                                       "Plug in the card reader."))
        return checks + _skipped(("Card", "Signing certificate", "Trust"), "a card reader") + \
            _late_checks(env, online, [])
    # Readers append a serial in parentheses, which PKCS#11's 64-character limit cuts off.
    names = [re.sub(r"\s*\(.*$", "", s.slot_description.strip()) or s.slot_description.strip() for s in slots]
    checks.append(Check("Card reader", Status.OK, "; ".join(names)))

    present = [s for s in slots if s.flags & SlotFlag.TOKEN_PRESENT]
    tokens = []
    for slot in present:
        try:
            token = slot.get_token()
        except pkcs11.exceptions.PKCS11Error:
            continue
        if token.flags & TokenFlag.TOKEN_INITIALIZED:
            tokens.append(token)
    if not tokens:
        checks.append(Check("Card", Status.FAIL, "no card in the reader, or the card can't be read",
                            "Insert the card fully, chip first. If it is already in, take it out and put it "
                            "back; a dirty or worn chip can make the card unreadable."))
        return checks + _skipped(("Signing certificate", "Trust"), "a card") + _late_checks(env, online, [])
    if len(tokens) > 1:
        checks.append(Check("Card", Status.WARN, f"{len(tokens)} cards or tokens are present",
                            "Remove the cards you don't want to sign with; Signall refuses to guess."))
        return checks + _skipped(("Signing certificate", "Trust"), "a single card") + _late_checks(env, online, [])
    token = tokens[0]
    checks.append(Check("Card", Status.OK, f"present ({token.manufacturer_id.strip()} {token.model.strip()})"))

    from signall.token import list_certificates

    try:
        certs = list_certificates(module_path)
        chosen = choose_signing_certificate(certs, env.now)
    except SignallError as exc:
        checks.append(Check("Signing certificate", Status.FAIL, str(exc),
                            "Get new certificates at a RAPIDS ID card office (or through the self-service "
                            "certificate update, if your site offers it)."))
        return checks + _skipped(("Trust",), "a signing certificate") + _late_checks(env, online, [])

    now = env.now or datetime.datetime.now(datetime.timezone.utc)
    days_left = (chosen.not_after - now).days
    detail = (f"{chosen.label}; issuer {chosen.issuer}; {', '.join(sorted(chosen.key_usage))}; "
              f"expires {chosen.not_after:%Y-%m-%d}")
    if days_left < EXPIRY_WARNING_DAYS:
        checks.append(Check("Signing certificate", Status.WARN, f"{detail} ({days_left} days left)",
                            "Renew your certificates at a RAPIDS ID card office before they expire."))
    else:
        checks.append(Check("Signing certificate", Status.OK, detail))
    checks.append(_trust_check(chosen.certificate, env))

    cert = chosen.certificate
    urls = list(cert.ocsp_urls) + [u for dp in (cert.crl_distribution_points or []) if (u := dp.url)]
    return checks + _late_checks(env, online, urls)


def _skipped(names, needs: str) -> list[Check]:
    return [Check(name, Status.SKIP, f"needs {needs}") for name in names]


def _late_checks(env: Environment, online: bool, urls: list[str]) -> list[Check]:
    """Checks that don't depend on the card: conflicting software and the network."""
    out = []
    running, shared = scdaemon_state(env)
    if not running:
        out.append(Check("GnuPG scdaemon", Status.OK, "not running"))
    elif shared:
        out.append(Check("GnuPG scdaemon", Status.OK, "running, with pcsc-shared"))
    else:
        out.append(Check("GnuPG scdaemon", Status.WARN, "running; it can take the reader for itself",
                         f"Run `gpgconf --kill scdaemon`, or add the line `pcsc-shared` to "
                         f"{Path(env.gnupg_home) / 'scdaemon.conf'}."))
    if online:
        out.append(_network_check(urls))
    else:
        out.append(Check("Revocation servers", Status.SKIP, "not checked (--offline)"))
    return out
