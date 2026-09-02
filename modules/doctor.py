"""snow doctor — pre-flight diagnostics.

Read-only checks that should pass before `engage` arms the kill-switch. The
single most common failure mode for a Tor-transproxy tool is "you ran engage
with a broken environment and now you can't reach anything to debug it" —
doctor surfaces every catchable cause before that happens.

Exit code: 0 if all checks ok-or-warn, 1 if any check fails.
"""
from __future__ import annotations

import os
import platform
import pwd
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Callable

from .util import color

Status = str  # "ok" | "warn" | "fail"
CheckFn = Callable[[], tuple[Status, str]]


def _check_cmd(name: str, hint: str = "") -> tuple[Status, str]:
    p = shutil.which(name)
    if p:
        return "ok", p
    return "fail", "not found on PATH" + (f" (hint: {hint})" if hint else "")


def _check_cmd_warn(name: str, hint: str = "") -> tuple[Status, str]:
    """Same as _check_cmd but missing == warn (for optional deps)."""
    p = shutil.which(name)
    if p:
        return "ok", p
    return "warn", "not found on PATH" + (f" ({hint})" if hint else "")


def _check_kernel() -> tuple[Status, str]:
    sysname = platform.system()
    return ("ok" if sysname == "Linux" else "fail", f"{sysname} {platform.release()}")


def _check_distro() -> tuple[Status, str]:
    osr = Path("/etc/os-release")
    if not osr.exists():
        return "warn", "/etc/os-release missing"
    pretty = ""
    for line in osr.read_text().splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty = line.split("=", 1)[1].strip().strip('"')
            break
    if "kali" in pretty.lower() or "debian" in pretty.lower():
        return "ok", pretty
    return "warn", pretty + " (tested on Kali/Debian; YMMV)"


def _check_root() -> tuple[Status, str]:
    if os.geteuid() == 0:
        return "ok", "uid=0"
    return "warn", f"uid={os.geteuid()} (sudo required for engage)"


def _check_debian_tor_user() -> tuple[Status, str]:
    try:
        u = pwd.getpwnam("debian-tor")
        return "ok", f"uid={u.pw_uid}"
    except KeyError:
        # Downgraded to warn so doctor passes when operator uses --upstream wg.
        # For Tor upstream, the deps.tor check still fails-fast on missing tor.
        return "warn", "debian-tor user not found — only relevant for Tor upstream"


def _check_run_tor_dir() -> tuple[Status, str]:
    p = Path("/run/tor")
    if not p.exists():
        return "warn", "/run/tor missing — only relevant for Tor upstream (rerun install.sh)"
    st = p.stat()
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    if owner != "debian-tor":
        return "warn", f"/run/tor owned by {owner}, expected debian-tor"
    return "ok", f"owner={owner} mode={oct(st.st_mode)[-3:]}"


def _check_default_iface() -> tuple[Status, str]:
    cp = subprocess.run(["ip", "route", "show", "default"],
                        capture_output=True, text=True, check=False)
    if cp.returncode != 0 or not cp.stdout.strip():
        return "fail", "no default route — host is offline"
    parts = cp.stdout.split()
    try:
        return "ok", parts[parts.index("dev") + 1]
    except (ValueError, IndexError):
        return "warn", "default route exists but no `dev` token parsed"


def _check_dns_resolve() -> tuple[Status, str]:
    try:
        socket.gethostbyname("example.com")
        return "ok", "example.com resolved"
    except OSError as e:
        return "fail", f"resolver dead: {e}"


def _check_avahi_on_dnsport() -> tuple[Status, str]:
    cp = subprocess.run(["systemctl", "is-active", "avahi-daemon"],
                        capture_output=True, text=True, check=False)
    if cp.returncode == 0 and cp.stdout.strip() == "active":
        return "fail", ("avahi-daemon is active and binds UDP 5353 — Tor DNSPort will clash. "
                       "Fix: systemctl disable --now avahi-daemon")
    return "ok", "avahi not on 5353"


def _check_one_port(port: int, label: str) -> tuple[Status, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return "ok", f"{port}/tcp free ({label})"
    except OSError:
        return "warn", f"{port}/tcp already in use ({label}) — stop the holder before engage"
    finally:
        s.close()


def _check_ports() -> tuple[Status, str]:
    out: list[str] = []
    worst = "ok"
    for p, label in [(9050, "SOCKS"), (5353, "DNSPort"), (9040, "TransPort"), (9051, "ControlPort")]:
        st, _ = _check_one_port(p, label)
        out.append(f"{p}={st}")
        if st == "fail":
            worst = "fail"
        elif st == "warn" and worst != "fail":
            worst = "warn"
    return worst, " ".join(out)


def _check_time_sync() -> tuple[Status, str]:
    """Tor refuses to bootstrap if the clock is significantly off."""
    cp = subprocess.run(["timedatectl", "show", "--property=NTPSynchronized"],
                        capture_output=True, text=True, check=False)
    if cp.returncode != 0:
        return "warn", "timedatectl not available"
    val = cp.stdout.strip().split("=", 1)[-1]
    if val == "yes":
        return "ok", "NTP synchronized"
    return "warn", "NTP not synchronized (Tor may refuse to bootstrap)"


def _check_nm_management(iface: str | None) -> tuple[Status, str]:
    if not shutil.which("nmcli"):
        return "ok", "NetworkManager not installed — no fight"
    if not iface:
        return "warn", "iface unknown; skipping NM-management check"
    cp = subprocess.run(["nmcli", "-t", "-f", "GENERAL.NM-MANAGED", "dev", "show", iface],
                        capture_output=True, text=True, check=False)
    if cp.returncode != 0:
        return "warn", f"nmcli could not query {iface}"
    if "yes" in cp.stdout.lower():
        return "warn", (f"{iface} is NM-managed — MAC randomize may be reverted; "
                        "prefer NM's wifi.mac-address=random")
    return "ok", f"{iface} not NM-managed"


def _check_module(name: str) -> tuple[Status, str]:
    mods = Path("/proc/modules")
    if not mods.exists():
        return "warn", "/proc/modules absent"
    for line in mods.read_text().splitlines():
        if line.split()[0] == name:
            return "ok", f"{name} loaded"
    cp = subprocess.run(["modprobe", "-n", name], capture_output=True, text=True, check=False)
    if cp.returncode == 0:
        return "warn", f"{name} not loaded but available (modprobe -n ok)"
    return "fail", f"{name} not available"


def _check_ipv6_kernel() -> tuple[Status, str]:
    p = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
    if not p.exists():
        return "warn", "IPv6 sysctl knobs absent — IPv6 kill no-op"
    return "ok", f"ipv6 kill toggle present (current={p.read_text().strip()})"


def _resolve_iface() -> str | None:
    cp = subprocess.run(["ip", "route", "show", "default"],
                        capture_output=True, text=True, check=False)
    if cp.returncode != 0 or "dev" not in cp.stdout:
        return None
    parts = cp.stdout.split()
    try:
        return parts[parts.index("dev") + 1]
    except (ValueError, IndexError):
        return None


def collect(iface: str | None = None) -> list[dict]:
    """Run every check, return list of {name, status, detail, elapsed_ms}."""
    iface_resolved = iface or _resolve_iface()

    plan: list[tuple[str, CheckFn]] = [
        ("kernel",          _check_kernel),
        ("distro",          _check_distro),
        ("user.root",       _check_root),
        ("deps.tor",        lambda: _check_cmd("tor",        "apt install tor")),
        ("deps.wg",         lambda: _check_cmd_warn("wg",       "apt install wireguard-tools  # only if using --upstream wg")),
        ("deps.wg_quick",   lambda: _check_cmd_warn("wg-quick", "apt install wireguard-tools  # only if using --upstream wg")),
        ("deps.macchanger", lambda: _check_cmd("macchanger", "apt install macchanger")),
        ("deps.iptables",   lambda: _check_cmd("iptables",   "apt install iptables")),
        ("deps.dig",        lambda: _check_cmd("dig",        "apt install dnsutils")),
        ("deps.conntrack",  lambda: _check_cmd("conntrack",  "apt install conntrack")),
        ("deps.curl",       lambda: _check_cmd("curl",       "apt install curl")),
        ("deps.jq",         lambda: _check_cmd("jq",         "apt install jq")),
        ("deps.runuser",    lambda: _check_cmd("runuser",    "apt install util-linux")),
        ("user.debian_tor", _check_debian_tor_user),
        ("dir.run_tor",     _check_run_tor_dir),
        ("net.iface",       _check_default_iface),
        ("net.dns",         _check_dns_resolve),
        ("ports.bind",      _check_ports),
        ("ports.avahi",     _check_avahi_on_dnsport),
        ("time.sync",       _check_time_sync),
        ("nm.management",   lambda: _check_nm_management(iface_resolved)),
        ("kernel.modules.nf_conntrack", lambda: _check_module("nf_conntrack")),
        ("ipv6.kernel",     _check_ipv6_kernel),
    ]

    results: list[dict] = []
    for name, fn in plan:
        t0 = time.time()
        try:
            status, detail = fn()
        except Exception as e:
            status, detail = "fail", f"check raised: {type(e).__name__}: {e}"
        results.append({
            "name": name, "status": status, "detail": detail,
            "elapsed_ms": int((time.time() - t0) * 1000),
        })
    return results


def render(results: list[dict]) -> None:
    SYMBOL = {"ok": ("OK ", "green"), "warn": ("!! ", "yellow"), "fail": ("XX ", "red")}
    longest = max((len(r["name"]) for r in results), default=0)
    for r in results:
        sym, c = SYMBOL.get(r["status"], ("?? ", "yellow"))
        print(f"  {color(sym, c)} {r['name']:<{longest}}  {r['detail']}")
    counts = {"ok": 0, "warn": 0, "fail": 0}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print()
    print(f"  summary: {color(str(counts['ok']) + ' ok', 'green')}, "
          f"{color(str(counts['warn']) + ' warn', 'yellow')}, "
          f"{color(str(counts['fail']) + ' fail', 'red')}")


def is_clean(results: list[dict]) -> bool:
    """True iff no FAIL entries. Warns are tolerated."""
    return not any(r["status"] == "fail" for r in results)


def run(iface: str | None = None) -> int:
    """Top-level entrypoint for `snow doctor`. Returns exit code."""
    results = collect(iface=iface)
    render(results)
    return 0 if is_clean(results) else 1
