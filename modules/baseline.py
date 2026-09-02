"""Snapshot current network identity so we can prove a delta and restore it."""
from __future__ import annotations

import socket
import urllib.request
from pathlib import Path
from typing import Any

from . import ipv6
from .util import baseline_save, is_dry_run, log, sh

# Generic UA so probes from this tool don't fingerprint the toolkit at the
# destination (the prior "ghost/0.1" was an easy correlation tag).
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"


def _read_mac(iface: str) -> str | None:
    p = Path(f"/sys/class/net/{iface}/address")
    return p.read_text().strip() if p.exists() else None


def _public_ip(timeout: int = 4) -> str | None:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode().strip()
        except Exception:
            continue
    return None


def _dns_servers() -> list[str]:
    p = Path("/etc/resolv.conf")
    if not p.exists():
        return []
    return [ln.split()[1] for ln in p.read_text().splitlines()
            if ln.startswith("nameserver") and len(ln.split()) > 1]


def _ipv6_enabled() -> bool:
    """IPv6 counts as 'enabled' if ANY knob (all/default/lo or any interface)
    is not disabled — so `status` reflects a per-interface re-enable, not just
    the global all/default knobs."""
    return not ipv6.fully_disabled()


def current_snapshot(iface: str = "wlan0", probe_public_ip: bool = True) -> dict[str, Any]:
    """Snapshot current network identity.

    `probe_public_ip=False` skips the 3 outbound HTTPS GETs (ipify/ifconfig/
    icanhazip), which is useful for `status` calls when the operator already
    knows the baseline IP and doesn't want to leak the probes to those
    services. Defaults True so `capture()` always records the real IP.
    """
    return {
        "iface": iface,
        "mac": _read_mac(iface),
        "hostname": socket.gethostname(),
        "dns": _dns_servers(),
        "ipv6_enabled": _ipv6_enabled(),
        "public_ip": _public_ip() if probe_public_ip else "(not probed)",
        "default_route": _default_route(),
    }


def _default_route() -> str | None:
    cp = sh("ip route show default", check=False)
    return cp.stdout.strip() if cp.returncode == 0 else None


def capture(iface: str = "wlan0") -> dict[str, Any]:
    # The public-IP probe is real HTTPS egress via urllib (not sh()), so under
    # --dry-run it must be skipped — a "preview" shouldn't phone home to three
    # IP-echo services from your real address.
    snap = current_snapshot(iface, probe_public_ip=not is_dry_run())
    baseline_save(snap)
    log(f"baseline captured: MAC={snap['mac']} host={snap['hostname']} "
        f"public_ip={snap['public_ip']}", "ok")
    return snap
