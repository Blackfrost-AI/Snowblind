"""Leak tests: public IP via Tor, DNS leak, IPv6 leak, non-DNS UDP leak,
killswitch effectiveness."""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import ipv6
from .util import baseline_load, color, is_dry_run, journal_load, log, sh
from .tor import SOCKS_PORT

# Generic UA so the leaktest's own probes don't fingerprint the toolkit at
# the destination (api.ipify, check.torproject, etc.).
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"

# Well-known NTP servers (stable anycast IPs) for the UDP-leak probe. Used as
# raw IPs so the probe never depends on DNS being in any particular state.
_NTP_PROBE_IPS = ("162.159.200.123", "216.239.35.0")  # Cloudflare, Google


class LeakResult:
    """Structured outcome of a leak test.

    `hard_leak` is the security-critical signal: True means the operator's
    real identity is exposed right now. Callers gate on it — notably
    `engage`, which must not report success or auto-launch the browser when
    hard_leak is True.
    """

    def __init__(self) -> None:
        self.clearnet_leak = False     # clearnet reachable AND it is the baseline IP
        self.dns_leak = False          # DNS resolver observed == baseline IP
        self.ipv6_leak = False         # IPv6 stack still enabled
        self.udp_leak = False          # non-DNS UDP escaped the kill-switch
        self.tor_confirmed = False     # tor exit reachable and IsTor=true
        self.checked_clearnet = False  # False in quick mode (clearnet check skipped)
        self.clearnet_unverified = False  # clearnet probe answered but baseline IP unknown

    @property
    def hard_leak(self) -> bool:
        """Any condition meaning the real identity is exposed right now."""
        return (self.clearnet_leak or self.dns_leak
                or self.ipv6_leak or self.udp_leak)


def _socks_host() -> str:
    """Address of the Tor SOCKS port for the current network context.

    In the host netns (default persona) Tor binds 127.0.0.1. Inside a named
    persona's netns, 127.0.0.1 is the netns's own loopback — Tor is reached
    on the persona's gateway IP instead (modules/tor.py binds the per-persona
    gateway in write_config). A leak test invoked inside the netns
    (`ip netns exec ... snow --persona X leaktest`) must target the gateway,
    or it would always report Tor UNREACHABLE.
    """
    persona = os.environ.get("SNOW_PERSONA", "default")
    if persona == "default":
        return "127.0.0.1"
    try:
        from . import netns
        return netns.subnet_for(persona)["host_ip"]
    except Exception:
        return "127.0.0.1"


def _engaged_upstream() -> str:
    """Best-effort: which upstream is currently engaged, read from the journal.

    Returns 'tor', 'wireguard', 'chain', or 'unknown'. Lets `run()` skip the
    Tor-specific SOCKS check for a WireGuard engage — there is no SOCKS port
    for WG, and running the check would print a misleading red failure.
    """
    for e in reversed(journal_load()):
        if e.get("module") == "upstream" and e.get("subtype"):
            return str(e["subtype"])
        if e.get("module") == "killswitch" and e.get("action") == "apply":
            up = str(e.get("upstream", "")).lower()
            if "wireguard" in up or up.startswith("wg"):
                return "wireguard"
            if "chain" in up:
                return "chain"
            if "tor" in up:
                return "tor"
    return "unknown"


def _http_get(url: str, via_tor: bool, timeout: int = 8, retries: int = 1) -> str | None:
    """GET `url`, return body or None.

    `retries`: number of attempts. The via_tor path benefits from retries
    because tor's first exit circuit takes 10-60s to build *after* bootstrap
    reaches 100%. Without retries the leaktest fires before a circuit exists
    and falsely reports `UNREACHABLE via SOCKS` / `no DNS answer`.
    """
    for attempt in range(retries):
        body = _http_get_once(url, via_tor=via_tor, timeout=timeout)
        if body is not None:
            return body
        if attempt < retries - 1:
            time.sleep(min(5 + attempt * 3, 12))
    return None


def _http_get_once(url: str, via_tor: bool, timeout: int) -> str | None:
    if via_tor:
        # fall back to system curl with SOCKS5h (pysocks isn't a hard dep).
        # SOCKS host is gateway-aware so this works inside a persona netns too.
        cp = sh(f"curl -s -A '{USER_AGENT}' --max-time {timeout} "
                f"--socks5-hostname {_socks_host()}:{SOCKS_PORT} {url}", check=False)
        return cp.stdout.strip() if cp.returncode == 0 and cp.stdout.strip() else None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode().strip()
    except (urllib.error.URLError, socket.timeout, OSError):
        return None


def _check_tor_exit() -> dict:
    """https://check.torproject.org returns IsTor JSON when polled via SOCKS.
    Retries up to 4x to give the first exit circuit time to build."""
    body = _http_get("https://check.torproject.org/api/ip", via_tor=True, retries=4)
    if not body:
        return {"reachable": False}
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"reachable": True, "raw": body[:120]}


def _check_clearnet_egress() -> str | None:
    """Direct (no-Tor) HTTPS to an IP-echo service. If the killswitch is armed,
    this should return None (blocked). A real response means the killswitch is
    leaking — either OUTPUT policy isn't DROP, or there's a wide bypass rule."""
    return _http_get("https://api.ipify.org", via_tor=False)


def _check_ipv6() -> bool:
    """True if IPv6 is disabled on every knob — all/default/lo AND each
    interface. Delegates to ipv6.fully_disabled so a per-interface re-enable
    (NetworkManager flips these back on reconnect) is caught, not just the
    global knobs."""
    return ipv6.fully_disabled()


def _check_udp_leak() -> bool:
    """Probe whether non-DNS UDP can escape the kill-switch.

    Sends an NTP query (UDP/123) to well-known external NTP servers. Tor does
    not carry arbitrary UDP, and the transproxy only REDIRECTs DNS — so a
    successful NTP *response* means a non-DNS UDP datagram reached the
    Internet and came back: it bypassed the kill-switch with the real IP.
    This is the same vector that QUIC (HTTP/3) and WebRTC STUN ride. Returns
    True on a leak (a reply was received), False if every probe was dropped.
    """
    # 48-byte NTP v3 client request; first byte 0x1B = LI 0, VN 3, Mode 3.
    pkt = b"\x1b" + b"\0" * 47
    for ip in _NTP_PROBE_IPS:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(4)
            s.sendto(pkt, (ip, 123))
            data, _addr = s.recvfrom(64)
            if len(data) >= 48:
                return True
        except (socket.timeout, OSError):
            continue
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
    return False


def _check_dns_leak() -> tuple[str, str | None]:
    """Query a DNS-based whoami service via the system resolver.

    `dig @1.0.0.1 whoami.cloudflare TXT` sends UDP/53 to 1.0.0.1. When transproxy
    is armed, our NAT chain REDIRECTs UDP/53 to Tor's DNSPort; Tor resolves
    over a circuit, so the resolver IP Cloudflare reports = a Tor exit. If
    the response equals our baseline public IP, DNS is bypassing Tor.

    Returns (status, observed_ip) where status ∈
        ok       — observed != baseline (egressing via Tor or other proxy)
        leak     — observed == baseline (DNS is still hitting clearnet)
        blocked  — query produced no answer (killswitch ate it; no leak)
        unknown  — could not determine
    """
    cp = sh(["dig", "+short", "+time=4", "+tries=2",
             "whoami.cloudflare", "TXT", "@1.0.0.1"],
            check=False, timeout=15)
    # +short prints one line per TXT string; whoami.cloudflare can return the
    # client IP AND an ECS subnet. Compare per line — a whole-output compare
    # against the baseline silently misses the leak whenever more than one
    # string comes back.
    lines = [ln.strip().strip('"') for ln in (cp.stdout or "").splitlines()
             if ln.strip()]
    if not lines:
        return ("blocked", None)
    baseline = baseline_load()
    base_ip = baseline.get("public_ip", "")
    if base_ip and any(ln == base_ip for ln in lines):
        return ("leak", base_ip)
    return ("ok", lines[0])


def run(quick: bool = False) -> LeakResult:
    """Run the leak checks, print the report, and return a structured result.

    The return value lets callers gate on the outcome — notably `engage`,
    which must NOT report success or open a browser when `result.hard_leak`
    is True. The printed report is unchanged in shape; the return value is
    additive.
    """
    result = LeakResult()
    baseline = baseline_load()
    upstream = _engaged_upstream()
    dry = is_dry_run()
    print(color("\n┏━ LEAK REPORT ━━━━━━━━━━━━━━━━━━━━━━━━", "cyan"))

    pre_ip = baseline.get("public_ip")
    known_baseline = bool(pre_ip) and pre_ip != "(not probed)"
    if not known_baseline:
        print(f"┃ baseline public IP  : {color('UNKNOWN — clearnet-leak check degraded', 'yellow')}")
    else:
        print(f"┃ baseline public IP  : {pre_ip}")

    # Tor exit check — only meaningful when Tor is (part of) the upstream.
    # A WireGuard engage has no SOCKS port; running the check would print a
    # misleading red 'UNREACHABLE via SOCKS'. 'unknown' still runs it (a
    # standalone `snow leaktest` with no journal defaults to the Tor view).
    if upstream in ("tor", "chain", "unknown"):
        tor_info = _check_tor_exit()
        if tor_info.get("IsTor") is True:
            result.tor_confirmed = True
            print(f"┃ tor exit IP         : {color(tor_info.get('IP', '?'), 'green')}  (IsTor=true)")
        elif tor_info.get("reachable"):
            print(f"┃ tor exit check      : {color('reachable but IsTor=false', 'yellow')}")
        else:
            print(f"┃ tor exit check      : {color('UNREACHABLE via SOCKS', 'red')}")
    else:
        print(f"┃ upstream            : {color(upstream + ' (non-Tor — SOCKS check skipped)', 'cyan')}")

    if not quick:
        result.checked_clearnet = True
        if dry:
            # urllib doesn't go through sh(), so without this gate a dry-run
            # would make a REAL clearnet request (from your real IP) — the
            # exact thing the tool exists to prevent.
            print(f"┃ killswitch          : {color('[dry] clearnet probe skipped', 'magenta')}")
        else:
            clear_ip = _check_clearnet_egress()
            if clear_ip is None:
                print(f"┃ killswitch          : {color('blocked clearnet HTTP (effective)', 'green')}")
            elif clear_ip == pre_ip:
                result.clearnet_leak = True
                print(f"┃ killswitch          : {color('INEFFECTIVE — clearnet still reaches ' + clear_ip, 'red')}")
            elif not known_baseline:
                # The probe egressed somewhere, but there is no baseline IP to
                # compare against — this is exactly the shape of a full leak when
                # the baseline probe failed pre-engage. Never print green here.
                result.clearnet_unverified = True
                print(f"┃ killswitch          : {color('clearnet probe answered ' + clear_ip + ' but baseline IP unknown — cannot classify', 'yellow')}")
            else:
                # A non-baseline IP here is the HEALTHY case: the probe egressed
                # through the upstream (transproxy REDIRECT into Tor, or the WG
                # tunnel) rather than clearnet. Not a leak.
                print(f"┃ killswitch          : {color(clear_ip + ' (egressing via upstream — no clearnet leak)', 'green')}")

    ipv6_ok = _check_ipv6()
    result.ipv6_leak = not ipv6_ok
    print(f"┃ IPv6 disabled       : {color('yes', 'green') if ipv6_ok else color('no — LEAK', 'red')}")

    if not quick:
        if dry:
            print(f"┃ UDP (non-DNS)       : {color('[dry] NTP probe skipped', 'magenta')}")
        else:
            result.udp_leak = _check_udp_leak()
            if result.udp_leak:
                print(f"┃ UDP (non-DNS)       : {color('NTP reply received — LEAK (QUIC/WebRTC vector)', 'red')}")
            else:
                print(f"┃ UDP (non-DNS)       : {color('blocked (no NTP reply — no leak)', 'green')}")

    dns_status, dns_ip = _check_dns_leak()
    if dns_status == "ok":
        print(f"┃ DNS resolver seen   : {color(f'{dns_ip} (no leak)', 'green')}")
    elif dns_status == "leak":
        result.dns_leak = True
        print(f"┃ DNS resolver seen   : {color(f'{dns_ip} — LEAK (your baseline IP)', 'red')}")
    elif dns_status == "blocked":
        print(f"┃ DNS resolver seen   : {color('query blocked (no answer — no leak)', 'green')}")
    else:
        print(f"┃ DNS resolver seen   : {color('unknown', 'yellow')}")

    print(color("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "cyan"))
    if result.hard_leak:
        print(color("  VERDICT: HARD LEAK — you are NOT anonymous. Run `snow restore`.\n", "red"))
    elif result.clearnet_unverified:
        print(color("  VERDICT: no hard leak PROVEN, but the clearnet check is "
                    "unverified (no baseline IP). Re-run `sudo snow engage` "
                    "(it captures a fresh baseline) or `snow baseline` "
                    "before trusting this result.\n", "yellow"))
    else:
        print(color("  VERDICT: no hard leak detected.\n", "green"))
    return result
