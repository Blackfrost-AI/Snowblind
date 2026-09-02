"""Network-namespace lifecycle for per-persona isolation.

Each named persona gets its own Linux network namespace, with a veth pair
connecting it to the host netns. Apps launched via `ip netns exec` live
in this namespace — their network stack is fully separate from the host's
(own loopback, own routing table, own iptables rules).

Architecture (per persona <P>):
    host netns                                  ghost-ns-<P>
    +----------+         veth pair         +----------+
    | gv-<P>-h |<------------------------->| gv-<P>-n |
    | 10.x.y.1 |                           | 10.x.y.2 |
    +----------+                           +----------+
       |                                       |
       | (NAT MASQUERADE for outbound)         | (default route -> 10.x.y.1)
       v                                       v
    Tor / WG / chain                       persona's apps (browser, etc.)

Subnet allocation: 10.200.<octet>.0/30 where <octet> is derived from a
SHA-256 hash of the persona name so two personas don't collide. Octet 0
is the host bridge slot (reserved); octets 1-254 are persona slots.

DNS: each persona's /etc/netns/<ns>/resolv.conf points at the gateway IP
(10.x.y.1). Tor (or whatever upstream) is configured to listen on that IP
in addition to 127.0.0.1, so the persona's DNS queries hit our DNSPort.
That config wiring lives in modules/tor.py:write_config (the per-persona
SocksPort/DNSPort/TransPort gateway bindings).

NAT MASQUERADE: outbound traffic from the persona is rewritten with the
host's external iface IP so it can egress through Tor/WG/etc. exactly as
host-netns traffic would.

This module handles netns lifecycle (create, exec, delete) plus the
per-netns internal routing — setup_internal_routing() installs the
DNAT-to-gateway-Tor rules and the in-netns default-DROP kill-switch.

Operational rules:
- Root required for every operation.
- Idempotent create: re-creating an existing ns is a no-op + warn.
- Delete tears down the netns AND removes the veth pair (deleting one end
  of a veth deletes both).
- All ip commands routed through util.sh so --dry-run prints intent.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

from .util import ROOT, journal_append, journal_has, log, sh

NS_PREFIX = "ghost-ns-"
VETH_PREFIX = "gv-"  # 'gv' = ghost-veth, short enough to fit Linux's 15-char iface name limit
NETNS_RUN = Path("/var/run/netns")
NETNS_CONF = Path("/etc/netns")   # /etc/netns/<ns>/resolv.conf hosted here per ns

# Workspace-level snapshot of the host's net.ipv4.ip_forward value. Taken the
# first time any persona netns is created, restored when the last one is
# deleted. Not persona-scoped — ip_forward is a single host-global knob.
_IPFWD_ORIG = ROOT / "state" / ".netns-ip-forward-orig"


# ---------------------------------------------------------------------------
# Naming + subnet derivation
# ---------------------------------------------------------------------------

def ns_name(persona: str) -> str:
    """Namespace name for a given persona."""
    return f"{NS_PREFIX}{persona}"


def _veth_names(persona: str) -> tuple[str, str]:
    """Return (host_side_iface, ns_side_iface) names.

    Linux limit: 15 chars max. Persona names are validated <= 32 chars so
    we hash them down for the iface name. Host side = 'gv-<8hex>-h',
    ns side = 'gv-<8hex>-n'. The 8-hex prefix is deterministic per persona.
    """
    tag = hashlib.sha256(persona.encode()).hexdigest()[:8]
    return f"{VETH_PREFIX}{tag}-h", f"{VETH_PREFIX}{tag}-n"


def subnet_for(persona: str) -> dict:
    """Deterministic /30 subnet per persona. Host gets .1, ns gets .2.

    Returns {'cidr', 'host_ip', 'ns_ip', 'prefixlen', 'octet'}.
    """
    h = int(hashlib.sha256(persona.encode()).hexdigest()[:6], 16)
    octet = (h % 253) + 1   # 1..253 inclusive (avoid 0 and 254)
    return {
        "cidr": f"10.200.{octet}.0/30",
        "host_ip": f"10.200.{octet}.1",
        "ns_ip": f"10.200.{octet}.2",
        "prefixlen": 30,
        "octet": octet,
    }


def is_valid_persona_for_netns(persona: str) -> bool:
    """Default persona doesn't get a netns (uses host netns directly)."""
    return persona != "default"


# ---------------------------------------------------------------------------
# Existence checks
# ---------------------------------------------------------------------------

def netns_exists(persona: str) -> bool:
    return (NETNS_RUN / ns_name(persona)).exists()


def iface_exists(name: str) -> bool:
    cp = subprocess.run(["ip", "link", "show", name],
                        capture_output=True, text=True, check=False)
    return cp.returncode == 0


# ---------------------------------------------------------------------------
# Detect host external iface (for MASQUERADE) — same shape as util's
# detect_default_iface but folded here to avoid circular imports.
# ---------------------------------------------------------------------------

def _host_default_iface() -> str | None:
    cp = subprocess.run(["ip", "route", "show", "default"],
                        capture_output=True, text=True, check=False)
    if cp.returncode != 0 or not cp.stdout.strip():
        return None
    for line in cp.stdout.splitlines():
        parts = line.split()
        try:
            return parts[parts.index("dev") + 1]
        except (ValueError, IndexError):
            continue
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create(persona: str) -> dict:
    """Build the netns + veth pair + addressing + default route + NAT.

    Idempotent: re-calling on an existing netns is a no-op + warn. Returns
    a dict with the subnet/veth details so callers can wire downstream
    components (e.g. Tor's per-persona DNSPort, killswitch's veth-allow).
    """
    if not is_valid_persona_for_netns(persona):
        raise ValueError(f"cannot create netns for default persona (host netns is used)")

    sub = subnet_for(persona)
    nsn = ns_name(persona)
    veth_h, veth_n = _veth_names(persona)

    if netns_exists(persona):
        log(f"netns {nsn} already exists — skipping (use `ghost persona delete` to tear down first)",
            "warn")
        return {"ns_name": nsn, "veth_host": veth_h, "veth_ns": veth_n, **sub,
                "already_existed": True}

    # Subnet-collision guard. subnet_for() is a hash mod 253, so two persona
    # names can map to the same /30 (birthday-bound: ~50% by 19 personas).
    # subnet_for() must stay deterministic — status, the per-persona Tor
    # binding, and routing all recompute it — so we cannot just pick a free
    # octet here. Refuse the colliding name and let the operator rename.
    for other in list_active():
        if other["persona"] != persona and other["octet"] == sub["octet"]:
            raise ValueError(
                f"persona '{persona}' hashes to subnet {sub['cidr']}, already "
                f"in use by persona '{other['persona']}'. The subnet is a "
                f"deterministic hash of the persona name — rename this persona."
            )

    host_ext = _host_default_iface()
    if not host_ext:
        raise RuntimeError("cannot detect host default iface — no default route?")

    # 1. Create the netns
    sh(["ip", "netns", "add", nsn])

    # 2. Create the veth pair (in host netns initially)
    sh(["ip", "link", "add", veth_h, "type", "veth", "peer", "name", veth_n])

    # 3. Move ns side into the netns
    sh(["ip", "link", "set", veth_n, "netns", nsn])

    # 4. Address + bring up the host-side iface
    sh(["ip", "addr", "add", f"{sub['host_ip']}/{sub['prefixlen']}", "dev", veth_h])
    sh(["ip", "link", "set", veth_h, "up"])

    # 5. Address + bring up the ns-side iface (inside the netns)
    sh(["ip", "-n", nsn, "addr", "add", f"{sub['ns_ip']}/{sub['prefixlen']}", "dev", veth_n])
    sh(["ip", "-n", nsn, "link", "set", veth_n, "up"])
    sh(["ip", "-n", nsn, "link", "set", "lo", "up"])

    # 6. Default route inside the netns -> the gateway (host-side veth)
    sh(["ip", "-n", nsn, "route", "add", "default", "via", sub["host_ip"]])

    # 7. Enable forwarding on the host (idempotent — write 1 even if already 1).
    #    Snapshot the original value ONCE (workspace-level) so the last
    #    delete() can restore it instead of leaving forwarding on forever.
    if not _IPFWD_ORIG.exists():
        try:
            _orig = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() or "0"
        except OSError:
            _orig = "0"
        _IPFWD_ORIG.parent.mkdir(parents=True, exist_ok=True)
        _IPFWD_ORIG.write_text(_orig)
    sh(["sysctl", "-w", "net.ipv4.ip_forward=1"])

    # 8. NAT MASQUERADE so persona traffic egresses via the host's default iface
    sh(["iptables", "-t", "nat", "-A", "POSTROUTING",
        "-s", sub["cidr"], "-o", host_ext, "-j", "MASQUERADE",
        "-m", "comment", "--comment", f"ghost-netns-{persona}"])
    sh(["iptables", "-A", "FORWARD",
        "-i", veth_h, "-j", "ACCEPT",
        "-m", "comment", "--comment", f"ghost-netns-{persona}"])
    sh(["iptables", "-A", "FORWARD",
        "-o", veth_h, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
        "-m", "comment", "--comment", f"ghost-netns-{persona}"])

    # 9. Per-ns DNS — point at the host gateway (where Tor's DNSPort will
    #    bind in alpha3 once engage is netns-aware).
    NETNS_CONF.mkdir(parents=True, exist_ok=True)
    ns_conf_dir = NETNS_CONF / nsn
    ns_conf_dir.mkdir(parents=True, exist_ok=True)
    (ns_conf_dir / "resolv.conf").write_text(f"nameserver {sub['host_ip']}\n")

    log(f"netns {nsn} created: {sub['cidr']} (host={sub['host_ip']}, ns={sub['ns_ip']}); "
        f"veth {veth_h}<->{veth_n}; MASQUERADE via {host_ext}", "ok")

    journal_append({
        "module": "netns", "action": "create",
        "persona": persona, "ns_name": nsn,
        "veth_host": veth_h, "veth_ns": veth_n,
        "subnet": sub, "host_ext_iface": host_ext,
    })

    return {"ns_name": nsn, "veth_host": veth_h, "veth_ns": veth_n,
            "host_ext_iface": host_ext, **sub, "already_existed": False}


def delete(persona: str) -> None:
    """Tear down a persona's netns. Idempotent."""
    if not is_valid_persona_for_netns(persona):
        return  # nothing to do for default persona

    nsn = ns_name(persona)
    veth_h, _veth_n = _veth_names(persona)
    sub = subnet_for(persona)
    host_ext = _host_default_iface() or ""

    if not netns_exists(persona):
        log(f"netns {nsn} does not exist — nothing to tear down", "warn")
        # Best-effort cleanup of any straggler veth + NAT rules
        if iface_exists(veth_h):
            sh(["ip", "link", "del", veth_h], check=False)

    else:
        # 1. Remove NAT + FORWARD rules (use --comment match to find ours)
        comment = f"ghost-netns-{persona}"
        if host_ext:
            sh(["iptables", "-t", "nat", "-D", "POSTROUTING",
                "-s", sub["cidr"], "-o", host_ext, "-j", "MASQUERADE",
                "-m", "comment", "--comment", comment], check=False)
        sh(["iptables", "-D", "FORWARD",
            "-i", veth_h, "-j", "ACCEPT",
            "-m", "comment", "--comment", comment], check=False)
        sh(["iptables", "-D", "FORWARD",
            "-o", veth_h, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
            "-m", "comment", "--comment", comment], check=False)

        # 2. Delete the netns (this also evicts processes still running inside)
        sh(["ip", "netns", "del", nsn], check=False)

        # 3. Veth pair: deleting one end deletes both. The host side may still
        #    exist if the ns-side was already gone; clean it up best-effort.
        if iface_exists(veth_h):
            sh(["ip", "link", "del", veth_h], check=False)

    # 4. Per-ns DNS dir
    ns_conf_dir = NETNS_CONF / nsn
    if ns_conf_dir.exists():
        try:
            for f in ns_conf_dir.iterdir():
                f.unlink()
            ns_conf_dir.rmdir()
        except OSError as e:
            log(f"could not fully clean {ns_conf_dir}: {e}", "warn")

    # If this was the last ghost-managed netns, restore the host's original
    # net.ipv4.ip_forward value (snapshotted by the first create()).
    if not list_active() and _IPFWD_ORIG.exists():
        orig = _IPFWD_ORIG.read_text().strip() or "0"
        sh(["sysctl", "-w", f"net.ipv4.ip_forward={orig}"], check=False)
        try:
            _IPFWD_ORIG.unlink()
        except OSError:
            pass
        log(f"restored net.ipv4.ip_forward={orig} (last persona netns removed)", "ok")

    log(f"netns {nsn} torn down", "ok")
    journal_append({
        "module": "netns", "action": "delete",
        "persona": persona, "ns_name": nsn,
    })


def exec_in(persona: str, argv: list[str]) -> int:
    """Run a command inside the persona's netns. Returns exit code.

    Used by the browser launcher (alpha3) and the `ghost persona shell`
    convenience command.
    """
    if not is_valid_persona_for_netns(persona):
        # Default persona = host netns; just run normally
        cp = subprocess.run(argv, check=False)
        return cp.returncode
    if not netns_exists(persona):
        log(f"netns for persona '{persona}' does not exist — run "
            f"`sudo ghost persona create {persona}` first", "err")
        return 1
    cp = subprocess.run(["ip", "netns", "exec", ns_name(persona)] + list(argv), check=False)
    return cp.returncode


def teardown_internal_routing(persona: str) -> None:
    """Flush the persona-netns iptables back to permissive default.

    Called from restore.py so engage/restore/engage cycles don't duplicate
    rules. Idempotent: safe to call even if no rules exist.
    """
    if not is_valid_persona_for_netns(persona):
        return
    if not netns_exists(persona):
        return
    nsn = ns_name(persona)
    sh(["ip", "netns", "exec", nsn, "iptables", "-P", "INPUT", "ACCEPT"], check=False)
    sh(["ip", "netns", "exec", nsn, "iptables", "-P", "OUTPUT", "ACCEPT"], check=False)
    sh(["ip", "netns", "exec", nsn, "iptables", "-P", "FORWARD", "ACCEPT"], check=False)
    sh(["ip", "netns", "exec", nsn, "iptables", "-F"], check=False)
    sh(["ip", "netns", "exec", nsn, "iptables", "-t", "nat", "-F"], check=False)
    for _ch in ("INPUT", "OUTPUT", "FORWARD"):
        sh(["ip", "netns", "exec", nsn, "ip6tables", "-P", _ch, "ACCEPT"], check=False)
    for _knob in ("all", "default", "lo"):
        sh(["ip", "netns", "exec", nsn, "sysctl", "-w",
            f"net.ipv6.conf.{_knob}.disable_ipv6=0"], check=False)
    log(f"netns {nsn} internal routing flushed", "ok")
    journal_append({
        "module": "netns", "action": "teardown_internal_routing",
        "persona": persona, "ns_name": nsn,
    })


def setup_internal_routing(persona: str, dns_port: int, trans_port: int) -> None:
    """Install per-persona-netns iptables: DNAT outbound DNS+TCP-SYN to the
    gateway's Tor ports, then default-DROP OUTPUT so anything that wasn't
    redirected can't escape clearnet.

    Idempotent: flushes existing rules in the netns first so re-engage on
    the same persona doesn't duplicate. This runs inside the persona's
    netns. It does NOT touch the host's iptables — the host's killswitch/
    transproxy are governed by their own apply() functions for host-netns
    traffic.
    """
    if not is_valid_persona_for_netns(persona):
        return
    if not netns_exists(persona):
        raise RuntimeError(f"netns for persona '{persona}' does not exist")

    nsn = ns_name(persona)
    sub = subnet_for(persona)
    gw = sub["host_ip"]

    # Flush any prior rules first (idempotency across engage/restore cycles).
    sh(["ip", "netns", "exec", nsn, "iptables", "-F"], check=False)
    sh(["ip", "netns", "exec", nsn, "iptables", "-t", "nat", "-F"], check=False)

    # NAT OUTPUT — DNS + TCP-SYN to Tor's per-persona ports on the gateway.
    sh(["ip", "netns", "exec", nsn, "iptables", "-t", "nat", "-A", "OUTPUT",
        "-p", "udp", "--dport", "53", "-j", "DNAT",
        "--to-destination", f"{gw}:{dns_port}"])
    sh(["ip", "netns", "exec", nsn, "iptables", "-t", "nat", "-A", "OUTPUT",
        "-p", "tcp", "--dport", "53", "-j", "DNAT",
        "--to-destination", f"{gw}:{dns_port}"])
    sh(["ip", "netns", "exec", nsn, "iptables", "-t", "nat", "-A", "OUTPUT",
        "-p", "tcp", "--syn", "-j", "DNAT",
        "--to-destination", f"{gw}:{trans_port}"])

    # Filter OUTPUT killswitch — only loopback, gateway, and established RT.
    sh(["ip", "netns", "exec", nsn, "iptables", "-A", "OUTPUT",
        "-o", "lo", "-j", "ACCEPT"])
    sh(["ip", "netns", "exec", nsn, "iptables", "-A", "OUTPUT",
        "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    sh(["ip", "netns", "exec", nsn, "iptables", "-A", "OUTPUT",
        "-d", gw, "-j", "ACCEPT"])
    sh(["ip", "netns", "exec", nsn, "iptables", "-P", "OUTPUT", "DROP"])

    # Filter INPUT — accept loopback + established (return path for our DNATs).
    sh(["ip", "netns", "exec", nsn, "iptables", "-A", "INPUT",
        "-i", "lo", "-j", "ACCEPT"])
    sh(["ip", "netns", "exec", nsn, "iptables", "-A", "INPUT",
        "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    sh(["ip", "netns", "exec", nsn, "iptables", "-P", "INPUT", "DROP"])

    # Kill IPv6 inside the netns. The netns has its own sysctl + ip6tables
    # namespace, so the host's ipv6.disable() does not reach here. Without
    # this the netns keeps a live v6 stack (a leak surface) and the in-netns
    # leak test's IPv6 check would false-positive on every persona engage.
    for _knob in ("all", "default", "lo"):
        sh(["ip", "netns", "exec", nsn, "sysctl", "-w",
            f"net.ipv6.conf.{_knob}.disable_ipv6=1"], check=False)
    for _ch in ("OUTPUT", "INPUT", "FORWARD"):
        sh(["ip", "netns", "exec", nsn, "ip6tables", "-P", _ch, "DROP"], check=False)

    log(f"netns {nsn} internal routing armed: DNS->{gw}:{dns_port}, "
        f"TCP-SYN->{gw}:{trans_port}, default-DROP OUTPUT", "ok")

    journal_append({
        "module": "netns", "action": "internal_routing",
        "persona": persona, "ns_name": nsn,
        "dns_port": dns_port, "trans_port": trans_port,
        "gateway": gw,
    })


def list_active() -> list[dict]:
    """All ghost-managed netns currently present, with their persona name
    and subnet info. Independent of state-dir presence (in case netns was
    created but state dir was deleted)."""
    out: list[dict] = []
    if not NETNS_RUN.exists():
        return out
    for f in sorted(NETNS_RUN.iterdir()):
        if not f.name.startswith(NS_PREFIX):
            continue
        persona = f.name[len(NS_PREFIX):]
        out.append({"persona": persona, "ns_name": f.name, **subnet_for(persona)})
    return out
