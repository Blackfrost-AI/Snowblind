"""Kill switch: default DROP OUTPUT policy. Only the active upstream + lo + LAN may leave.

Rules live in a named `ghost-killswitch` chain so they can be flushed and
recreated independently of UFW / fail2ban / docker chains.

Upstream-aware: Tor egress is matched by UID (debian-tor); WireGuard egress
is matched by iface (e.g. ghost-wg). Both forms supported simultaneously
(useful for future chain upstreams).
"""
from __future__ import annotations

from .util import backup_path, is_dry_run, journal_append, journal_has, log, sh

CHAIN = "ghost-killswitch"
FILTER_BACKUP = backup_path("killswitch-iptables-filter.save")
FILTER6_BACKUP = backup_path("killswitch-ip6tables-filter.save")

# Always-bypass nets at L3.5: loopback only. LAN comes in as a parameter
# so we don't open all of RFC1918 by default.
_LOOPBACK = ["127.0.0.0/8"]


def _chain_exists() -> bool:
    # sh() fakes rc=0 under --dry-run, which would make this read "already
    # applied" and the preview would never show the intended ruleset.
    if is_dry_run():
        return False
    cp = sh(f"iptables -nL {CHAIN}", check=False)
    return cp.returncode == 0


def apply(iface: str = "wlan0",
          upstream=None,
          lan_cidrs: list[str] | None = None,
          bypass_ips: list[str] | None = None) -> None:
    """Arm the kill-switch. Idempotent: a second call is a no-op.

    `upstream` — optional Upstream instance. Its `killswitch_owner_uids()` and
    `killswitch_egress_ifaces()` define what's allowed to escape default-DROP.
    If None, falls back to Tor-via-uid lookup for backward compatibility.

    `bypass_ips` — host IPs that should be ACCEPTed in addition to upstream/lo/LAN.
    Pair this with the same list on transproxy.apply so they travel clearnet.
    """
    if journal_has("killswitch", "apply") or _chain_exists():
        log("killswitch already applied — skipping (use `ghost restore` first)", "warn")
        return

    # Resolve upstream allowances; fall back to legacy Tor-uid behavior so older
    # callers that don't pass `upstream` still work identically.
    if upstream is not None:
        owner_uids = list(upstream.killswitch_owner_uids())
        egress_ifaces = list(upstream.killswitch_egress_ifaces())
        upstream_name = upstream.name
        # Upstream-declared explicit accepts — e.g. the WireGuard tunnel's
        # encrypted packets to the VPN endpoint, which leave on the REAL iface
        # as UDP and would otherwise survive only as long as their conntrack
        # ESTABLISHED entry (an idle tunnel without PersistentKeepalive would
        # then be dropped). getattr guards an upstream that predates the method.
        _extra = getattr(upstream, "killswitch_extra_accepts", None)
        extra_accepts = list(_extra()) if callable(_extra) else []
    else:
        from .tor import tor_uid
        owner_uids = [tor_uid()]
        egress_ifaces = []
        upstream_name = "tor (default)"
        extra_accepts = []

    bypass = list(_LOOPBACK) + list(lan_cidrs or [])
    target_bypass = list(bypass_ips or [])

    # Snapshot pre-existing filter state for both v4 and v6.
    sh(f"sh -c 'iptables-save -t filter > {FILTER_BACKUP}'")
    sh(f"sh -c 'ip6tables-save > {FILTER6_BACKUP}'", check=False)

    sh(f"iptables -N {CHAIN}")
    sh(f"iptables -I OUTPUT 1 -j {CHAIN}")

    cmds = [
        f"iptables -A {CHAIN} -o lo -j ACCEPT",
        f"iptables -A {CHAIN} -m state --state ESTABLISHED,RELATED -j ACCEPT",
        # DHCP keeps the lease alive
        f"iptables -A {CHAIN} -p udp --dport 67:68 --sport 67:68 -j ACCEPT",
    ]
    # Upstream egress — by UID (Tor) or by iface (WireGuard) or both (chain)
    for uid in owner_uids:
        cmds.append(f"iptables -A {CHAIN} -m owner --uid-owner {uid} -j ACCEPT")
    for egress in egress_ifaces:
        cmds.append(f"iptables -A {CHAIN} -o {egress} -j ACCEPT")
    for net in bypass:
        cmds.append(f"iptables -A {CHAIN} -d {net} -j ACCEPT")
    for ip in target_bypass:
        cmds.append(f"iptables -A {CHAIN} -d {ip}/32 -j ACCEPT")
    # Upstream-declared explicit accepts (e.g. the WireGuard tunnel endpoint).
    for proto, ip, port in extra_accepts:
        cmds.append(f"iptables -A {CHAIN} -p {proto} -d {ip} --dport {port} -j ACCEPT")
    # Terminate the chain in DROP, not RETURN. RETURN hands the packet back
    # to the OUTPUT chain, where a downstream ACCEPT from another tool can let
    # it leave before the `-P OUTPUT DROP` policy is ever reached — most
    # importantly UFW's `ufw-track-output` (`-p udp/tcp -m conntrack
    # --ctstate NEW -j ACCEPT`, which is how UFW implements "allow outgoing").
    # On a UFW host that leaked all non-Tor UDP (QUIC, WebRTC) past the
    # kill-switch. Ending the chain in DROP makes the kill-switch
    # self-contained: correctness no longer depends on OUTPUT policy or on
    # ghost being the only OUTPUT rule.
    cmds.append(f"iptables -A {CHAIN} -j DROP")
    cmds.append("iptables -P OUTPUT DROP")  # belt-and-suspenders behind the chain DROP
    # INPUT-side belt + suspenders for hosts running INPUT default DROP.
    cmds.append("iptables -I INPUT 1 -m state --state ESTABLISHED,RELATED "
                "-m comment --comment ghost-input-est -j ACCEPT")
    # IPv6: block entirely (we already nuked the stack via sysctl).
    cmds.append("ip6tables -P OUTPUT DROP")
    cmds.append("ip6tables -P INPUT DROP")
    cmds.append("ip6tables -P FORWARD DROP")

    for c in cmds:
        sh(c, check=False)

    # Flush conntrack so pre-existing TCP flows are re-evaluated against the
    # new ruleset, not sailed through on ESTABLISHED-allow.
    cp = sh(["conntrack", "-F"], check=False)
    if cp.returncode != 0:
        log("conntrack -F failed (apt install conntrack); pre-existing flows "
            "may continue to leak via the ESTABLISHED-allow rule", "warn")

    allow_desc = []
    if owner_uids:
        allow_desc.append(f"uids={','.join(str(u) for u in owner_uids)}")
    if egress_ifaces:
        allow_desc.append(f"ifaces={','.join(egress_ifaces)}")
    tgt_note = f", target_bypass={','.join(target_bypass)}" if target_bypass else ""
    log(f"kill-switch armed for upstream={upstream_name}: OUTPUT default DROP, "
        f"allow={CHAIN} ({' '.join(allow_desc)}, lo, DHCP, LAN={','.join(bypass)}{tgt_note})", "ok")
    journal_append({
        "module": "killswitch", "action": "apply",
        "iface": iface, "chain": CHAIN,
        "upstream": upstream_name,
        "owner_uids": owner_uids,
        "egress_ifaces": egress_ifaces,
        "backup": str(FILTER_BACKUP), "backup6": str(FILTER6_BACKUP),
        "bypass": bypass,
        "target_bypass_ips": target_bypass,
        "extra_accepts": [list(x) for x in extra_accepts],
    })


def revert() -> None:
    sh("iptables -P OUTPUT ACCEPT", check=False)
    sh("ip6tables -P OUTPUT ACCEPT", check=False)
    sh("ip6tables -P INPUT ACCEPT", check=False)
    sh("ip6tables -P FORWARD ACCEPT", check=False)
    sh("iptables -D INPUT -m state --state ESTABLISHED,RELATED "
       "-m comment --comment ghost-input-est -j ACCEPT", check=False)
    sh(f"iptables -D OUTPUT -j {CHAIN}", check=False)
    sh(f"iptables -F {CHAIN}", check=False)
    sh(f"iptables -X {CHAIN}", check=False)
    if FILTER_BACKUP.exists():
        sh(f"sh -c 'iptables-restore < {FILTER_BACKUP}'", check=False)
        log(f"kill-switch: filter restored from {FILTER_BACKUP}", "ok")
    else:
        log(f"kill-switch: no backup at {FILTER_BACKUP}, left flushed", "warn")
    if FILTER6_BACKUP.exists():
        sh(f"sh -c 'ip6tables-restore < {FILTER6_BACKUP}'", check=False)
