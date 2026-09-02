"""Kill switch: default DROP OUTPUT policy. Only the active upstream + lo + LAN may leave.

Rules live in a named `snow-killswitch` chain so they can be flushed and
recreated independently of UFW / fail2ban / docker chains.

Armed in TWO PHASES by engage:

  prelock()  — right after the IPv6 kill and BEFORE the upstream daemon
               starts. The ruleset is the final one; arming it early means
               the upstream's bootstrap window (Tor can take ~45s) DROPS new
               connections from every other process instead of letting them
               egress clearnet. No conntrack flush here, so pre-existing
               flows — notably the operator's own session — keep working
               until finalize.
  apply()    — after the upstream is verified up. Reinstalls the identical
               ruleset, then flushes conntrack so every pre-existing flow is
               re-evaluated against the lockdown.

Both phases journal their action (`prelock` / `apply`); a failed upstream
start journals `unwind` and releases the lock so the box stays reachable.
`snow restore` undoes any of them.

Upstream-aware: Tor egress is matched by UID (debian-tor); WireGuard egress
is matched by iface (e.g. snow-wg). Both forms supported simultaneously
(useful for future chain upstreams).
"""
from __future__ import annotations

from .util import backup_path, is_dry_run, journal_append, journal_load, log, sh

CHAIN = "snow-killswitch"
FILTER_BACKUP = backup_path("killswitch-iptables-filter.save")
FILTER6_BACKUP = backup_path("killswitch-ip6tables-filter.save")

# Always-bypass nets at L3.5: loopback only. LAN comes in as a parameter
# so we don't open all of RFC1918 by default.
_LOOPBACK = ["127.0.0.0/8"]

_INPUT_RULE_ARGS = ["-m", "state", "--state", "ESTABLISHED,RELATED",
                    "-m", "comment", "--comment", "snow-input-est", "-j", "ACCEPT"]


def _chain_exists() -> bool:
    # sh() fakes rc=0 under --dry-run, which would make this read "already
    # applied" and the preview would never show the intended ruleset.
    if is_dry_run():
        return False
    cp = sh(f"iptables -nL {CHAIN}", check=False)
    return cp.returncode == 0


def _allowances(upstream) -> tuple[list[int], list[str], list[tuple[str, str, int]], str]:
    """Resolve what the active upstream is allowed to send: (owner_uids,
    egress_ifaces, extra_accepts, upstream_name). Falls back to Tor-via-uid
    for legacy callers that pass no upstream."""
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
        owner_uids, egress_ifaces, extra_accepts = [tor_uid()], [], []
        upstream_name = "tor (default)"
    return owner_uids, egress_ifaces, extra_accepts, upstream_name


def _journaled_state() -> str:
    """Current kill-switch state as recorded by the journal:
    'clean' | 'prelocked' | 'applied'. Walks entries in order so an
    'unwind' correctly releases a 'prelock'."""
    state = "clean"
    for e in journal_load():
        if e.get("module") != "killswitch":
            continue
        action = e.get("action")
        if action == "prelock":
            state = "prelocked"
        elif action == "unwind":
            state = "clean"
        elif action == "apply":
            state = "applied"
    return state


def _snapshot_backups() -> None:
    """Snapshot pre-engage filter state ONCE per session. Keep-first, not
    overwrite: the backup must describe the PRE-ENGAGE ruleset even though
    arming happens in two phases (revert deletes the files after a successful
    restore, so the next engage snapshots fresh)."""
    if not FILTER_BACKUP.exists():
        sh(f"sh -c 'iptables-save -t filter > {FILTER_BACKUP}'")
    if not FILTER6_BACKUP.exists():
        sh(f"sh -c 'ip6tables-save > {FILTER6_BACKUP}'", check=False)


def _install(owner_uids, egress_ifaces, extra_accepts, bypass, target_bypass) -> None:
    """(Re)create the chain with the full ruleset and set the DROP policies.
    Idempotent: flushes the chain first, so upgrading a prelock to the final
    ruleset is the same code path as installing from scratch."""
    if not _chain_exists():
        sh(f"iptables -N {CHAIN}")
        sh(f"iptables -I OUTPUT 1 -j {CHAIN}")
    sh(f"iptables -F {CHAIN}")

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
    # snow being the only OUTPUT rule.
    cmds.append(f"iptables -A {CHAIN} -j DROP")
    cmds.append("iptables -P OUTPUT DROP")  # belt-and-suspenders behind the chain DROP
    # INPUT-side belt + suspenders for hosts running INPUT default DROP.
    # -C first: prelock and apply both run this, and it must not duplicate.
    cp = sh(["iptables", "-C", "INPUT"] + _INPUT_RULE_ARGS, check=False)
    if cp.returncode != 0:
        sh(" ".join(["iptables", "-I", "INPUT", "1"] + _INPUT_RULE_ARGS), check=False)
    # IPv6: block entirely (we already nuked the stack via sysctl).
    sh("ip6tables -P OUTPUT DROP", check=False)
    sh("ip6tables -P INPUT DROP", check=False)
    sh("ip6tables -P FORWARD DROP", check=False)

    for c in cmds:
        sh(c, check=False)


def prelock(iface: str = "eth0", upstream=None,
            lan_cidrs: list[str] | None = None,
            bypass_ips: list[str] | None = None) -> None:
    """Arm the kill-switch BEFORE the upstream daemon starts.

    Closes the engage window: from here until the upstream is up, every new
    connection that isn't the upstream's own traffic is dropped, not
    proxied-but-too-late. Deliberately does NOT flush conntrack — pre-existing
    flows (the operator's session, an open editor's sync) stay alive until
    apply()'s finalize flush re-evaluates them.
    """
    state = _journaled_state()
    if state != "clean":
        log(f"kill-switch already armed (journal state: {state}) — prelock skipped", "warn")
        return
    if _chain_exists():
        log("kill-switch chain already present — prelock skipped (run `snow restore` first)", "warn")
        return

    owner_uids, egress_ifaces, extra_accepts, upstream_name = _allowances(upstream)
    bypass = list(_LOOPBACK) + list(lan_cidrs or [])
    target_bypass = list(bypass_ips or [])

    _snapshot_backups()
    _install(owner_uids, egress_ifaces, extra_accepts, bypass, target_bypass)

    log(f"pre-engage lock armed for upstream={upstream_name}: OUTPUT default DROP, "
        f"allow=uids={','.join(str(u) for u in owner_uids) or '-'}, "
        f"ifaces={','.join(egress_ifaces) or '-'}, lo, DHCP, LAN={','.join(bypass)}, "
        f"target_bypass={','.join(target_bypass) or '-'} — "
        f"new non-upstream connections now drop until engage finalizes", "ok")
    journal_append({
        "module": "killswitch", "action": "prelock",
        "iface": iface, "chain": CHAIN,
        "upstream": upstream_name,
        "owner_uids": owner_uids,
        "egress_ifaces": egress_ifaces,
        "backup": str(FILTER_BACKUP), "backup6": str(FILTER6_BACKUP),
        "bypass": bypass,
        "target_bypass_ips": target_bypass,
        "extra_accepts": [list(x) for x in extra_accepts],
    })


def apply(iface: str = "eth0",
          upstream=None,
          lan_cidrs: list[str] | None = None,
          bypass_ips: list[str] | None = None) -> None:
    """Finalize the kill-switch after the upstream is verified up.

    Installs the full ruleset (upgrading a prelock in place), then flushes
    conntrack so pre-existing flows are re-evaluated against the lockdown
    instead of sailing through on ESTABLISHED-allow.
    """
    state = _journaled_state()
    if state == "applied":
        log("killswitch already applied — skipping (use `snow restore` first)", "warn")
        return

    owner_uids, egress_ifaces, extra_accepts, upstream_name = _allowances(upstream)
    bypass = list(_LOOPBACK) + list(lan_cidrs or [])
    target_bypass = list(bypass_ips or [])

    _snapshot_backups()
    _install(owner_uids, egress_ifaces, extra_accepts, bypass, target_bypass)

    # Flush conntrack so pre-existing TCP flows are re-evaluated against the
    # new ruleset, not sailed through on ESTABLISHED-allow.
    cp = sh(["conntrack", "-F"], check=False)
    if cp.returncode != 0:
        log("conntrack -F failed (apt install conntrack); pre-existing flows "
            "may continue to leak via the ESTABLISHED-allow rule", "warn")

    if state == "prelocked":
        log(f"kill-switch finalized for upstream={upstream_name} "
            f"(upgraded from prelock; conntrack flushed — every flow re-evaluated)", "ok")
    else:
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
    sh(["iptables", "-D", "INPUT"] + _INPUT_RULE_ARGS, check=False)
    sh(f"iptables -D OUTPUT -j {CHAIN}", check=False)
    sh(f"iptables -F {CHAIN}", check=False)
    sh(f"iptables -X {CHAIN}", check=False)
    if FILTER_BACKUP.exists():
        sh(f"sh -c 'iptables-restore < {FILTER_BACKUP}'", check=False)
        log(f"kill-switch: filter restored from {FILTER_BACKUP}", "ok")
        FILTER_BACKUP.unlink()
    else:
        log(f"kill-switch: no backup at {FILTER_BACKUP}, left flushed", "warn")
    if FILTER6_BACKUP.exists():
        sh(f"sh -c 'ip6tables-restore < {FILTER6_BACKUP}'", check=False)
        FILTER6_BACKUP.unlink()
