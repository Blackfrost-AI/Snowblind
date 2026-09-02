"""Transparent proxy NAT: redirect outbound TCP to the upstream's trans port,
DNS to the upstream's DNS port. Used for upstreams that expose local-loopback
proxy/DNS ports (Tor). No-op for upstreams that handle routing themselves
(WireGuard, where kernel routes pull everything through the tunnel).

Rules live in a named `snow-trans` chain so they can be flushed and recreated
without disturbing pre-existing nat/OUTPUT rules (UFW, fail2ban, docker, etc.).
"""
from __future__ import annotations

from .util import backup_path, is_dry_run, journal_append, journal_has, log, sh

CHAIN = "snow-trans"
RULES_BACKUP = backup_path("transproxy-iptables.save")

# Always-bypass nets: loopback. LAN bypass is passed in dynamically; defaults
# to loopback-only.
_LOOPBACK = ["127.0.0.0/8"]


def _chain_exists() -> bool:
    # sh() fakes rc=0 under --dry-run, which would read as "already applied"
    # and hide the intended ruleset from the preview.
    if is_dry_run():
        return False
    cp = sh(f"iptables -t nat -nL {CHAIN}", check=False)
    return cp.returncode == 0


def apply(upstream=None,
          lan_cidrs: list[str] | None = None,
          bypass_ips: list[str] | None = None) -> None:
    """Install transproxy if the active upstream wants TCP/DNS REDIRECT.

    Idempotent. Becomes a logged no-op when the upstream doesn't need it
    (WireGuard handles routing via kernel routes added by wg-quick).

    `bypass_ips` — host IPs that skip REDIRECT and travel clearnet. Pair with
    the same list on killswitch.apply so they're also allowed by the filter.
    """
    if journal_has("transproxy", "apply") or _chain_exists():
        log("transproxy already applied — skipping (use `snow restore` first)", "warn")
        return

    # Resolve upstream details (or fall back to Tor defaults for legacy callers)
    if upstream is not None:
        needs_dns = upstream.needs_dns_redirect
        trans_port = upstream.trans_port
        dns_port = upstream.dns_port
        owner_uids = list(upstream.killswitch_owner_uids())
        upstream_name = upstream.name
    else:
        from .tor import DNS_PORT, TRANS_PORT, tor_uid
        needs_dns = True
        trans_port = TRANS_PORT
        dns_port = DNS_PORT
        owner_uids = [tor_uid()]
        upstream_name = "tor (default)"

    if not needs_dns and trans_port is None:
        # Upstream handles its own routing (WireGuard). Record a no-op journal
        # entry so restore knows transproxy was *considered* but skipped.
        log(f"transproxy: upstream={upstream_name} handles routing itself — no NAT rules needed", "ok")
        journal_append({
            "module": "transproxy", "action": "skipped",
            "upstream": upstream_name,
            "reason": "upstream provides routing (no trans/dns port)",
        })
        return

    bypass = list(_LOOPBACK) + list(lan_cidrs or [])
    target_bypass = list(bypass_ips or [])

    # Snapshot pre-existing iptables state so restore can roll back cleanly.
    sh(f"sh -c 'iptables-save > {RULES_BACKUP}'")

    # Create our chain, then jump to it from nat/OUTPUT exactly once.
    sh(f"iptables -t nat -N {CHAIN}")
    sh(f"iptables -t nat -I OUTPUT 1 -j {CHAIN}")

    rules: list[str] = []
    # Don't NAT the upstream's own traffic — it would loop.
    for uid in owner_uids:
        rules.append(f"iptables -t nat -A {CHAIN} -m owner --uid-owner {uid} -j RETURN")
    # Bypass loopback + LAN
    for net in bypass:
        rules.append(f"iptables -t nat -A {CHAIN} -d {net} -j RETURN")
    # Bypass target IPs (clearnet-allowed comms partner)
    for ip in target_bypass:
        rules.append(f"iptables -t nat -A {CHAIN} -d {ip}/32 -j RETURN")
    # DNS REDIRECT (if upstream serves DNS locally)
    if needs_dns and dns_port:
        rules.append(f"iptables -t nat -A {CHAIN} -p udp --dport 53 -j REDIRECT --to-ports {dns_port}")
        rules.append(f"iptables -t nat -A {CHAIN} -p tcp --dport 53 -j REDIRECT --to-ports {dns_port}")
    # TCP REDIRECT (if upstream has a transparent proxy port)
    if trans_port:
        rules.append(f"iptables -t nat -A {CHAIN} -p tcp --syn -j REDIRECT --to-ports {trans_port}")

    for r in rules:
        sh(r)

    tgt_note = f", target_bypass={','.join(target_bypass)}" if target_bypass else ""
    log(f"transproxy: {len(rules)} NAT rules in chain {CHAIN} for upstream={upstream_name} "
        f"(DNS->{dns_port if needs_dns else 'n/a'}, TCP->{trans_port or 'n/a'}, "
        f"bypass={','.join(bypass)}{tgt_note})", "ok")
    journal_append({
        "module": "transproxy", "action": "apply",
        "chain": CHAIN, "backup": str(RULES_BACKUP),
        "upstream": upstream_name,
        "trans_port": trans_port, "dns_port": dns_port,
        "bypass": bypass,
        "target_bypass_ips": target_bypass,
    })


def revert() -> None:
    # Remove the jump from OUTPUT, then flush + delete our chain.
    sh(f"iptables -t nat -D OUTPUT -j {CHAIN}", check=False)
    sh(f"iptables -t nat -F {CHAIN}", check=False)
    sh(f"iptables -t nat -X {CHAIN}", check=False)
    if RULES_BACKUP.exists():
        sh(f"sh -c 'iptables-restore < {RULES_BACKUP}'")
        log(f"transproxy: iptables restored from {RULES_BACKUP}", "ok")
    else:
        log(f"transproxy: chain removed; no backup at {RULES_BACKUP} to replay", "warn")
