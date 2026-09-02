"""Walk the journal in reverse, undoing each action."""
from __future__ import annotations

from . import host, hostsfile, ipv6, killswitch, mac, netns, tor, transproxy
from .util import (baseline_load, journal_clear, journal_is_corrupt,
                   journal_load, journal_verify, log, sh)


def _stop_upstream(entry: dict) -> None:
    """Restore-side upstream teardown. We can't re-instantiate the Upstream
    object (no live state) but the journal entry carries the subtype + iface
    needed to call the right stop primitive."""
    subtype = entry.get("subtype", "tor")
    if subtype == "tor":
        tor.stop()
    elif subtype == "wireguard":
        iface = entry.get("iface", "ghost-wg")
        sh(["wg-quick", "down", iface], check=False)
        log(f"WG stopped ({iface})", "ok")
    else:
        log(f"unknown upstream subtype in journal: {subtype!r}", "warn")


def rollback() -> None:
    if journal_is_corrupt():
        log("journal file is CORRUPT (invalid JSON) — restore has nothing to "
            "replay from it. If the box is still engaged (check `ghost "
            "status` / `iptables -nL ghost-killswitch`), undo manually: "
            "`iptables -P OUTPUT ACCEPT && iptables -D OUTPUT 1` plus "
            "ip6tables policies, wg-quick down ghost-wg, and pkill the tor "
            "instance. Do NOT delete the corrupt file — it's evidence.", "err")
        return
    entries = journal_load()
    if not entries:
        log("journal empty — nothing to restore", "warn")
        return

    # Verify the hash chain before walking it; surface tampering but proceed
    # (an operator running restore explicitly is generally trying to *recover*,
    # not adjudicate — surface the issue so they can investigate after).
    ok, idx, reason = journal_verify()
    if not ok:
        log(f"journal chain BROKEN at index {idx}: {reason}", "err")
        log("proceeding with restore anyway; investigate the journal after rollback", "warn")

    log(f"rolling back {len(entries)} journaled actions in reverse")
    base = baseline_load()
    failures = 0  # count revert errors — keep the journal if any fail

    for e in reversed(entries):
        mod = e.get("module")
        act = e.get("action")
        try:
            if mod == "session" and act == "schedule_autorestore":
                # Cancel any pending systemd timer we set with `engage --duration`.
                unit = e.get("unit_name", "")
                if unit:
                    sh(["systemctl", "stop", unit], check=False)
                    log(f"cancelled pending autorestore timer: {unit}", "ok")
            elif mod == "killswitch":
                killswitch.revert()
            elif mod == "transproxy":
                transproxy.revert()
            elif mod == "hostsfile" and act == "pin":
                hostsfile.revert()
            elif mod == "tor":
                if act == "start":
                    tor.stop()
                elif act == "configure":
                    # Remove the generated torrc and — importantly — the
                    # plaintext ControlPort password file. Leaving
                    # /etc/tor/ghost_control_pw on disk after restore is a
                    # stale secret; a fresh engage regenerates both anyway.
                    for stale in (tor.CONTROL_PW_FILE, tor.TORRC):
                        try:
                            if stale.exists():
                                stale.unlink()
                                log(f"removed {stale}", "ok")
                        except OSError as ex:
                            log(f"could not remove {stale}: {ex}", "warn")
            elif mod == "upstream":
                if act == "start":
                    _stop_upstream(e)
                # configure entries leave their staged config in place — harmless
            elif mod == "netns":
                if act == "internal_routing":
                    # Flush persona-netns iptables back to permissive default.
                    # Netns itself stays (persisted across engage/restore cycles;
                    # only `ghost persona delete` tears the namespace down).
                    netns.teardown_internal_routing(e.get("persona", ""))
                # action=create / action=delete entries are informational —
                # ns lifecycle is owned by `ghost persona create/delete`, not
                # by engage/restore.
            elif mod == "ipv6" and act == "disable":
                ipv6.enable(e.get("previous"))
            elif mod == "host" and act == "randomize":
                host.restore(e.get("original", base.get("hostname", "kali")))
            elif mod == "mac" and act == "randomize":
                mac.restore(e.get("iface", base.get("iface", "wlan0")))
        except Exception as ex:
            log(f"error reverting {mod}/{act}: {ex}", "err")
            failures += 1

    # Only clear the journal on a fully clean restore. If a revert failed, the
    # journal is the record of what still needs undoing — wiping it would
    # strand the operator (e.g. a failed killswitch.revert() leaves OUTPUT
    # policy DROP with nothing left to replay). Keep it so `ghost restore` can
    # be re-run after the operator investigates.
    if failures:
        log(f"{failures} revert(s) FAILED — keeping the journal so you can re-run "
            f"`ghost restore` after investigating. The box may be in a partial "
            f"state; check with `ghost status` and `ghost leaktest`.", "err")
    else:
        journal_clear()
        log("restore complete — journal cleared", "ok")
