"""Pin FQDNs to specific IPs in /etc/hosts so libc resolves them locally.

Used by `engage --target` so the bypass FQDNs don't get re-resolved via Tor's
DNSPort to a different geographic CDN pool whose IPs aren't in our killswitch
ACCEPT list. Pinning ensures the same IPs we whitelisted are the ones libc
hands to the app.

Block format in /etc/hosts:
    # ghost-target-bypass BEGIN
    <ip> <fqdn>
    ...
    # ghost-target-bypass END
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from .util import backup_path, journal_append, journal_has, log, write_system_file

HOSTS = Path("/etc/hosts")
HOSTS_BACKUP = backup_path("hosts.save")
MARK_BEGIN = "# ghost-target-bypass BEGIN"
MARK_END = "# ghost-target-bypass END"

# /etc/hosts is whitespace-delimited, so a name containing whitespace would
# inject extra columns (or, with a newline, whole extra entries). Pin names
# are re-validated here even though ghost.py gates them — defense in depth
# for anything that calls pin() directly.
_FQDN_RE = re.compile(
    r"^(?=.{1,253}\Z)"
    r"([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+"
    r"[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\Z"
)


def _strip_existing_block(text: str) -> str:
    out: list[str] = []
    skip = False
    for line in text.splitlines():
        if line.strip() == MARK_BEGIN:
            skip = True
            continue
        if line.strip() == MARK_END:
            skip = False
            continue
        if not skip:
            out.append(line)
    return "\n".join(out).rstrip() + "\n"


def pin(fqdn_to_ips: dict[str, list[str]]) -> None:
    """Atomically write the bypass block. Idempotent — re-runs replace prior block."""
    if not fqdn_to_ips:
        return
    if journal_has("hostsfile", "pin"):
        log("hostsfile already pinned — skipping (use `ghost restore` first)", "warn")
        return

    # Snapshot once. If we already have a backup from a prior incomplete run,
    # keep it (original baseline) rather than overwriting with a partially-modified file.
    if not HOSTS_BACKUP.exists():
        write_system_file(HOSTS_BACKUP, HOSTS.read_text())

    clean: dict[str, list[str]] = {}
    for fqdn, ips in fqdn_to_ips.items():
        name = fqdn.strip().rstrip(".")
        if not _FQDN_RE.match(name):
            log(f"refusing to pin {fqdn!r} — not a valid DNS name", "warn")
            continue
        good_ips = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                log(f"refusing to pin {name} → {ip!r} — not a valid IP", "warn")
                continue
            good_ips.append(ip)
        if good_ips:
            clean[name] = good_ips
    if not clean:
        log("no valid pin entries — /etc/hosts left untouched", "warn")
        return

    body = _strip_existing_block(HOSTS.read_text())
    lines = [body.rstrip(), "", MARK_BEGIN]
    for fqdn, ips in clean.items():
        for ip in ips:
            lines.append(f"{ip}\t{fqdn}")
    lines.append(MARK_END)
    write_system_file(HOSTS, "\n".join(lines) + "\n")

    flat = sum(len(v) for v in clean.values())
    log(f"hosts pinned: {len(clean)} fqdn → {flat} ip entries (backup={HOSTS_BACKUP})", "ok")
    journal_append({
        "module": "hostsfile", "action": "pin",
        "backup": str(HOSTS_BACKUP),
        "pinned": clean,
    })


def revert() -> None:
    if HOSTS_BACKUP.exists():
        write_system_file(HOSTS, HOSTS_BACKUP.read_text())
        log(f"hosts restored from {HOSTS_BACKUP}", "ok")
        HOSTS_BACKUP.unlink()
    else:
        # Best-effort: strip the block in place if no backup found.
        write_system_file(HOSTS, _strip_existing_block(HOSTS.read_text()))
        log("hosts: no backup found, stripped bypass block in place", "warn")
