"""Hostname rotation. Common DHCP hostnames blend into typical home/corp LANs."""
from __future__ import annotations

import random
import socket
from pathlib import Path

from .util import journal_append, log, sh, write_system_file

# blend-in pool: looks like the default hostname a Win10/macOS/Android box would announce
_POOL = [
    "DESKTOP-{rand}", "LAPTOP-{rand}", "PC-{rand}", "WIN-{rand}",
    "MacBook-Pro", "MacBook-Air", "iPhone", "Android-{rand}",
]


def _gen() -> str:
    template = random.choice(_POOL)
    rand = "".join(random.choices("ABCDEFGHJKMNPQRSTUVWXYZ23456789", k=7))
    return template.format(rand=rand)


def _swap_hostname(text: str, old: str, new: str) -> str:
    """Replace `old` with `new` only as a WHOLE whitespace-delimited field,
    and only in the address/hostname portion of a line — never inside a
    comment. A plain str.replace() mangles unrelated lines: on a box named
    `kali`, every /etc/hosts entry containing that substring (a mirror name,
    a comment word) would be rewritten.
    """
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#") or not line.strip():
            out.append(line)
            continue
        # Split off any trailing comment so its words are never rewritten.
        code, sep, comment = line.partition("#")
        fields = code.split()
        if old in fields:
            line = "\t".join(new if f == old else f for f in fields) + sep + comment
        out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def randomize() -> str:
    original = socket.gethostname()
    new = _gen()
    log(f"current hostname: {original}")
    sh(f"hostnamectl set-hostname {new}", check=False)
    # also patch /etc/hosts so sudo doesn't whine
    hosts = Path("/etc/hosts")
    if hosts.exists():
        text = hosts.read_text()
        if original in text.split():
            write_system_file(hosts, _swap_hostname(text, original, new))
    log(f"new hostname: {new}", "ok")
    journal_append({
        "module": "host",
        "action": "randomize",
        "original": original,
        "new": new,
    })
    return new


def restore(original: str) -> str:
    sh(f"hostnamectl set-hostname {original}", check=False)
    hosts = Path("/etc/hosts")
    if hosts.exists():
        cur = socket.gethostname()
        text = hosts.read_text()
        if cur != original and cur in text.split():
            write_system_file(hosts, _swap_hostname(text, cur, original))
    log(f"hostname restored: {original}", "ok")
    return original
