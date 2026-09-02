"""Persona — named identity slots with isolated state.

A persona is a separate operating identity on the same physical box. Each
persona has its own state directory (journal, baseline, backups, browser
profile, logs), so engagement A and engagement B don't cross-contaminate
via shared bookkeeping. In v0.6.0 each persona also gets its own network
namespace (modules/netns.py), so the isolation extends to the kernel
network stack.

State layout:
    state/                          'default' persona (legacy compat — pre-v0.6
        journal.json                use of ghost stays here unchanged)
        baseline.json
        backups/
        logs/
    state/personas/<name>/          named personas
        journal.json
        baseline.json
        backups/
        logs/
        browser/                    per-persona browser profile

The active persona is selected via:
    sudo ghost --persona <name> engage
or persistently via the GHOST_PERSONA env var. ghost.py pre-parses --persona
from sys.argv BEFORE importing util so module-globals (STATE_DIR, etc.)
resolve to the persona's directory rather than the legacy state/.

Naming rules: alphanumeric plus dash/underscore, max 32 chars. The literal
name 'default' is reserved for the legacy state/ dir and cannot be created
or deleted via this CLI.
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from .util import color, log, ROOT

import os

PERSONAS_DIR = ROOT / "state" / "personas"
DEFAULT_PERSONA = "default"
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$")


def current() -> str:
    """Name of the active persona for this process (env-driven)."""
    return os.environ.get("GHOST_PERSONA", DEFAULT_PERSONA)


def is_default(name: str) -> bool:
    return name == DEFAULT_PERSONA


def validate_name(name: str) -> None:
    if not name or not _NAME_RE.match(name):
        raise ValueError(
            f"persona name must match {_NAME_RE.pattern} (got: {name!r})"
        )
    if is_default(name):
        raise ValueError("'default' is a reserved name (it's the legacy state/ dir)")


def state_dir_for(name: str) -> Path:
    """Where this persona's state lives on disk."""
    if is_default(name):
        return ROOT / "state"
    return PERSONAS_DIR / name


def exists(name: str) -> bool:
    return state_dir_for(name).exists()


def has_active_journal(name: str) -> bool:
    """True if this persona has a non-empty journal — i.e. an engage that
    hasn't been restored yet. Used by delete() to refuse a wipe that would
    orphan iptables/sysctl state."""
    j = state_dir_for(name) / "journal.json"
    return j.exists() and j.stat().st_size > 2  # `[]` is 2 bytes


def create(name: str, with_netns: bool = True) -> Path:
    """Create a new persona's state directory layout AND its network namespace.

    State subdirs: backups/, logs/, browser/.
    Netns (when with_netns=True and not running as non-root): see netns.create.

    Idempotent on both sides. with_netns=False is for unit-test / non-root
    scenarios where the state dir is wanted but the kernel ns can't be made.
    """
    validate_name(name)
    d = state_dir_for(name)
    if d.exists():
        log(f"persona '{name}' state dir already exists at {d}", "warn")
    else:
        d.mkdir(parents=True)
        for sub in ("backups", "logs", "browser"):
            (d / sub).mkdir()
        log(f"persona '{name}' state dir created at {d}", "ok")

    if with_netns:
        # Import here to avoid circular import (netns imports util only).
        from . import netns
        if os.geteuid() != 0:
            log("not running as root — skipping netns creation. Re-run with sudo to "
                "create the persona's network namespace.", "warn")
        else:
            try:
                netns.create(name)
            except Exception as e:
                log(f"netns creation failed: {e}. State dir kept; "
                    f"you can retry with `sudo ghost persona create {name}`.", "err")
    return d


def delete(name: str, force: bool = False) -> None:
    """Wipe a persona's state AND tear down its network namespace.

    Refuses by default if the persona has an active journal (would orphan
    iptables/sysctl state); --force overrides. Default persona cannot be
    deleted via this API.
    """
    if is_default(name):
        raise ValueError("cannot delete 'default' persona (legacy state/)")
    d = state_dir_for(name)
    if not d.exists():
        raise FileNotFoundError(f"persona '{name}' does not exist")
    if has_active_journal(name) and not force:
        raise RuntimeError(
            f"persona '{name}' has an active journal at {d / 'journal.json'}. "
            f"Restore it first:\n"
            f"  sudo GHOST_PERSONA={name} ghost restore\n"
            f"or pass --force to wipe anyway (leaves any in-place iptables/sysctl "
            f"changes dangling — see `ghost doctor` after)."
        )
    # Tear down netns first (deleting netns evicts running processes in it).
    from . import netns
    if os.geteuid() == 0 and netns.netns_exists(name):
        try:
            netns.delete(name)
        except Exception as e:
            log(f"netns teardown failed: {e}. Continuing with state dir wipe; "
                f"investigate dangling iptables/netns state.", "err")
    shutil.rmtree(d)
    log(f"persona '{name}' deleted (was at {d})", "ok")


def list_all() -> list[dict]:
    """Inventory of personas on this box. Always includes 'default'."""
    out = [{
        "name": DEFAULT_PERSONA,
        "state_dir": str(ROOT / "state"),
        "is_default": True,
        "has_journal": has_active_journal(DEFAULT_PERSONA),
        "is_current": current() == DEFAULT_PERSONA,
    }]
    if PERSONAS_DIR.exists():
        for d in sorted(PERSONAS_DIR.iterdir()):
            if d.is_dir():
                out.append({
                    "name": d.name,
                    "state_dir": str(d),
                    "is_default": False,
                    "has_journal": has_active_journal(d.name),
                    "is_current": current() == d.name,
                })
    return out


def render(personas: list[dict]) -> None:
    """Pretty-print persona list."""
    max_name = max((len(p["name"]) for p in personas), default=0)
    for p in personas:
        marker = color("*", "cyan") if p["is_current"] else " "
        default_tag = color(" (default)", "blue") if p["is_default"] else ""
        active_tag = color(" [ENGAGED]", "yellow") if p["has_journal"] else ""
        print(f"  {marker} {p['name']:<{max_name}}{default_tag}{active_tag}")
        print(f"    {p['state_dir']}")
    print()
    print(f"  current persona: {color(current(), 'cyan')}")
    print(f"  switch with:     sudo ghost --persona <name> <cmd>")
    print(f"  or persistently: export GHOST_PERSONA=<name>")
