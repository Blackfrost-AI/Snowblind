"""Shared helpers: logging, shell, root check, hash-chained journal, dry-run."""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Persona-aware state directory resolution (v0.6.0)
# ---------------------------------------------------------------------------
# Active persona comes from $SNOW_PERSONA, set by snow.py BEFORE this
# module is first imported (pre-parsed from --persona on sys.argv). The
# 'default' persona uses the legacy state/ path for backward compatibility
# with installations created before v0.6.0; named personas live under
# state/personas/<name>/.
#
# All module-level constants below are derived from STATE_DIR at import
# time. Any module that needs persona-scoped state inherits the right path
# via `from .util import STATE_DIR, JOURNAL, BASELINE, BACKUPS_DIR`.
# ---------------------------------------------------------------------------

_PERSONA = os.environ.get("SNOW_PERSONA", "default")

if _PERSONA == "default":
    STATE_DIR = ROOT / "state"
else:
    STATE_DIR = ROOT / "state" / "personas" / _PERSONA

BACKUPS_DIR = STATE_DIR / "backups"
JOURNAL = STATE_DIR / "journal.json"
BASELINE = STATE_DIR / "baseline.json"


# ---------------------------------------------------------------------------
# Dry-run plumbing
# ---------------------------------------------------------------------------
# When dry-run is set, sh() prints intent and returns rc=0 without executing.
# File writes (journal_append, baseline_save) still happen against real state;
# the model is "show me what subprocess calls would fire," not "run me in a
# total sandbox." Documented in --help so operators expecting full isolation
# aren't surprised.
# ---------------------------------------------------------------------------

_DRY_RUN = False


def set_dry_run(v: bool) -> None:
    global _DRY_RUN
    _DRY_RUN = v


def is_dry_run() -> bool:
    return _DRY_RUN


def write_system_file(path, text: str, mode: int | None = None) -> None:
    """Write a SYSTEM file (/etc, /run, /var), honoring dry-run.

    Under --dry-run this prints intent and does nothing — a dry run must not
    mutate the host. State files (journal, baseline) deliberately do NOT use
    this: they are written for real even under dry-run so a preview leaves an
    inspectable journal. This helper is only for host-system paths.

    The write is ATOMIC and the requested mode is applied AT CREATION, not
    after: the file is built as a sibling temp file opened with the final
    permissions, fsynced, then renamed over the target. The old
    write-then-chmod approach left secrets (the Tor ControlPort password)
    briefly world-readable under the default umask, and a crash mid-write
    could truncate the target. Symlinked targets are written through, not
    replaced.
    """
    p = Path(path)
    if _DRY_RUN:
        extra = f" (mode {oct(mode)})" if mode is not None else ""
        print(color(f"[dry] write {p}{extra}", "magenta"))
        return
    target = p.resolve() if p.is_symlink() else p
    perm = mode if mode is not None else 0o644
    tmp = target.with_name(target.name + ".snow-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, perm)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, perm)  # os.open mode is umask-masked; re-assert
        os.replace(tmp, target)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def make_system_dir(path, mode: int | None = None) -> None:
    """mkdir -p a SYSTEM directory, honoring dry-run."""
    p = Path(path)
    if _DRY_RUN:
        print(color(f"[dry] mkdir -p {p}", "magenta"))
        return
    p.mkdir(parents=True, exist_ok=True)
    if mode is not None:
        p.chmod(mode)


# ---------------------------------------------------------------------------

def backup_path(name: str) -> Path:
    """Stable per-module backup file under state/backups/. Survives reboot
    (state/ lives next to snow.py); /tmp is tmpfs and would lose this."""
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    return BACKUPS_DIR / name


def detect_lan_cidr(iface: str) -> str | None:
    """Return the CIDR of the IPv4 network attached to iface, e.g. '192.168.50.0/24'.
    Used to scope LAN bypass rules tightly instead of opening all of RFC1918."""
    import ipaddress
    cp = subprocess.run(
        ["ip", "-o", "-f", "inet", "addr", "show", "dev", iface],
        capture_output=True, text=True, check=False,
    )
    if cp.returncode != 0:
        return None
    for line in cp.stdout.splitlines():
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok == "inet" and i + 1 < len(parts):
                try:
                    return str(ipaddress.ip_interface(parts[i + 1]).network)
                except ValueError:
                    continue
    return None


def detect_default_iface() -> str | None:
    """Return the iface used by the default IPv4 route, e.g. 'wlp3s0' or 'eth0'.

    Replaces the hardcoded 'wlan0' default — many modern installs use
    predictable interface names (enp3s0, wlp2s0) where 'wlan0' doesn't exist
    and the tool fails silently or operates on the wrong iface.
    """
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


def journal_has(module: str, action: str = "apply") -> bool:
    """True if the (module, action) pair is present in the current journal —
    cheap idempotency guard for engage-then-engage-again."""
    for e in journal_load():
        if e.get("module") == module and e.get("action") == action:
            return True
    return False


_COLORS = {
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "bold": "\033[1m", "reset": "\033[0m",
}


def color(text: str, c: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{_COLORS.get(c, '')}{text}{_COLORS['reset']}"


def banner(text: str) -> None:
    bar = "=" * max(40, len(text) + 8)
    print(color(bar, "cyan"))
    print(color(f"    {text}", "bold"))
    print(color(bar, "cyan"))


def log(msg: str, level: str = "info") -> None:
    tag = {"info": ("[*]", "blue"), "ok": ("[+]", "green"),
           "warn": ("[!]", "yellow"), "err": ("[x]", "red")}[level]
    print(f"{color(tag[0], tag[1])} {msg}")


def require_root() -> None:
    if os.geteuid() != 0:
        log("must run as root (try: sudo snow ...)", "err")
        sys.exit(1)


def sh(cmd: str | list[str], check: bool = True, capture: bool = True,
       timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a shell command; returns CompletedProcess.

    Honors global dry-run: prints intent in magenta and returns rc=0
    CompletedProcess without executing. State-file writes (journal_append,
    baseline_save) still happen against real disk — use --dry-run to preview
    subprocess actions, not to run in a sandbox.
    """
    if isinstance(cmd, str):
        argv = shlex.split(cmd)
    else:
        argv = [str(a) for a in cmd]

    if _DRY_RUN:
        print(color("[dry] " + " ".join(argv), "magenta"))
        return subprocess.CompletedProcess(argv, 0, "", "")

    try:
        cp = subprocess.run(argv, check=check, capture_output=capture,
                            text=True, timeout=timeout)
        return cp
    except subprocess.CalledProcessError as e:
        log(f"command failed: {' '.join(argv)}", "err")
        if e.stderr:
            print(e.stderr.strip())
        if check:
            raise
        return e
    except subprocess.TimeoutExpired:
        log(f"command timed out: {' '.join(argv)}", "err")
        raise


# ---------------------------------------------------------------------------
# Hash-chained journal
# ---------------------------------------------------------------------------
# Every entry carries `prev_hash` (entry_hash of prior entry, or "GENESIS")
# and `entry_hash` (SHA-256 over the canonical JSON of the entry minus its
# own entry_hash). Tampering with any historical entry breaks the chain at
# that index; journal_verify() detects it. Restore surfaces but doesn't
# refuse on a broken chain — operators running restore are usually trying
# to *recover*, not adjudicate.
# ---------------------------------------------------------------------------

def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _atomic_write_state(path: Path, text: str) -> None:
    """Atomically persist a state file (journal/baseline) at mode 0600.

    These files carry the operator's REAL public IP, MAC, and hostname — they
    get owner-only permissions, and the tmp+rename dance means a crash can
    never leave a truncated file behind.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def journal_append(entry: dict[str, Any]) -> None:
    """Append an action to the hash-chained journal.

    If the existing journal is corrupt (crash mid-write, disk issue), it is
    QUARANTINED to journal.json.corrupt-<ts> rather than silently discarded:
    the old behavior reset to a fresh GENESIS chain in place, which both
    destroyed the tamper-evidence trail and let a corrupting event erase
    every record of an engaged session.
    """
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    if JOURNAL.exists():
        try:
            entries = json.loads(JOURNAL.read_text())
        except json.JSONDecodeError as e:
            quarantine = JOURNAL.with_name(f"{JOURNAL.name}.corrupt-{int(time.time())}")
            try:
                JOURNAL.rename(quarantine)
                log(f"journal was corrupt ({e}) — quarantined to {quarantine}; "
                    f"starting a fresh chain", "err")
            except OSError:
                log(f"journal corrupt and could not be quarantined: {e}", "err")
            entries = []
    entry.setdefault("ts", time.time())
    entry["prev_hash"] = entries[-1].get("entry_hash") if entries else "GENESIS"
    entry["entry_hash"] = _entry_hash(entry)
    entries.append(entry)
    _atomic_write_state(JOURNAL, json.dumps(entries, indent=2))


def journal_load() -> list[dict[str, Any]]:
    if not JOURNAL.exists():
        return []
    try:
        return json.loads(JOURNAL.read_text())
    except json.JSONDecodeError:
        return []


def journal_is_corrupt() -> bool:
    """True if the journal file exists but is not valid JSON. journal_load()
    is deliberately lenient (returns []) — this lets callers distinguish
    'no journal' from 'journal unreadable' instead of misreporting a corrupt
    journal as a verified empty one."""
    if not JOURNAL.exists():
        return False
    try:
        json.loads(JOURNAL.read_text())
        return False
    except json.JSONDecodeError:
        return True


def journal_verify() -> tuple[bool, int | None, str | None]:
    """Walk the chain. Returns (ok, broken_at_index, reason)."""
    if journal_is_corrupt():
        return False, 0, "journal file is corrupt (invalid JSON)"
    entries = journal_load()
    if not entries:
        return True, None, None
    prev = "GENESIS"
    for i, e in enumerate(entries):
        if e.get("prev_hash") != prev:
            return False, i, (f"prev_hash mismatch at index {i} "
                              f"(expected {prev}, got {e.get('prev_hash')})")
        expected = _entry_hash(e)
        if e.get("entry_hash") != expected:
            return False, i, f"entry_hash mismatch at index {i} (entry modified after recording)"
        prev = e["entry_hash"]
    return True, None, None


def journal_clear() -> None:
    if JOURNAL.exists():
        JOURNAL.unlink()


def baseline_save(snap: dict[str, Any]) -> None:
    _atomic_write_state(BASELINE, json.dumps(snap, indent=2))


def baseline_load() -> dict[str, Any]:
    if not BASELINE.exists():
        return {}
    try:
        return json.loads(BASELINE.read_text())
    except json.JSONDecodeError:
        log("baseline.json is corrupt — treating as empty", "warn")
        return {}


# ---------------------------------------------------------------------------
# Duration parsing — "4h", "30m", "10s", "1h30m"
# ---------------------------------------------------------------------------

def parse_duration(s: str) -> int:
    """Parse a duration string into seconds. Accepts h/m/s suffixes, combinable.
    Bare integer = seconds. Raises ValueError on garbage."""
    s = s.strip().lower()
    if not s:
        raise ValueError("empty duration")
    if s.isdigit():
        return int(s)
    total = 0
    cur = ""
    for ch in s:
        if ch.isdigit():
            cur += ch
        elif ch in "hms":
            if not cur:
                raise ValueError(f"bad duration: {s!r}")
            n = int(cur)
            total += n * {"h": 3600, "m": 60, "s": 1}[ch]
            cur = ""
        else:
            raise ValueError(f"unrecognized char {ch!r} in duration {s!r}")
    if cur:
        total += int(cur)  # trailing digits = seconds
    if total <= 0:
        raise ValueError(f"duration must be positive: {s!r}")
    return total
