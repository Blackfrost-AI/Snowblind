"""Tor daemon: install, configure, start. Exposes SOCKS, DNS, Trans, Control ports."""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

from .util import is_dry_run, journal_append, log, make_system_dir, sh, write_system_file

TORRC = Path("/etc/tor/torrc.snow")
# Holds the PLAINTEXT ControlPort password (0600, root) — the name is
# historical; it is not a hash and not a Tor auth cookie. rotate.py and
# restore.py import this symbol.
CONTROL_PW_FILE = Path("/etc/tor/snow_control_pw")
# Backward-compat alias for anything still referencing the old name.
COOKIE_HASH_FILE = CONTROL_PW_FILE
TOR_PID_FILE = Path("/run/tor/snow.pid")

# Ports — chosen high to avoid clashing with anything common
SOCKS_PORT = 9050
DNS_PORT = 5353
TRANS_PORT = 9040
CONTROL_PORT = 9051


# UID of debian-tor user; written into killswitch so its packets escape the DROP policy
def tor_uid() -> int:
    import pwd
    return pwd.getpwnam("debian-tor").pw_uid


def ensure_installed() -> None:
    if shutil.which("tor"):
        return
    log("tor not installed — apt installing")
    sh("apt-get update", timeout=120)
    sh("apt-get install -y tor torsocks", timeout=300)
    log("tor installed", "ok")


def _tor_s2k_hash(pw: str) -> str:
    """Compute Tor's HashedControlPassword (S2K-RFC2440 format) in pure Python.

    Avoids `tor --hash-password <pw>`, which exposes the cleartext password
    on the argv (visible in /proc/<pid>/cmdline) for the lifetime of the
    hash computation — a brief but real window where any process on the box
    can read the control password. Output matches `tor --hash-password`
    byte-for-byte: "16:" + HEX(salt[8] + count_byte[1] + sha1_iterated[20]).
    """
    indicator = 0x60  # Tor's default cost byte: 65536 SHA1 iterations
    salt = secrets.token_bytes(8)
    EXPBIAS = 6
    count = (16 + (indicator & 15)) << ((indicator >> 4) + EXPBIAS)
    tmp = salt + pw.encode()
    slen = len(tmp)
    d = hashlib.sha1()
    remaining = count
    while remaining > 0:
        if remaining > slen:
            d.update(tmp)
            remaining -= slen
        else:
            d.update(tmp[:remaining])
            remaining = 0
    return "16:" + (salt + bytes([indicator]) + d.digest()).hex().upper()


def _gen_control_pw() -> tuple[str, str]:
    """Generate plaintext password + Tor-format hashed cookie for ControlPort."""
    pw = secrets.token_urlsafe(24)
    hashed = _tor_s2k_hash(pw)
    # write_system_file applies 0600 at creation (atomic tmp+rename), so the
    # password is never briefly world-readable the way write-then-chmod was.
    write_system_file(CONTROL_PW_FILE, pw + "\n", 0o600)
    return pw, hashed


def _exit_country_block(exit_country: str | None) -> str:
    """Format an `ExitNodes` directive from a comma-separated country-code list.

    `exit_country="us,ca,gb"` -> `ExitNodes {us},{ca},{gb}` plus `StrictNodes 1`
    so Tor refuses to fall back if no exit in those countries can be built.
    `None` -> no constraint (current behavior).
    """
    if not exit_country:
        return "# ExitNodes (none configured — exits chosen from full consensus)\nStrictNodes 0"
    codes = [c.strip().lower() for c in exit_country.split(",") if c.strip()]
    if not codes:
        return "# ExitNodes (empty after parse — exits chosen from full consensus)\nStrictNodes 0"
    if not all(re.fullmatch(r"[a-z]{2}", c) for c in codes):
        raise ValueError(f"exit_country must be 2-letter ISO codes: {exit_country!r}")
    formatted = ",".join("{" + c + "}" for c in codes)
    return f"ExitNodes {formatted}\nStrictNodes 1   # refuse fallback outside listed countries"


def write_config(exit_country: str | None = None, persona: str | None = None) -> None:
    """Write Tor's torrc.

    If `persona` is non-default, ALSO bind SOCKS/DNS/Trans to the persona's
    gateway IP (modules/netns.subnet_for). That lets the persona's netns
    DNAT its traffic to the gateway and have Tor receive it. The host's
    127.0.0.1 bindings remain so host-netns operations (rotate, leaktest,
    etc.) still work.
    """
    pw, hashed = _gen_control_pw()
    exit_block = _exit_country_block(exit_country)

    extra_bindings = ""
    if persona and persona != "default":
        from . import netns
        sub = netns.subnet_for(persona)
        gw = sub["host_ip"]
        extra_bindings = (
            f"\n# Per-persona bindings for {persona} (netns gateway {gw})\n"
            f"SocksPort {gw}:{SOCKS_PORT} IsolateDestAddr\n"
            f"DNSPort {gw}:{DNS_PORT}\n"
            f"TransPort {gw}:{TRANS_PORT}\n"
        )

    torrc = f"""# snow torrc — auto-generated, do not edit
SocksPort 127.0.0.1:{SOCKS_PORT} IsolateDestAddr
DNSPort 127.0.0.1:{DNS_PORT}
TransPort 127.0.0.1:{TRANS_PORT}{extra_bindings}
AutomapHostsOnResolve 1
VirtualAddrNetworkIPv4 10.192.0.0/10

ControlPort {CONTROL_PORT}
HashedControlPassword {hashed}
CookieAuthentication 0

# Hardening
AvoidDiskWrites 1
ClientUseIPv6 0
ClientPreferIPv6ORPort 0
# {{??}} is Tor's geocode for "country unknown" — exclude exits whose country
# GeoIP can't determine (stale or missing descriptor entries).
ExcludeExitNodes {{??}}
{exit_block}

Log notice file /var/log/tor/snow.log
DataDirectory /var/lib/tor/snow
PidFile {TOR_PID_FILE}
RunAsDaemon 0
"""
    write_system_file(TORRC, torrc, 0o644)
    # 0700: this directory holds Tor's client state (entry-guard list,
    # consensus cache). Anything a local non-root user can read here narrows
    # their activity correlation.
    make_system_dir("/var/lib/tor/snow", 0o700)
    sh("chown -R debian-tor:debian-tor /var/lib/tor/snow")
    make_system_dir("/var/log/tor")
    sh("chown debian-tor:debian-tor /var/log/tor")
    # Self-heal /run/tor. install.sh installs a tmpfiles.d entry that recreates
    # it at boot, but if that entry was removed or the box was rebooted before
    # the entry landed, Tor would fail to write its PidFile and bootstrap would
    # silently time out. Recreate idempotently every write_config().
    make_system_dir("/run/tor", 0o750)
    sh("chown debian-tor:debian-tor /run/tor")
    log(f"torrc written: {TORRC}", "ok")
    journal_append({"module": "tor", "action": "configure", "torrc": str(TORRC)})


def _avahi_on_dnsport() -> bool:
    """avahi-daemon binds UDP 5353 for mDNS. If it's up, our DNSPort can't bind."""
    cp = sh("systemctl is-active avahi-daemon", check=False)
    return cp.returncode == 0 and cp.stdout.strip() == "active"


def start(timeout: int = 45) -> bool:
    """Spawn tor under debian-tor; poll /var/log/tor/snow.log for bootstrap.

    Returns True iff Tor reached `Bootstrapped 100%` within `timeout` seconds.
    Callers (notably engage) MUST gate the kill-switch on a True return — if Tor
    didn't bootstrap and we DROP all outbound traffic, the box is offline with
    no Tor to route through.
    """
    if is_dry_run():
        log("[dry] would start tor and wait for bootstrap (skipped)", "warn")
        journal_append({"module": "tor", "action": "start"})
        return True
    if _avahi_on_dnsport():
        log(f"avahi-daemon is active and binds UDP {DNS_PORT} — Tor DNSPort will fail. "
            "Disable with: systemctl disable --now avahi-daemon", "err")
        return False

    # Stop any pre-existing tor first to avoid port clash. Use argv directly —
    # our sh() helper goes through subprocess.run (no shell), so `||` / `2>/dev/null`
    # idioms don't work and previously turned into literal argv that systemctl
    # rejected with "Invalid unit name". check=False swallows the harmless
    # "Unit not loaded" error when nothing was running.
    sh(["systemctl", "stop", "tor"], check=False)
    sh(["systemctl", "stop", "tor@default"], check=False)

    # Launch our tor in a detached session under debian-tor. The previous
    # `sh(... &)` form ALSO hit the no-shell problem — `&` became a literal
    # argv to tor, which errored out, and the polling loop then waited 45s
    # for a log file that was never created. Popen with start_new_session=True
    # is the right primitive: tor becomes its own session leader, parent
    # returns immediately, no shell metacharacter games.
    try:
        proc = subprocess.Popen(
            ["runuser", "-u", "debian-tor", "--", "tor", "-f", str(TORRC), "--quiet"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except FileNotFoundError as err:
        log(f"failed to spawn tor: {err}", "err")
        return False

    # Poll for bootstrap — also check the child process is still alive so we
    # surface crashes immediately instead of waiting out the full timeout for
    # a log file that'll never appear.
    #
    # The timeout is PROGRESS-AWARE, not wall-clock: every new `Bootstrapped`
    # step in the log resets the stall clock (deadline = now + timeout). A
    # cold-cache bootstrap that crawls through its 10 steps over two minutes
    # succeeds; a connection that actually stalls fails after `timeout`
    # seconds of zero progress. hard_deadline bounds the worst case. File
    # logs append across runs, so the seen-count initializes from existing
    # content to only react to THIS run's lines.
    log("waiting for tor bootstrap…")
    log_path = Path("/var/log/tor/snow.log")
    seen_lines = 0
    if log_path.exists():
        seen_lines = log_path.read_text(errors="replace").count("Bootstrapped ")
    start_time = time.time()
    deadline = start_time + timeout
    hard_deadline = start_time + timeout * 4
    while True:
        rc = proc.poll()
        if rc is not None:
            log(f"tor exited during bootstrap (rc={rc}) — check {log_path}", "err")
            return False
        progress = False
        if log_path.exists():
            text = log_path.read_text(errors="replace")
            n = text.count("Bootstrapped ")
            if n > seen_lines:
                if "Bootstrapped 100%" in text:
                    log(f"tor bootstrapped (100%) in {int(time.time() - start_time)}s", "ok")
                    journal_append({"module": "tor", "action": "start"})
                    return True
                seen_lines = n
                progress = True
                latest = text.rstrip().splitlines()[-1] if text.strip() else ""
                log(f"  {latest.strip()[:100]}")
        now = time.time()
        if progress:
            deadline = now + timeout
        if now >= deadline or now >= hard_deadline:
            if seen_lines == 0:
                log(f"tor produced no bootstrap progress in {int(now - start_time)}s "
                    f"— check {log_path}", "err")
            else:
                log(f"tor bootstrap STALLED after step {seen_lines} "
                    f"(no progress in {timeout}s) — check {log_path}", "err")
            # Don't leave a half-started tor running.
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            return False
        time.sleep(1)


def get_circuits() -> list[dict]:
    """Query the ControlPort for current circuit status.

    Returns a list of dicts with keys: id, status, hops (list of {fingerprint,
    nickname}), purpose, build_flags, time_created. Empty list on auth/connect
    failure. Used by `snow circuit` to show the operator the path.
    """
    if not CONTROL_PW_FILE.exists():
        return []
    pw = CONTROL_PW_FILE.read_text().strip()
    try:
        with socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=5) as s:
            s.sendall(f'AUTHENTICATE "{pw}"\r\n'.encode())
            if not s.recv(256).startswith(b"250"):
                return []
            s.sendall(b"GETINFO circuit-status\r\n")
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if data.endswith(b"250 OK\r\n"):
                    break
            try:
                s.sendall(b"QUIT\r\n")
            except OSError:
                pass
    except (ConnectionRefusedError, socket.timeout, OSError):
        return []

    circuits: list[dict] = []
    for raw in data.decode(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith(("250 ", "250-", "250+", ".")):
            continue
        parts = line.split(" ", 3)
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        cid, status, path_str = parts[0], parts[1], parts[2]
        hops = []
        for hop in path_str.split(","):
            hop = hop.strip()
            if "~" in hop:
                fp, nick = hop.split("~", 1)
            elif "=" in hop:
                fp, nick = hop.split("=", 1)
            else:
                fp, nick = hop, "?"
            hops.append({"fingerprint": fp.lstrip("$"), "nickname": nick})
        kv: dict[str, str] = {}
        if len(parts) == 4:
            for tok in parts[3].split():
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    kv[k.lower()] = v
        circuits.append({
            "id": cid, "status": status, "hops": hops,
            "purpose": kv.get("purpose", ""),
            "build_flags": kv.get("build_flags", ""),
            "time_created": kv.get("time_created", ""),
        })
    return circuits


def stop() -> None:
    """SIGTERM the tor we started using its PidFile.

    Targeting by PID avoids the `pkill -f "tor -f ..."` pattern-match, which
    can collateral-kill any wrapper or test harness whose argv happens to
    contain that string.
    """
    if TOR_PID_FILE.exists():
        try:
            pid = int(TOR_PID_FILE.read_text().strip())
            os.kill(pid, signal.SIGTERM)
            for _ in range(20):
                try:
                    os.kill(pid, 0)
                    time.sleep(0.1)
                except ProcessLookupError:
                    log(f"tor (pid={pid}) stopped", "ok")
                    return
            os.kill(pid, signal.SIGKILL)
            log(f"tor (pid={pid}) killed (didn't exit on SIGTERM)", "warn")
            return
        except (ValueError, ProcessLookupError, PermissionError) as e:
            log(f"snow.pid stale or unkillable ({e}) — falling back to pkill", "warn")
    # Last-resort: pattern match. Tightened to the full -f path so we don't
    # match arbitrary wrappers.
    sh(["pkill", "-f", f"tor -f {TORRC}"], check=False)
    log("tor stopped (via pkill fallback)", "ok")
