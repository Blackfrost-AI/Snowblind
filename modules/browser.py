"""Mullvad Browser launcher tied to ghost engage state.

ghost owns the network layer; Mullvad Browser owns the fingerprint layer.
This wrapper enforces the pairing and handles the privilege/env dance
needed when ghost runs under `sudo` but the browser needs the operator's
X/Wayland session to actually paint a window.

What it does:
- Refuses to launch unless ghost is engaged (skippable for engage-flow callers).
- Quick egress check before launch (skippable too).
- Drops privileges to the invoking user (via SUDO_USER) so the browser
  doesn't run as root.
- Reconstructs the user's session env (DISPLAY, XAUTHORITY, XDG_RUNTIME_DIR,
  DBUS_SESSION_BUS_ADDRESS, HOME, USER, LOGNAME, PATH) so the browser can
  reach the X/Wayland server — sudo strips DISPLAY/XAUTHORITY by default,
  which was the root cause of v0.5.0's "silently fails" bug.
- Captures stdout+stderr to state/logs/browser-*.log instead of /dev/null
  so silent failures are actually diagnosable.

Set $GHOST_BROWSER to override the binary path search.
"""
from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import time
from pathlib import Path

from .util import journal_load, log, STATE_DIR

CANDIDATES = [
    "~/.local/share/mullvad-browser/Browser/start-mullvad-browser",
    "~/mullvad-browser/Browser/start-mullvad-browser",
    "/opt/mullvad-browser/Browser/start-mullvad-browser",
]


# ---------------------------------------------------------------------------
# Binary discovery (with SUDO_USER awareness so we look at the invoking
# user's $HOME, not /root)
# ---------------------------------------------------------------------------

def _invoking_user() -> tuple[str | None, str | None]:
    """Return (username, home_dir) of the user who invoked sudo, or (None, None)
    if not running under sudo."""
    if os.geteuid() != 0:
        return None, None
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or sudo_user == "root":
        return None, None
    try:
        pw = pwd.getpwnam(sudo_user)
        return sudo_user, pw.pw_dir
    except KeyError:
        return None, None


def _find_browser() -> str | None:
    env = os.environ.get("GHOST_BROWSER", "").strip()
    if env:
        p = Path(os.path.expanduser(env))
        if p.exists():
            return str(p)

    # When running under sudo, expand ~ against SUDO_USER's home, not /root.
    _, sudo_home = _invoking_user()
    for c in CANDIDATES:
        if c.startswith("~/") and sudo_home:
            p = Path(sudo_home) / c[2:]
        else:
            p = Path(os.path.expanduser(c))
        if p.exists():
            return str(p)

    for name in ("mullvad-browser", "start-mullvad-browser"):
        which = shutil.which(name)
        if which:
            return which
    return None


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

def _is_engaged() -> bool:
    """True if ghost engage has armed the kill-switch or started the upstream."""
    entries = journal_load()
    for e in entries:
        if e.get("module") == "killswitch" and e.get("action") == "apply":
            return True
        if e.get("module") == "upstream" and e.get("action") == "start":
            return True
        if e.get("module") == "tor" and e.get("action") == "start":
            return True
    return False


def _quick_leak_check() -> tuple[bool, str]:
    from .leaktest import _check_tor_exit
    info = _check_tor_exit()
    if info.get("IsTor") is True:
        return True, f"egress via Tor exit {info.get('IP', '?')}"
    if info.get("reachable"):
        return True, "SOCKS reachable but IsTor=false (non-Tor upstream — that's expected for WG)"
    return False, "SOCKS unreachable — upstream isn't routing traffic"


# ---------------------------------------------------------------------------
# Session-env reconstruction for the invoking user
# ---------------------------------------------------------------------------

def _detect_display_for(user: str) -> str | None:
    """Find the user's active X DISPLAY from `who`. Output lines like:
       'alice tty7  2026-05-18 09:12 (:0)'  -> DISPLAY=:0
    Wayland sessions show '(:1)' or '(wayland-0)' depending on display manager.
    """
    cp = subprocess.run(["who"], capture_output=True, text=True, check=False)
    if cp.returncode != 0:
        return None
    for line in cp.stdout.splitlines():
        parts = line.split()
        if not parts or parts[0] != user:
            continue
        for tok in parts:
            if tok.startswith("(:") and tok.endswith(")"):
                return tok.strip("()")
    return None


def _build_user_env(user: str, home: str) -> dict[str, str]:
    """Build the env dict an X/Wayland app needs to actually paint pixels.

    Critical vars:
      DISPLAY                  — X server address (e.g. :0)
      XAUTHORITY               — auth cookie file (typically ~/.Xauthority)
      XDG_RUNTIME_DIR          — /run/user/<uid>, hosts Wayland socket + DBUS
      WAYLAND_DISPLAY          — Wayland socket name (typically wayland-0)
      DBUS_SESSION_BUS_ADDRESS — session bus, MB uses for IPC
      HOME, USER, LOGNAME      — identity
      PATH                     — sane default for the user
    """
    pw = pwd.getpwnam(user)
    uid = pw.pw_uid
    env = {
        "HOME": home,
        "USER": user,
        "LOGNAME": user,
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "XDG_RUNTIME_DIR": f"/run/user/{uid}",
    }

    display = _detect_display_for(user) or os.environ.get("DISPLAY")
    if display:
        env["DISPLAY"] = display

    xauth = Path(home) / ".Xauthority"
    if xauth.exists():
        env["XAUTHORITY"] = str(xauth)
    elif os.environ.get("XAUTHORITY"):
        env["XAUTHORITY"] = os.environ["XAUTHORITY"]

    # Wayland socket — common naming, look for it under XDG_RUNTIME_DIR
    wayland_dir = Path(env["XDG_RUNTIME_DIR"])
    if wayland_dir.exists():
        for sock_name in ("wayland-0", "wayland-1"):
            if (wayland_dir / sock_name).exists():
                env["WAYLAND_DISPLAY"] = sock_name
                break

    # DBUS — the session bus, almost always at $XDG_RUNTIME_DIR/bus on systemd boxes
    dbus = wayland_dir / "bus"
    if dbus.exists():
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={dbus}"

    # Preserve LANG/LC_* so MB doesn't drop to POSIX locale
    for k in ("LANG", "LC_ALL", "LC_CTYPE", "TZ"):
        if k in os.environ:
            env[k] = os.environ[k]

    return env


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def launch(extra_args: list[str] | None = None, skip_gates: bool = False) -> int:
    """Launch Mullvad Browser as the invoking user (drops sudo privileges).

    `skip_gates=True` — caller (typically engage flow) has just verified
    engagement and a leaktest; don't re-check.
    """
    browser_bin = _find_browser()
    if not browser_bin:
        log("Mullvad Browser not found on this box.", "err")
        print("""\
  Install Mullvad Browser:

    V=15.0.16
    curl -fL -o /tmp/mb.tar.xz \\
         https://cdn.mullvad.net/browser/$V/mullvad-browser-linux-x86_64-$V.tar.xz
    curl -fL -o /tmp/mb.tar.xz.asc \\
         https://cdn.mullvad.net/browser/$V/mullvad-browser-linux-x86_64-$V.tar.xz.asc
    gpg --keyserver hkps://keys.openpgp.org --recv-keys \\
        EF6E286DDA85EA2A4BA7DE684E2C6E8793298290
    gpg --verify /tmp/mb.tar.xz.asc /tmp/mb.tar.xz
    tar -C ~/.local/share -xJf /tmp/mb.tar.xz

  Or set GHOST_BROWSER=/absolute/path/to/start-mullvad-browser
""")
        return 1

    if not skip_gates:
        if not _is_engaged():
            log("ghost is NOT engaged — refusing to launch browser. "
                "Run `sudo ghost engage` first.", "err")
            return 1
        ok, msg = _quick_leak_check()
        if not ok:
            log(f"pre-launch egress check FAILED: {msg}", "err")
            log("Run `ghost leaktest` to diagnose, then `ghost rotate` or `ghost restore` "
                "before relaunching.", "warn")
            return 1
        log(f"pre-launch egress check: {msg}", "ok")

    # Determine target user: if running under sudo, drop to SUDO_USER; if not
    # under sudo, launch in-place with current env.
    sudo_user, sudo_home = _invoking_user()
    pw = pwd.getpwnam(sudo_user) if sudo_user else None

    logs_dir = STATE_DIR / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    stdout_log = logs_dir / "browser-stdout.log"
    stderr_log = logs_dir / "browser-stderr.log"

    cmd = [browser_bin]
    if extra_args:
        cmd.extend(extra_args)

    # Resolve persona netns BEFORE privilege handling. `ip netns exec` needs
    # root (setns requires CAP_SYS_ADMIN), so when both apply the ordering
    # matters: enter the netns as root, THEN drop to the user inside it via
    # runuser. The previous shape (preexec_fn dropping to the user, then
    # exec'ing `ip netns exec`) ran setns as an unprivileged user and failed
    # with EPERM — the persona+sudo browser path never actually worked.
    from . import persona as _persona
    from . import netns as _netns
    active = _persona.current()
    ns_name: str | None = None
    if not _persona.is_default(active):
        if not _netns.netns_exists(active):
            log(f"persona '{active}' has no netns — refusing to launch browser. "
                f"Run `sudo ghost persona create {active}` and `sudo ghost --persona "
                f"{active} engage` first.", "err")
            return 1
        ns_name = _netns.ns_name(active)

    out_f = open(stdout_log, "ab", buffering=0)
    err_f = open(stderr_log, "ab", buffering=0)
    # Browser logs can echo URLs / crash traces — owner-only.
    os.chmod(stdout_log, 0o600)
    os.chmod(stderr_log, 0o600)

    popen_kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": out_f,
        "stderr": err_f,
        "start_new_session": True,
    }

    if sudo_user and sudo_home:
        uid, gid = pw.pw_uid, pw.pw_gid

        user_env = _build_user_env(sudo_user, sudo_home)
        log(f"dropping privileges to {sudo_user} (uid={uid}) for Mullvad Browser launch")
        log(f"  DISPLAY={user_env.get('DISPLAY', '(unset)')}  "
            f"XAUTHORITY={user_env.get('XAUTHORITY', '(unset)')}  "
            f"XDG_RUNTIME_DIR={user_env.get('XDG_RUNTIME_DIR', '(unset)')}")

        if "DISPLAY" not in user_env and "WAYLAND_DISPLAY" not in user_env:
            log("neither DISPLAY nor WAYLAND_DISPLAY resolved — the browser will "
                "spawn but cannot paint a window. Is the user logged into a "
                "graphical session? If you're on a headless box, run `ghost browser` "
                "as your user directly (without sudo) in the X/Wayland session.", "warn")

        popen_kwargs["env"] = user_env
        popen_kwargs["cwd"] = sudo_home

        if ns_name:
            # root enters the netns, then runuser drops to the invoking user
            # inside it. runuser (util-linux, already a ghost dep) preserves
            # the ambient env — DISPLAY/XAUTHORITY/etc. survive the hop.
            cmd = ["ip", "netns", "exec", ns_name,
                   "runuser", "-u", sudo_user, "--"] + cmd
            log(f"launching inside netns {ns_name} (privilege drop via runuser)")
        else:
            # preexec_fn runs in child between fork and exec — drop privs there.
            def _drop():
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
            popen_kwargs["preexec_fn"] = _drop
    else:
        log("launching Mullvad Browser in-place (not running under sudo or no SUDO_USER)")
        if ns_name:
            cmd = ["ip", "netns", "exec", ns_name] + cmd
            log(f"launching inside netns {ns_name}")

    log(f"command: {' '.join(cmd)}")
    log(f"stdout: {stdout_log}")
    log(f"stderr: {stderr_log}")

    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
    except (FileNotFoundError, PermissionError) as err:
        log(f"failed to spawn browser: {err}", "err")
        out_f.close()
        err_f.close()
        return 1
    finally:
        # The child holds its own dup of these fds; drop the parent's copies.
        try:
            out_f.close()
            err_f.close()
        except OSError:
            pass

    # Give the process a moment, then check it didn't immediately die.
    # If it crashes within 2s, surface stderr so the operator can debug.
    time.sleep(2)
    rc = proc.poll()
    if rc is not None:
        log(f"browser exited immediately (rc={rc})", "err")
        try:
            tail = stderr_log.read_text(errors="replace").splitlines()[-15:]
            if tail:
                log("last lines of browser stderr:", "err")
                for line in tail:
                    print(f"    {line}")
        except OSError:
            pass
        log(f"full stderr: {stderr_log}", "warn")
        return 1

    log(f"browser spawned (pid={proc.pid}). Verify in browser via https://check.torproject.org/", "ok")
    return 0
