#!/usr/bin/env python3
"""
snow — anonymity / OPSEC tool.

Single-binary CLI that chains together the modules in ./modules to turn a
Kali host into an anonymous-by-default client: MAC randomization, hostname
rotation, IPv6 kill, Tor transparent proxy, kill-switch firewall, circuit
rotation, and leak verification. Every state change is journaled to
state/journal.json so `snow restore` can reverse it.

For authorized use on systems you own or have written permission to test.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# Pre-parse --persona BEFORE any module imports so util.py reads the right
# SNOW_PERSONA at module-import time. Module globals like STATE_DIR are
# derived once at import; we can't rebind them after the fact across all
# downstream importers (they have their own references). Setting the env
# var here is the cleanest way to thread persona through.
# ---------------------------------------------------------------------------
for _i, _a in enumerate(sys.argv):
    if _a == "--persona" and _i + 1 < len(sys.argv):
        os.environ["SNOW_PERSONA"] = sys.argv[_i + 1]
        break
    if _a.startswith("--persona="):
        os.environ["SNOW_PERSONA"] = _a.split("=", 1)[1]
        break

from modules import baseline, mac, host, hostsfile, ipv6, tor, transproxy, killswitch, rotate, leaktest, restore, doctor, browser, persona, netns  # noqa: E402
from modules.util import (  # noqa: E402
    banner, color, detect_default_iface, detect_lan_cidr,
    journal_append, journal_is_corrupt, journal_verify, log, parse_duration,
    require_root, set_dry_run, STATE_DIR,
)
from modules.upstream import from_spec as upstream_from_spec  # noqa: E402


def _validate_active_persona() -> None:
    """Refuse an invalid --persona / $SNOW_PERSONA before anything is written.

    STATE_DIR is derived from the persona name (state/personas/<name>/) before
    any validation runs, so an unchecked name containing '/' or '..' is a path
    traversal: `sudo snow --persona ../../tmp/x engage` would scatter
    journal.json into arbitrary root-writable directories. Persona names are
    alphanumeric + dash + underscore — the same rule `persona create` enforces.
    """
    active = persona.current()
    if persona.is_default(active):
        return
    try:
        persona.validate_name(active)
    except ValueError as e:
        print(color(f"[x] invalid persona: {e}", "red"))
        sys.exit(2)


def _default_iface() -> str:
    """Resolved at runtime so argparse can use a sensible default even on
    hosts where 'wlan0' doesn't exist (most modern systemd-named installs)."""
    return detect_default_iface() or "wlan0"


VERSION = "0.6.1"

# Default FQDN allowlist for `engage --target` — endpoints that must stay
# reachable in the clear (operator's control plane: chat, comms, sync, API).
# Pinned to current A records at engage time and inserted as a clearnet
# bypass in transproxy + killswitch. Override at run time with --target-fqdn
# or persistently via the SNOW_TARGET_FQDN environment variable.
DEFAULT_TARGET_FQDNS = os.environ.get("SNOW_TARGET_FQDN", "")


def _resolve_fqdns(fqdns: list[str]) -> dict[str, list[str]]:
    """Resolve each FQDN to its current A records via the system resolver.
    Must be called BEFORE transproxy/killswitch are armed so DNS still works.
    Skips entries that fail to resolve OR resolve to bogus addresses
    (0.0.0.0/8, loopback, link-local, multicast — typical adblocker sentinels
    like AdGuard's 0.0.0.0 sinkhole). Logs a warning per skip.

    Names are validated BEFORE resolution AND before they reach /etc/hosts:
    the pin block is line-based, so an unchecked name containing whitespace
    or a newline would inject arbitrary hosts-file entries.
    """
    import ipaddress
    import re
    import socket
    _FQDN_RE = re.compile(
        r"^(?=.{1,253}\Z)"
        r"([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+"
        r"[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\Z"
    )
    out: dict[str, list[str]] = {}
    for raw in fqdns:
        fqdn = raw.strip().rstrip(".")
        if not _FQDN_RE.match(fqdn):
            log(f"invalid target FQDN {raw!r} — must be a dotted DNS name "
                f"(letters/digits/hyphen/underscore); skipping", "warn")
            continue
        try:
            _, _, ips = socket.gethostbyname_ex(fqdn)
        except OSError as e:
            log(f"failed to resolve {fqdn}: {e} — skipping", "warn")
            continue
        good: list[str] = []
        for ip in sorted(set(ips)):
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if a.is_unspecified or a.is_loopback or a.is_link_local or a.is_multicast:
                log(f"{fqdn} → {ip} is bogus (sinkhole/reserved) — dropping", "warn")
                continue
            good.append(ip)
        if good:
            out[fqdn] = good
            log(f"resolved {fqdn} → {','.join(good)}")
        else:
            log(f"{fqdn} returned no usable A records — skipping", "warn")
    return out


def cmd_status(args: argparse.Namespace) -> int:
    banner("SNOW :: status")
    active = persona.current()
    print(color(f"persona: {active}", "cyan"))
    if not persona.is_default(active):
        sub = netns.subnet_for(active)
        ns_alive = netns.netns_exists(active)
        print(f"  netns:   {netns.ns_name(active)}  "
              f"{'(present)' if ns_alive else color('(MISSING — create persona first)', 'red')}")
        print(f"  subnet:  {sub['cidr']}  (host={sub['host_ip']}, ns={sub['ns_ip']})")
    print()
    iface = args.iface or _default_iface()
    snap = baseline.current_snapshot(iface=iface, probe_public_ip=not args.no_public_ip)
    print(json.dumps(snap, indent=2))
    j = STATE_DIR / "journal.json"
    if j.exists():
        ok, idx, reason = journal_verify()
        print(color("\n[journal entries]", "cyan"))
        if journal_is_corrupt():
            print(color("[!] journal file is CORRUPT (invalid JSON) — "
                        "next journal_append will quarantine it", "red"))
        elif not ok:
            print(color(f"[!] journal chain BROKEN at index {idx}: {reason}", "red"))
        else:
            try:
                n = len(json.loads(j.read_text()))
                print(color(f"[+] journal chain VERIFIED ({n} entries)", "green"))
            except json.JSONDecodeError:
                pass
        print(j.read_text())
    else:
        print(color("\nno journal — system in pristine state", "yellow"))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    banner("SNOW :: doctor")
    iface = args.iface or _default_iface()
    rv = doctor.run(iface=iface)
    # Persona-aware extra check: if non-default, the netns must exist.
    active = persona.current()
    if not persona.is_default(active):
        print()
        if netns.netns_exists(active):
            log(f"persona '{active}' netns present at {netns.ns_name(active)}", "ok")
        else:
            log(f"persona '{active}' selected but netns does NOT exist. "
                f"Run `sudo snow persona create {active}` before engage.", "err")
            rv = 1
    return rv


def cmd_circuit(_args: argparse.Namespace) -> int:
    """Show current Tor circuits (guard / middle / exit) via ControlPort."""
    require_root()
    banner("SNOW :: circuit")
    circuits = tor.get_circuits()
    if not circuits:
        log("no circuits visible (Tor not engaged, or ControlPort unreachable)", "warn")
        return 1
    built = [c for c in circuits if c["status"].upper() == "BUILT"]
    others = [c for c in circuits if c["status"].upper() != "BUILT"]
    print(color(f"\n  BUILT circuits ({len(built)}):", "green"))
    for c in built:
        path = " -> ".join(h["nickname"] for h in c["hops"])
        print(f"    [{c['id']:>3}]  {path}   purpose={c['purpose']}")
    if others:
        print(color(f"\n  other circuits ({len(others)}):", "yellow"))
        for c in others:
            path = " -> ".join(h["nickname"] for h in c["hops"])
            print(f"    [{c['id']:>3}]  {c['status']:<10s}  {path}")
    print()
    return 0


def _schedule_autorestore(duration_seconds: int) -> str:
    """Schedule a one-shot `snow restore` via systemd-run. Returns the
    transient unit name so restore can cancel it on early teardown."""
    import secrets
    unit = f"snow-autorestore-{int(time.time())}-{secrets.token_hex(3)}"
    snow_bin = "/usr/local/bin/snow"
    if not Path(snow_bin).exists():
        # development run from cloned dir
        snow_bin = str(ROOT / "snow.py")
    from modules.util import sh
    cp = sh(["systemd-run", "--on-active=" + str(duration_seconds) + "s",
             "--unit=" + unit, snow_bin, "restore"], check=False)
    if cp.returncode != 0:
        log(f"failed to schedule autorestore via systemd-run (rc={cp.returncode})", "warn")
        return ""
    log(f"autorestore scheduled in {duration_seconds}s (systemd unit: {unit})", "ok")
    journal_append({"module": "session", "action": "schedule_autorestore",
                    "unit_name": unit, "duration_seconds": duration_seconds})
    return unit


def cmd_engage(args: argparse.Namespace) -> int:
    """Full snow mode: chain every module in the safe order."""
    require_root()
    banner("SNOW :: ENGAGE" + ("  [+target bypass]" if args.target else "")
           + ("  [DRY-RUN]" if args.dry_run else ""))
    iface = args.iface or _default_iface()

    # The pre-engage lock (step 6/8) arms the kill-switch BEFORE the upstream
    # daemon starts, so new clearnet connections from other processes drop
    # during the upstream's bootstrap. Residual exposure: flows already
    # ESTABLISHED before engage stay up until the finalize conntrack flush.
    log("pre-existing connections stay up until the finalize flush — close "
        "sensitive apps / browsers before continuing", "warn")

    # Pre-flight doctor — refuse engage on any FAIL unless explicitly skipped.
    if not args.skip_doctor:
        log("running pre-flight doctor; pass --skip-doctor to bypass")
        results = doctor.collect(iface=iface)
        doctor.render(results)
        if not doctor.is_clean(results):
            log("doctor reports FAIL conditions; refusing to engage. "
                "Fix the issues or pass --skip-doctor to override.", "err")
            return 1

    # Resolve upstream — `--upstream` wins; otherwise synthesize from legacy
    # --exit-country flag for backward compat (tor with country pinning).
    upstream_spec = args.upstream
    if not upstream_spec and args.exit_country:
        import re
        codes = [c.strip().lower() for c in args.exit_country.split(",") if c.strip()]
        if not all(re.fullmatch(r"[a-z]{2}", c) for c in codes):
            log(f"--exit-country must be 2-letter ISO codes (got: {args.exit_country!r})", "err")
            return 1
        upstream_spec = f"tor:exit_country={args.exit_country}"

    # Persona resolution — non-default personas need a pre-existing netns
    # (created via `snow persona create <name>`). Pass through to upstream
    # so e.g. Tor knows to bind per-persona ports.
    active_persona = persona.current()
    if not persona.is_default(active_persona):
        if not netns.netns_exists(active_persona):
            log(f"persona '{active_persona}' has no netns. "
                f"Run `sudo snow persona create {active_persona}` first.", "err")
            return 1
        log(f"persona: {active_persona} (netns={netns.ns_name(active_persona)})")
    else:
        log("persona: default (host netns)")

    try:
        upstream = upstream_from_spec(upstream_spec, persona=active_persona)
    except (ValueError, NotImplementedError, FileNotFoundError) as e:
        log(f"--upstream: {e}", "err")
        return 1
    log(f"upstream: {upstream.name}" + (f" (spec: {upstream_spec})" if upstream_spec else ""))

    # Parse --duration if provided so we can fail-fast on garbage.
    duration_seconds: int | None = None
    if args.duration:
        try:
            duration_seconds = parse_duration(args.duration)
            log(f"session will auto-restore in {duration_seconds}s")
        except ValueError as e:
            log(f"--duration: {e}", "err")
            return 1

    # Resolve LAN CIDR for bypass rules — explicit flag wins, else auto-detect
    # from the iface address. If neither yields anything we proceed with
    # loopback-only bypass (the killswitch will block LAN reachability too).
    import ipaddress as _ipaddress
    lan_cidrs: list[str] = []
    if args.lan:
        for c in (c.strip() for c in args.lan.split(",") if c.strip()):
            try:
                lan_cidrs.append(str(_ipaddress.ip_network(c, strict=False)))
            except ValueError:
                log(f"--lan: {c!r} is not a valid CIDR (e.g. 192.168.50.0/24)", "err")
                return 1
        log(f"LAN bypass: {','.join(lan_cidrs)} (from --lan)")
    else:
        detected = detect_lan_cidr(iface)
        if detected:
            lan_cidrs = [detected]
            log(f"LAN bypass: {detected} (auto-detected from {iface})")
        else:
            log(f"no LAN CIDR detected on {iface} — bypass will be loopback only", "warn")

    # Target bypass — resolve FQDNs to current IPs while DNS still works.
    target_pins: dict[str, list[str]] = {}
    target_ips: list[str] = []
    if args.target:
        fqdns = [f.strip() for f in args.target_fqdn.split(",") if f.strip()]
        log(f"target bypass: resolving {','.join(fqdns)} (OPSEC tradeoff: those IPs see your real source IP)")
        target_pins = _resolve_fqdns(fqdns)
        target_ips = sorted({ip for ips in target_pins.values() for ip in ips})
        if not target_ips:
            log("--target requested but no FQDNs resolved — refusing to engage", "err")
            return 1

    log("step 1/8  baseline snapshot")
    baseline.capture(iface)

    log("step 2/8  randomize MAC on " + iface)
    mac.randomize(iface)

    log("step 3/8  rotate hostname")
    host.randomize()

    log("step 4/8  kill IPv6")
    ipv6.disable()

    log(f"step 5/8  install + configure upstream ({upstream.name})")
    # ensure_installed may apt-install — that needs clearnet, so it happens
    # BEFORE the pre-engage lock arms at step 6.
    upstream.ensure_installed()
    upstream.write_config()

    log("step 6/8  pre-engage lock (close the bootstrap window)")
    killswitch.prelock(iface=iface, upstream=upstream, lan_cidrs=lan_cidrs,
                       bypass_ips=target_ips)

    log(f"step 7/8  start upstream ({upstream.name}) — bootstrapping behind the lock")
    if not upstream.start():
        log(f"upstream {upstream.name} failed to start — releasing the pre-engage "
            f"lock so the box stays reachable", "err")
        killswitch.revert()
        journal_append({"module": "killswitch", "action": "unwind",
                        "reason": f"upstream {upstream.name} failed to start"})
        log("Pre-engage lock released, network restored. Run `snow restore` to undo "
            "MAC/host/IPv6 changes, then investigate the upstream.", "warn")
        return 1

    if args.target:
        log("step 7b/8 pin target FQDNs in /etc/hosts (lock resolution before transproxy)")
        hostsfile.pin(target_pins)

    log("step 7c/8  transparent-proxy iptables (NAT REDIRECT into upstream, if applicable)")
    transproxy.apply(upstream=upstream, lan_cidrs=lan_cidrs, bypass_ips=target_ips)

    log(f"step 7d/8  kill-switch finalize (flush conntrack; drop everything that "
        f"isn't via {upstream.name})")
    killswitch.apply(iface=iface, upstream=upstream, lan_cidrs=lan_cidrs, bypass_ips=target_ips)

    # Per-persona netns internal routing — DNAT DNS+TCP-SYN inside the ns to
    # the gateway's per-persona Tor ports + default-DROP OUTPUT.
    if not persona.is_default(active_persona):
        log(f"step 7b/8 wiring netns internal iptables for persona '{active_persona}'")
        netns.setup_internal_routing(
            persona=active_persona,
            dns_port=tor.DNS_PORT,
            trans_port=tor.TRANS_PORT,
        )

    log("step 8/8  verify")
    hard_leak = False
    leak_detail = ""
    if args.dry_run:
        # Nothing was applied, so any "leak" the probes see is just the
        # unmodified host. Report the limit instead of faking a failure.
        log("[dry] verification skipped — a dry run cannot prove leak-freedom; "
            "run a real engage to verify", "warn")
    elif persona.is_default(active_persona):
        time.sleep(3)
        result = leaktest.run()
        hard_leak = result.hard_leak
        if hard_leak:
            leaks = []
            if result.clearnet_leak:
                leaks.append("clearnet reachable as your real IP")
            if result.dns_leak:
                leaks.append("DNS resolving via your real IP")
            if result.ipv6_leak:
                leaks.append("IPv6 stack still reachable")
            if result.udp_leak:
                leaks.append("non-DNS UDP escaping the kill-switch")
            leak_detail = "; ".join(leaks)
        elif upstream.name == "tor" and not result.tor_confirmed:
            log("Tor exit not yet confirmed (circuit may still be building). "
                "Re-run `snow leaktest` to confirm before doing anything "
                "sensitive.", "warn")
    else:
        # The operator's apps run inside the persona's netns — verify THERE,
        # not in the host netns. Re-invoke `snow leaktest` inside the ns;
        # cmd_leaktest exits non-zero on a hard leak.
        time.sleep(3)
        log(f"verifying inside the netns for persona '{active_persona}'")
        rc = netns.exec_in(active_persona,
                           ["python3", str(ROOT / "snow.py"),
                            "--persona", active_persona, "leaktest"])
        hard_leak = (rc != 0)
        leak_detail = "see the in-netns leak report above"

    # Gate on the verification. A hard leak means the operator's real identity
    # is exposed RIGHT NOW — engage must NOT report success or open a browser.
    if hard_leak:
        log("HARD LEAK DETECTED — you are NOT anonymous: " + leak_detail, "err")
        log("NOT launching the browser. Run `snow restore` now, then investigate "
            "the leak before doing anything sensitive on this box.", "err")
        print(color("\n[x] ENGAGE FAILED VERIFICATION — leak detected (see leak report above)", "red"))
        return 1

    # If --duration was given, schedule auto-restore now. Done AFTER all the
    # state changes AND after the leak gate so a failed engage doesn't leave a
    # dangling timer. Skipped under --dry-run: there is no session to time out.
    if duration_seconds is not None and not args.dry_run:
        _schedule_autorestore(duration_seconds)

    # Auto-launch Mullvad Browser if found and not suppressed. Matches the
    # operator-expected "engage opens the browser" flow. We pass skip_gates=True
    # because we just verified engagement (steps 6-8) and ran leaktest in step 8.
    if not args.no_browser and not args.dry_run:
        if browser._find_browser():
            log("step 9/8  launching Mullvad Browser (suppress with --no-browser)")
            browser.launch(skip_gates=True)
        else:
            log("Mullvad Browser not found — skipping auto-launch. "
                "Set $SNOW_BROWSER or install it. Suppress this with --no-browser.", "warn")

    if args.target:
        print(color(f"\n[+] snow mode active (target bypass: {','.join(target_pins.keys())})", "green"))
        print(color("    Those FQDNs travel clearnet to their pinned IPs — everything else is forced through Tor.", "yellow"))
    else:
        print(color("\n[+] snow mode active — run `snow rotate` for a new circuit, `snow restore` to revert", "green"))
    return 0


def cmd_rotate(_args: argparse.Namespace) -> int:
    require_root()
    rotate.new_circuit()
    time.sleep(2)
    leaktest.run(quick=True)
    return 0


def cmd_leaktest(args: argparse.Namespace) -> int:
    # Exit non-zero on a hard leak so `snow leaktest` is usable as a gate
    # in scripts and so engage can verify a persona's netns via this path.
    result = leaktest.run(quick=args.quick)
    return 1 if result.hard_leak else 0


def cmd_restore(_args: argparse.Namespace) -> int:
    require_root()
    restore.rollback()
    return 0


def cmd_mac(args: argparse.Namespace) -> int:
    require_root()
    iface = args.iface or _default_iface()
    if args.restore:
        mac.restore(iface)
    else:
        mac.randomize(iface)
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    iface = args.iface or _default_iface()
    baseline.capture(iface)
    return 0


def cmd_browser(args: argparse.Namespace) -> int:
    """Launch Mullvad Browser, gated on snow being engaged and egress healthy."""
    return browser.launch(extra_args=args.browser_args)


def cmd_persona(args: argparse.Namespace) -> int:
    """Persona management: create, delete, list."""
    if args.persona_cmd == "list":
        banner("SNOW :: personas")
        persona.render(persona.list_all())
        return 0
    if args.persona_cmd == "create":
        try:
            persona.create(args.name)
        except (ValueError, FileExistsError) as e:
            log(f"persona create: {e}", "err")
            return 1
        return 0
    if args.persona_cmd == "delete":
        require_root()
        try:
            persona.delete(args.name, force=args.force)
        except (ValueError, FileNotFoundError, RuntimeError) as e:
            log(f"persona delete: {e}", "err")
            return 1
        return 0
    if args.persona_cmd == "shell":
        require_root()
        if not netns.netns_exists(args.name):
            log(f"netns for persona '{args.name}' does not exist. "
                f"Run `sudo snow persona create {args.name}` first.", "err")
            return 1
        log(f"entering netns for persona '{args.name}' — exit to return to host shell")
        return netns.exec_in(args.name, [args.shell])
    log(f"unknown persona subcommand: {args.persona_cmd}", "err")
    return 2


def main() -> int:
    p = argparse.ArgumentParser(prog="snow", description="Anonymity / OPSEC toolkit for Kali")
    p.add_argument("-v", "--version", action="version", version=f"snow {VERSION}")
    p.add_argument("--dry-run", action="store_true",
                   help="print intended subprocess calls without executing them. "
                        "Note: file writes (journal, baseline) still happen; this is "
                        "a 'preview the iptables-level intent' mode, not a full sandbox.")
    # --persona is pre-parsed before imports (see top of this file). Argparse
    # consumes it here too so it doesn't trip on it; the env var is what
    # actually steers util.STATE_DIR.
    p.add_argument("--persona", default=None,
                   help="select operating persona (state isolated under state/personas/<name>/). "
                        "Default = 'default' (legacy state/ dir). Use `snow persona list` to see "
                        "available personas, `snow persona create <name>` to make one.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status",   help="show current network identity + journal")
    s.add_argument("--iface", default=None, help="network iface (default: auto-detect)")
    s.add_argument("--no-public-ip", action="store_true",
                   help="skip the 3 clearnet HTTPS probes used to fetch baseline public IP")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("doctor",   help="pre-flight diagnostics — run before engage")
    s.add_argument("--iface", default=None, help="network iface (default: auto-detect)")
    s.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("engage",   help="enable full snow mode")
    s.add_argument("--iface", default=None, help="network iface (default: auto-detect)")
    s.add_argument("--lan", default="",
                   help="comma-separated LAN CIDR(s) to bypass (default: auto-detect from iface)")
    s.add_argument("--target", action="store_true",
                   help="bypass --target-fqdn endpoints clearnet so a chosen comms partner "
                        "(your chat / API / control plane) stays reachable while engaged. "
                        "Trade: those endpoints see your real source IP.")
    s.add_argument("--target-fqdn", default=DEFAULT_TARGET_FQDNS,
                   help="comma-separated FQDNs to pin + bypass when --target is set. "
                        "Falls back to $SNOW_TARGET_FQDN. Example: "
                        "--target-fqdn signal.org,api.signal.org")
    s.add_argument("--upstream", default=None,
                   help="egress mechanism: 'tor' (default), 'tor:exit_country=us,ca', "
                        "'wg:CONFIG_NAME' (resolves to /etc/wireguard/<name>.conf), or "
                        "'wg:/abs/path/config.conf'. WireGuard requires an operator-"
                        "supplied wg-quick config (e.g. from Mullvad/IVPN/AzireVPN).")
    s.add_argument("--exit-country", default=None,
                   help="DEPRECATED in favor of --upstream tor:exit_country=...; kept for "
                        "backward compat. 2-letter ISO country codes (e.g. us,ca,gb). "
                        "Implies StrictNodes 1.")
    s.add_argument("--duration", default=None,
                   help="auto-restore after this duration (h/m/s suffixes; e.g. 4h, 30m, "
                        "1h30m). Uses systemd-run --on-active for the timer. Forces a "
                        "shorter engaged window = less correlation surface.")
    s.add_argument("--skip-doctor", action="store_true",
                   help="skip the pre-flight diagnostic. Don't use unless you know "
                        "what's failing and have already accepted it.")
    s.add_argument("--no-browser", action="store_true",
                   help="don't auto-launch Mullvad Browser after engage completes "
                        "(by default snow launches it if found, dropping privileges "
                        "to the invoking user via SUDO_USER).")
    s.set_defaults(fn=cmd_engage)

    s = sub.add_parser("circuit",  help="show current Tor circuit(s)")
    s.set_defaults(fn=cmd_circuit)

    s = sub.add_parser("rotate",   help="request new Tor circuit / exit node")
    s.set_defaults(fn=cmd_rotate)

    s = sub.add_parser("leaktest", help="check IP / DNS / IPv6 leaks")
    s.add_argument("--quick", action="store_true")
    s.set_defaults(fn=cmd_leaktest)

    s = sub.add_parser("restore",  help="revert everything from the journal")
    s.set_defaults(fn=cmd_restore)

    s = sub.add_parser("mac",      help="MAC submodule")
    s.add_argument("--iface", default=None, help="network iface (default: auto-detect)")
    s.add_argument("--restore", action="store_true")
    s.set_defaults(fn=cmd_mac)

    s = sub.add_parser("baseline", help="snapshot current identity")
    s.add_argument("--iface", default=None, help="network iface (default: auto-detect)")
    s.set_defaults(fn=cmd_baseline)

    s = sub.add_parser("browser",  help="launch Mullvad Browser (gated on engage + leak check)")
    s.add_argument("browser_args", nargs="*", help="extra args passed through to Mullvad Browser")
    s.set_defaults(fn=cmd_browser)

    sp = sub.add_parser("persona",  help="manage named identity slots with isolated state")
    sp_sub = sp.add_subparsers(dest="persona_cmd", required=True)
    sp_list = sp_sub.add_parser("list", help="show all personas + current selection")
    sp_create = sp_sub.add_parser("create", help="create a new persona's state dir")
    sp_create.add_argument("name", help="persona name (alphanumeric + dash/underscore, max 32 chars)")
    sp_delete = sp_sub.add_parser("delete", help="wipe a persona's state dir")
    sp_delete.add_argument("name", help="persona to delete")
    sp_delete.add_argument("--force", action="store_true",
                           help="delete even if persona has an active journal (dangerous — "
                                "may orphan iptables/sysctl state)")
    sp_shell = sp_sub.add_parser("shell", help="drop into a shell inside the persona's netns")
    sp_shell.add_argument("name", help="persona name")
    sp_shell.add_argument("--shell", default="/bin/bash", help="shell binary (default /bin/bash)")
    sp.set_defaults(fn=cmd_persona)

    args = p.parse_args()
    _validate_active_persona()
    if args.dry_run:
        set_dry_run(True)
        log("dry-run: subprocess calls will be printed instead of executed", "warn")
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        print(color("\n[!] interrupted", "red"))
        return 130


if __name__ == "__main__":
    sys.exit(main())
