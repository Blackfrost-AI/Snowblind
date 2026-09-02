# Snowblind

```
 ____  _   _  _____        ______  _     ___ _   _ ____
/ ___|| \ | |/ _ \ \      / / __ )| |   |_ _| \ | |  _ \
\___ \|  \| | | | \ \ /\ / /|  _ \| |    | ||  \| | | | |
 ___) | |\  | |_| |\ V  V / | |_) | |___ | || |\  | |_| |
|____/|_| \_|\___/ \_/\_/  |____/|_____|___|_| \_|____/
```

**Linux anonymity / OPSEC toolkit by [Blackfrost-AI](https://github.com/Blackfrost-AI).
One command to turn a Linux host into an anonymous-by-default Tor client with a
kill switch, and one command to verify it actually works.** The project ships a
single CLI: `snow`. Authorized use only — on systems you own or have written
permission to test. See [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).

## What it does

| Layer | Action |
|---|---|
| L2  | MAC address spoofed every session (`macchanger -A`) |
| L3  | IPv6 stack disabled — no parallel non-Tor path |
| L3.5 | Default-DROP `OUTPUT` policy: only Tor's UID + loopback + (optional) LAN escape |
| L4  | All TCP forced through Tor's `TransPort` via NAT REDIRECT |
| L7  | All DNS (53/udp + 53/tcp) forced through Tor's `DNSPort` |
| ID  | Hostname rotated to a generic DHCP-blend value |
| Ctl | `SIGNAL NEWNYM` on demand for fresh circuit / exit |
| Tgt | Optional clearnet bypass for chosen comms FQDNs (chat, API, control plane) |
| Vfy | Self-test against `check.torproject.org` + clearnet probes |
| Rst | Full journal-based restore returns the box to baseline |
| Up  | Pluggable **upstream**: Tor (default) or WireGuard via operator-supplied wg-quick config |
| Ns  | **Per-persona network namespaces** — engagement A and engagement B share zero kernel network state |

## Install

```bash
git clone https://github.com/Blackfrost-AI/Snowblind.git
cd Snowblind
sudo bash install.sh
```

The install also drops `/etc/tmpfiles.d/snow-tor.conf` so `/run/tor` is
recreated on every boot. Snowblind disables the system `tor.service` (to free
Tor's port for its own instance), and that service is what normally creates
`/run/tor` — without the tmpfiles drop, Tor would fail to write its PidFile
on the next reboot and bootstrap would silently time out.

Tested on Kali / Debian-family with systemd, NetworkManager, and netfilter
(iptables-nft). PRs welcome for other distros.

## Usage

```bash
sudo snow doctor                # pre-flight checks — run this before engage
sudo snow status                # current MAC / hostname / public IP / IPv6 / DNS / journal
sudo snow engage                # full lockdown: every byte through Tor or dropped
sudo snow engage --target \
     --target-fqdn signal.org    # same, but signal.org travels clearnet (see below)
sudo snow engage \
     --upstream wg:mullvad-se \  # WireGuard egress instead of Tor
     --duration 4h               # auto-restore after 4 hours via systemd-run
sudo snow engage \
     --upstream chain:wg=mullvad-se,tor   # WG then Tor on top (residential-VPN-fronted Tor)
sudo snow circuit               # show current guard/middle/exit hops (Tor upstream only)
sudo snow leaktest              # IsTor=true, clearnet blocked, IPv6 off, DNS via Tor
sudo snow rotate                # request fresh circuit / new exit node
sudo snow browser               # launch Mullvad Browser (refuses unless engaged)
sudo snow restore               # journal replay; box back to pristine state
sudo snow --dry-run engage      # preview the iptables/sysctl calls without firing them
```

### `snow browser` and auto-launch on engage

`sudo snow engage` auto-launches Mullvad Browser as its final step (step 9/8)
if a Mullvad Browser binary is found on the box. Suppress with `--no-browser`.

`sudo snow browser` launches it standalone, gated on:
1. Snowblind is engaged (journal contains an active engage)
2. A quick egress check passes (SOCKS reachable)

**Privilege drop:** when Snowblind runs under `sudo` (it has to, for iptables/
sysctl), the browser cannot inherit the root environment — `sudo` strips
`DISPLAY` and `XAUTHORITY`, so a root-spawned browser silently fails to
find the X server. Snowblind detects `SUDO_USER`, reconstructs the user's
session env (`DISPLAY` from `who`, `XAUTHORITY` from `~/.Xauthority`,
`XDG_RUNTIME_DIR`/`WAYLAND_DISPLAY`/`DBUS_SESSION_BUS_ADDRESS` from
`/run/user/<uid>/`), and drops privileges to that user via `preexec_fn`
before exec'ing the browser.

**Browser logs:** stdout and stderr land at `state/logs/browser-stdout.log`
and `browser-stderr.log` (NOT `/dev/null`, which is the right answer for a
"silently fails" debug story). If the browser exits within 2s, Snowblind
surfaces the last 15 lines of stderr.

Override the binary path with `$SNOW_BROWSER`. Default search:
`~/.local/share/mullvad-browser/Browser/start-mullvad-browser`, then
`~/mullvad-browser/...`, then `/opt/mullvad-browser/...`, then `$PATH`.
Under sudo, `~` is expanded against `SUDO_USER`'s `$HOME`, not `/root`.

### Personas — isolated identity slots

Each named persona has its own state directory (journal, baseline, backups,
browser profile, logs) AND its own Linux network namespace. Engagement A
and engagement B can be operated from the same physical box without
cross-contaminating either bookkeeping or kernel network state.

```bash
sudo snow persona create acme-h1     # state dir + netns + veth + NAT MASQUERADE
sudo snow persona list               # show all personas, current selection, ENGAGED flag

# operate under a persona
sudo snow --persona acme-h1 engage   # Tor binds per-persona gateway ports
sudo snow --persona acme-h1 browser  # Mullvad Browser launches inside the netns
sudo snow --persona acme-h1 leaktest
sudo snow --persona acme-h1 restore  # unwind iptables/sysctl; netns persists

# investigate inside the netns
sudo snow persona shell acme-h1      # drops into bash inside the namespace
# inside: `ip addr`, `ip route`, `curl https://check.torproject.org/api/ip`

# tear it down
sudo snow persona delete acme-h1     # refuses if active journal; --force overrides
```

**Architecture per non-default persona:**

```
host netns                              snow-ns-acme-h1
+----------+    veth pair          +----------+
| sv-xx-h  |<--------------------->| sv-xx-n  |    apps:
| 10.x.y.1 |                       | 10.x.y.2 |    - Mullvad Browser
+----------+                       +----------+    - curl, dig, etc.
   |                                   |
   |                                   default route -> 10.x.y.1
   v                                   ns iptables:
Tor                                      nat OUTPUT: DNS -> gw:5353
  bound 127.0.0.1:9050/5353/9040                    TCP-SYN -> gw:9040
  AND  10.x.y.1:9050/5353/9040           filter OUTPUT: default DROP
                                                     except lo + ESTABLISHED + d=gw
host iptables:
  POSTROUTING MASQUERADE 10.x.y.0/30 via <host_default_iface>
  FORWARD ACCEPT veth_h
```

**State layout:**

```
state/                          'default' persona (legacy, backward-compat)
    journal.json
    baseline.json
    backups/                    iptables-save + /etc/hosts snapshots
    logs/                       browser stdout/stderr
state/personas/acme-h1/         named persona
    journal.json
    baseline.json
    backups/
    logs/
    browser/                    per-persona MB profile (future v0.7 wiring)
```

**Subnet allocation:** SHA-256(persona_name)[:6] modulo 253 + 1 → octet
in 10.200.<octet>.0/30. Deterministic so the same persona always gets
the same subnet; collisions probabilistically unlikely (253 slots).

**Tor binding:** when `--persona <name>` is set, `tor.write_config`
emits SocksPort/DNSPort/TransPort bound to the persona's gateway IP
in addition to 127.0.0.1. One Tor instance serves both the host
namespace and the active persona's namespace simultaneously.

**Constraint:** only one persona can be engaged at a time — Tor binds
to a single persona's gateway IP per `engage`. Switch personas by
running `restore` first, then `engage` under the new persona.

**Backward compat:** `--persona` unset = 'default' persona = host
namespace path. Behaves exactly as v0.5.1 did. Existing installations
upgrading to v0.6.0 see no behavior change until they explicitly
create a named persona.

### `--upstream` — Tor or WireGuard egress

`engage` defaults to Tor egress. For ops where Tor is the wrong shape — bug
bounty against WAF-protected targets that block Tor exits, red-team work
that should blend with normal residential VPN users, sustained-bandwidth
engagements — pass a different upstream:

```bash
# default Tor (same as before)
sudo snow engage

# Tor with exit pinned to specific countries
sudo snow engage --upstream "tor:exit_country=us,ca"

# WireGuard — operator-supplied wg-quick config
sudo cp ~/Downloads/mullvad-se.conf /etc/wireguard/mullvad-se.conf
sudo snow engage --upstream wg:mullvad-se
#                 ^^^^^^^^^^^^^^^^^^^^^^^^^
#                 resolves /etc/wireguard/mullvad-se.conf

# WireGuard via absolute path
sudo snow engage --upstream wg:/etc/wireguard/ivpn-de.conf
```

The kill-switch, journal, restore, and target-FQDN-bypass discipline is
identical regardless of upstream. Only the egress mechanism varies:

| Upstream | Egress mechanism | Killswitch authorizes | Transproxy |
|---|---|---|---|
| `tor` (default) | local Tor daemon on 9040/5353 | `--uid-owner debian-tor` | TCP-SYN → 9040, DNS → 5353 |
| `wg:<name>` | wg-quick on iface `snow-wg` | `-o snow-wg` | skipped (kernel routes handle it) |

**Trust tradeoff:** with WireGuard, the VPN provider sees your real IP and
destinations. Provider matters — Mullvad/IVPN/AzireVPN have strong no-logs
records; budget providers may not. Pair with operator-anonymous payment.

**Chain upstream — WG then Tor on top:**

```bash
sudo snow engage --upstream "chain:wg=mullvad-se,tor"
# or with Tor exit pinning
sudo snow engage --upstream "chain:wg=mullvad-se,tor:exit_country=us"
```

The chain brings up WireGuard first, then starts Tor on top — Tor's
guard-relay traffic exits through the WG tunnel. Net effect:
- ISP sees only WG traffic to the VPN provider
- VPN provider sees only Tor traffic (no destination plaintext)
- Tor exits see only the VPN exit IP, never your real ISP

Tradeoff: stacked latency, and an adversary controlling *both* the VPN
provider and the Tor guards can still correlate you. Don't use chain
when Tor alone is the right egress; the VPN layer just costs latency.

### `snow doctor`

Pre-flight read-only diagnostic. Surfaces every catchable cause of a broken
engage *before* the kill-switch arms. `engage` runs doctor automatically and
refuses to proceed on any `fail`; `--skip-doctor` overrides.

Checks: deps installed (`tor`, `macchanger`, `iptables`, `dig`, `conntrack`,
`curl`, `jq`, `runuser`), `debian-tor` user exists, `/run/tor` present and
owner-correct, default route + iface, system resolver responsive, the four Tor
ports (9050/5353/9040/9051) free of conflict, avahi-daemon not on 5353, NTP
synchronized, NetworkManager management of the iface, `nf_conntrack` kernel
module, IPv6 sysctl knobs present.

### `--exit-country` and `--duration`

`--exit-country us,ca,gb` plumbs to Tor's `ExitNodes` directive with `StrictNodes 1`
— Tor will refuse to fall back to exits outside the listed countries. Useful when
a program requires geo-bounded egress or you want to avoid specific jurisdictions.

`--duration 4h` schedules a one-shot `snow restore` via `systemd-run --on-active`
to fire when the duration elapses. Forces shorter engaged windows = less
correlation surface, prevents the "I forgot I was engaged and now my chat client
has been confused for 12 hours" failure mode. Cancelled automatically on an
earlier manual `snow restore`.

### `snow circuit`

Queries the ControlPort for current circuit status and prints the guard →
middle → exit hops with relay nicknames. Useful for confirming `--exit-country`
took effect, or for surfacing a stuck circuit before `snow rotate`.

### `--dry-run`

Global flag. When set, every subprocess call (iptables, sysctl, macchanger,
hostnamectl, etc.) is printed in magenta with `[dry]` prefix and returns success
without executing. System-file writes (`/etc/hosts`, `/etc/tor/torrc.snow`,
the ControlPort password file) and daemon starts (tor, wg-quick) are likewise
printed and skipped — a dry run does not mutate the host or start anything.
State-file writes under `state/` (journal, baseline) DO still happen, so a
dry-run engage leaves a journal you should `snow restore` after. This is
"preview the network-level intent," not a full sandbox.

### Hash-chained journal (tamper-evident)

Every `state/journal.json` entry carries `prev_hash` (the previous entry's
`entry_hash`, or `"GENESIS"` for the first) and `entry_hash` (SHA-256 over the
canonical JSON of the entry minus its own hash). `snow status` and `snow
restore` both verify the chain; tampering with any historical entry breaks the
chain at that index and surfaces a `!` warning. Restore proceeds anyway —
operators running restore are usually recovering, not adjudicating.

### Pass-throughs: `--target` (FQDN) and `--lan` (subnet)

`engage` is total lockdown. Real operations usually need *one or two* things
to stay reachable in the clear — your team chat, a ticketing API, a
self-hosted model server on the lab network, a control channel. Snowblind
gives you two precise tools for that; everything else still gets the full
Tor + kill-switch treatment.

**Hole by hostname — `--target --target-fqdn`:**

```bash
sudo snow engage --target --target-fqdn chat.example.com,api.example.com
# or persist via env
export SNOW_TARGET_FQDN=api.example.com,sync.example.com
sudo -E snow engage --target
```

How it works:
1. Resolves the FQDNs to A records **before** the killswitch arms
2. Pins them in `/etc/hosts` (so libc never re-resolves to a different CDN IP)
3. Inserts `RETURN` rules in the transproxy NAT chain for those IPs
4. Inserts `ACCEPT` rules in the killswitch filter chain for those IPs
5. Everything else still gets the full Tor + killswitch treatment

Literal IPv4 addresses are accepted the same way (`--target-fqdn 203.0.113.7`)
— useful when the endpoint has no stable name. Names are validated before
they touch `/etc/hosts`; anything with whitespace or weird characters is
refused.

**Hole by subnet — `--lan`:**

```bash
sudo snow engage --lan 10.10.20.0/24              # one trusted lab subnet
sudo snow engage --lan 192.168.1.0/24,10.8.0.0/24 # home LAN + an overlay net
```

Use this when the thing you need lives on a private network — a self-hosted
LLM endpoint with no public DNS can't be pinned by FQDN. `--lan` keeps the
whole named subnet clearnet-reachable (and out of the transproxy), so scope
it tightly: one subnet you control, not all of RFC1918. Loopback is always
bypassed; the physical LAN is auto-detected from the default iface unless
you override it.

**Recipes:**

| What you need reachable | How |
|---|---|
| Team chat / comms API (public) | `--target --target-fqdn chat.example.com` |
| Self-hosted LLM / internal tool on a private subnet | `--lan 10.10.20.0/24` |
| Self-hosted endpoint that resolves on your DNS | `--target --target-fqdn llm.corp.internal` |
| Management overlay while engaged | `--lan <overlay-cidr>` |
| Several of the above at once | combine the flags |

**Tradeoff:** everything you bypass sees your real source IP for the whole
engage. Bypass only endpoints that are *supposed* to know who you are — your
own infrastructure, your team's comms. Never bypass the target you're
testing, and prefer one narrow `--target-fqdn` over a wide `--lan`.

`snow restore` reverts the `/etc/hosts` pin from a journaled backup.

## Architecture

```
snow.py              CLI dispatch + argparse + --persona pre-parse + dry-run plumbing
modules/
  util.py             shell / log / hash-chained journal / persona-aware STATE_DIR /
                      colors / LAN-detect / dry-run / duration
  persona.py          named identity slot management (create/delete/list)
  netns.py            Linux network-namespace lifecycle + veth pair + MASQUERADE
                      + per-persona internal iptables (DNAT to gateway-Tor ports)
  doctor.py           pre-flight diagnostic (deps, ports, user, time, NM, kernel,
                      persona-netns presence)
  baseline.py         pre-engage snapshot
  mac.py              macchanger wrapper (post-randomize verify when NM-managed)
  host.py             hostname rotation
  ipv6.py             sysctl IPv6 kill
  tor.py              torrc gen + start + ExitNodes + ControlPort circuit query
                      (SOCKS 9050, DNS 5353, Trans 9040, Ctrl 9051)
  upstream/
    __init__.py       Upstream protocol + from_spec() factory
    tor.py            Tor adapter (wraps modules/tor.py into Upstream interface)
    wireguard.py      WireGuard upstream (wg-quick, peer-handshake verification)
  hostsfile.py        /etc/hosts pin/unpin for --target FQDNs
  transproxy.py       NAT redirects via named `snow-trans` chain (upstream-aware;
                      no-op for upstreams that route via kernel routes)
  killswitch.py       filter DROP policy via named `snow-killswitch` chain;
                      two-phase arm (prelock before upstream start, finalize +
                      conntrack flush after); authorizes by upstream UID
                      and/or egress iface
  rotate.py           NEWNYM over ControlPort
  leaktest.py         IP / DNS / IPv6 verification (real DNS leak test via dig)
  restore.py          journal replay in reverse (cancels any pending duration timer)
state/
  baseline.json       pre-engage snapshot
  journal.json        every state change, hash-chained (prev_hash + entry_hash)
  backups/            iptables-save + /etc/hosts snapshots (survive reboot)
```

## Threat model & limits

- Transparency tool, not malware. Doesn't try to evade host-based detection.
- Doesn't defeat **browser fingerprinting** — pair with Tor Browser, Mullvad
  Browser, or a hardened Firefox profile (arkenfox + `privacy.resistFingerprinting`).
- Doesn't anonymize traffic that bypasses netfilter — raw sockets from root,
  out-of-tree kernel modules, VPN clients that install their own routes.
- Bridges / obfs4 / meek not wired in by default. Add a `Bridge` block to
  `modules/tor.py:write_config` for censored networks.
- **Non-DNS UDP is silently dropped, not anonymized.** The transproxy only
  REDIRECTs DNS (UDP 53) and TCP-SYN. QUIC / WebRTC STUN / NTP / multicast
  hit the killswitch. No leak, but expect HTTP/3 to fall back to TCP and
  some chat clients to chirp about connectivity.
- The killswitch keeps LAN reachable on purpose so the host stays SSH-able.
  Pass `--lan ""` to disable LAN bypass entirely, or tighten with
  `--lan 192.168.50.0/24`.
- **Tor Browser bundles its own Tor.** Running it while Snowblind is engaged
  creates a Tor-over-Tor loop that breaks both. Use one or the other, not
  both. (Mullvad Browser is Tor Browser with the bundled tor stripped out —
  pair that with Snowblind for fingerprint resistance + system-wide Tor.)
- **Pre-existing TCP connections are re-evaluated, not retroactively
  anonymized.** `engage` flushes the conntrack table (`conntrack -F`) so any
  open clearnet TCP flow has to re-establish through the new ruleset. If the
  `conntrack` binary is missing (warning will fire), pre-existing flows
  continue to traffic via the ESTABLISHED-allow rule until they tear down
  on their own. Close long-lived sessions (SSH, IRC, persistent websockets)
  before `engage` if conntrack isn't available.
- **The engage window is closed by a pre-engage lock.** The kill-switch arms
  in two phases: `prelock` (step 6/8) installs the full DROP policy *before*
  the upstream daemon starts, so Tor's bootstrap (~10-45s) drops new
  connections from every other process instead of letting them egress
  clearnet. Only the upstream's own traffic (its UID, the WG iface, and the
  WG endpoint UDP — pre-resolved at config time), loopback, DHCP, and the
  configured LAN/target bypasses may leave. `apply` (step 7d/8) then flushes
  conntrack so nothing sails through on a stale ESTABLISHED entry. Residual
  exposure: flows already ESTABLISHED *before* `engage` ran keep working
  until that flush — close sensitive apps / browsers before running it. If
  the upstream fails to start, the lock is released automatically
  (`unwind`) so the box never bricks itself.
- **Wifi probe requests carry your previously-joined SSID list** — a
  fingerprint independent of the MAC. Out of scope for this tool. Mitigate at
  the wpa_supplicant / NetworkManager layer with `wifi.scan-rand-mac-address=yes`
  or by bringing wifi up only after MAC randomization.
- **Forensic trace on the local host.** Every iptables, sysctl, and hostname
  change goes through systemd-journald / kern.log. If the threat model
  includes someone with root on this box auditing what happened, Snowblind is
  loud in the journal. This is an anti-surveillance tool, not anti-forensic.

## Recommended browser pairing

Snowblind owns the **network** layer (IP, DNS, IPv6, killswitch). It does **not** touch the **browser** layer where most fingerprinting happens — UA, screen, fonts, canvas, WebGL, WebRTC, audio context. Pair Snowblind with a browser that handles those, or your IP is hidden but your browser is still uniquely identifiable.

### Best — Mullvad Browser  *(EFF Cover Your Tracks: non-unique, ~3M-user herd)*

[Mullvad Browser](https://mullvad.net/en/browser) is Tor Browser stripped of its bundled tor, designed to run through an external proxy. Pair it with `sudo snow engage --target`: Snowblind provides the Tor circuit, Mullvad Browser provides the Tor-Browser-quality fingerprint defense. You join the ~3-million-user Tor/Mullvad Browser herd.

```bash
V=15.0.12
curl -fL -o /tmp/mb.tar.xz     https://cdn.mullvad.net/browser/$V/mullvad-browser-linux-x86_64-$V.tar.xz
curl -fL -o /tmp/mb.tar.xz.asc https://cdn.mullvad.net/browser/$V/mullvad-browser-linux-x86_64-$V.tar.xz.asc
gpg --keyserver hkps://keys.openpgp.org --recv-keys EF6E286DDA85EA2A4BA7DE684E2C6E8793298290  # Tor Browser Developers
gpg --verify /tmp/mb.tar.xz.asc /tmp/mb.tar.xz
tar -C ~/.local/share -xJf /tmp/mb.tar.xz
ln -sf ~/.local/share/mullvad-browser/Browser/start-mullvad-browser ~/.local/bin/mullvad-browser
```

### Good — hardened Firefox  *(EFF Cover Your Tracks: strong protection, ~50K-user herd)*

Use [arkenfox user.js](https://github.com/arkenfox/user.js) in a dedicated profile with these overrides explicitly enabled (arkenfox leaves them commented for "breaks too many sites" reasons — opt in via `user-overrides.js`):

```javascript
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.resistFingerprinting.letterboxing", true);
user_pref("media.peerconnection.enabled", false);   // kill WebRTC
user_pref("webgl.disabled", true);
```

Familiar Firefox UX, full extension support, smaller herd than Mullvad. Note: RFP's `navigator.hardwareConcurrency=2` spoof and 13-font system list are stale in 2026 (most devices have 4+ cores; common font lists are shorter) — these axes actually *increase* uniqueness vs Mullvad Browser's choices. Expect "strong protection" but possibly "unique fingerprint" without further tuning.

### Don't — Tor Browser while Snowblind is engaged

Tor Browser bundles its own tor instance. Running it alongside `sudo snow engage` creates a Tor-over-Tor loop: Tor Browser's bundled tor tries to reach the real Tor network, but snow's transproxy REDIRECTs that traffic into *snow's* tor, which then tries to relay it. Bootstrap fails in both. Use Mullvad Browser if you want Tor Browser's fingerprint resistance — same defenses, no bundled tor to fight Snowblind.

## Interactions with hardened hosts

- **UFW (nftables backend)**: Snowblind calls raw `iptables` but installs into
  named chains (`snow-trans`, `snow-killswitch`) and snapshots filter+nat
  state to `state/backups/` before any change. UFW INPUT rules survive an
  engage→restore cycle intact. The `snow-killswitch` chain self-terminates
  in `-j DROP` — it does NOT `RETURN` to `OUTPUT`. This is deliberate: a
  RETURN would hand kill-switched packets back to `OUTPUT`, where UFW's
  `ufw-track-output` (`-m conntrack --ctstate NEW -j ACCEPT`) would accept
  them before the `-P OUTPUT DROP` policy is reached — a leak. Because the
  chain drops in place, the kill-switch is correct regardless of UFW. Note:
  snow's `-I OUTPUT 1` jump and our `-I INPUT 1` ESTABLISHED rule both
  insert at position 1, so the rule-number display in `ufw status numbered`
  shifts by one slot for the duration of engage.
- **fail2ban**: adds dynamic iptables rules. The backup→engage→restore can
  race with f2b, but f2b re-adds what it needs on the next trigger.
- **NetworkManager `wifi.mac-address=random`**: NM owns the wifi MAC and
  will overwrite anything macchanger sets. snow's mac module warns when it
  detects NM management. Prefer NM's built-in randomization for wifi; use
  macchanger for interfaces NM doesn't manage.
- **avahi-daemon**: binds UDP 5353 for mDNS, same port Snowblind gives to Tor's
  DNSPort. Disable with `systemctl disable --now avahi-daemon` if Tor refuses
  to start.

## Idempotency & safety

- `engage` is gated on Tor reaching `Bootstrapped 100%`. If Tor fails to
  bootstrap, the pre-engage lock is **released automatically** (`unwind`) —
  the box stays online so you can investigate. MAC / hostname / IPv6 changes
  already applied are reversible via `snow restore`.
- The kill-switch arms in two journaled phases (`prelock` before the
  upstream starts, `apply` after). State is tracked through the journal
  (`clean → prelocked → applied`, with `unwind` releasing a prelock), so
  running `engage` twice without a `restore` in between is a no-op — it
  won't corrupt backups or duplicate rules.
- `transproxy.apply()` refuses to run if its named chain already exists or
  if its journal entry is present.
- Backups live at `state/backups/`, not `/tmp`. They survive reboot, so a
  panic-restore on next boot will actually have something to replay.

## Security hardening notes (2026-09 review)

Result of a full code audit; all shipped in-tree:

- **Atomic system-file writes with creation-time modes.** `/etc/hosts`, the
  torrc, and especially the Tor ControlPort password file are written via a
  temp file opened with final permissions, fsynced, then `rename(2)`d into
  place. The old write-then-chmod left the plaintext control password briefly
  world-readable, and a crash mid-write could truncate a system file.
- **Journal survives corruption intact.** A malformed `journal.json` (crash,
  disk issue) used to be silently replaced by a fresh `GENESIS` chain on the
  next write — erasing the record of an engaged session. It is now
  quarantined to `journal.json.corrupt-<ts>` and `snow restore` /
  `snow status` say so loudly instead of misreporting "no journal".
- **Persona names validated at dispatch.** `--persona` / `$SNOW_PERSONA`
  feed `state/personas/<name>/` directly; an unchecked name containing `/`
  or `..` was a path traversal. Same charset rule as `persona create`.
- **Target FQDNs and `--lan` CIDRs validated** before they reach
  `/etc/hosts` or iptables — a whitespace-bearing FQDN could previously
  inject arbitrary hosts entries.
- **Leak-test false negatives closed:** the DNS-leak check compares
  Cloudflare TXT lines individually (a multi-string answer used to mask a
  leak), and a missing/stale baseline IP no longer renders a green
  "egressing via upstream" verdict — it reports the clearnet check as
  unverifiable.
- **Secrets at 0600:** WG config backups in `state/backups/` (they hold the
  tunnel private key and were 0644), journal + baseline (they hold your real
  IP/MAC/hostname), and browser logs. Tor's data dir is 0700.
- **`--dry-run` no longer stages WireGuard configs** into `/etc/wireguard` —
  the WG upstream wrote real system files during a dry run, contradicting
  the dry-run contract.
- **Browser-in-netns under sudo actually works now.** The old order
  (drop privileges via `preexec_fn`, then exec `ip netns exec`) ran
  `setns()` as an unprivileged user and always failed with EPERM. The
  launch now enters the netns as root and drops to the invoking user inside
  it via `runuser`.
- **Hostname rotation no longer substring-replaces in `/etc/hosts`.** On a
  box named `kali`, every line containing that substring was rewritten;
  only exact whitespace-delimited fields swap now.

## Authority

This is a transparency tool. Use it on systems you own, or systems you have
explicit written authorization to test. Don't break laws you don't want to
break. The author is not your lawyer.

## License

Apache-2.0 — see [LICENSE](LICENSE). Copyright © 2026 Blackfrost-AI.
