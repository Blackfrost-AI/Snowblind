"""WireGuard upstream — operator-provided wg-quick config.

When to use this instead of Tor:
- Bug bounty against WAF-protected targets that block Tor exits (Cloudflare,
  Akamai often serve captchas / blocks to known Tor exits)
- Red team where you want to blend with normal residential VPN traffic, not
  stand out as Tor traffic
- Engagements requiring specific egress jurisdiction that Tor's relay
  geography can't reliably hit
- High-bandwidth sustained traffic (Tor's per-circuit throughput is limited)

Tradeoff: a WireGuard provider sees your real IP and your destinations.
Provider trust matters — Mullvad/IVPN/AzireVPN have strong no-logs records;
budget providers may not. Pair with operator-anonymous payment.

Operator supplies the wg-quick config — this module doesn't generate it.
Typical workflow:
    # Mullvad: download account-specific config from mullvad.net/en/account
    sudo cp ~/Downloads/mlvd-se-mma-wg-001.conf /etc/wireguard/mullvad-se.conf
    sudo snow engage --upstream wg:mullvad-se
"""
from __future__ import annotations

import shutil
import time
import urllib.request
from pathlib import Path

from ..util import backup_path, is_dry_run, journal_append, log, sh, write_system_file

WG_DIR = Path("/etc/wireguard")
SNOW_IFACE = "snow-wg"  # stable iface name regardless of source config name

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"


class WireGuardUpstream:
    name = "wireguard"

    def __init__(self, config: str):
        """`config` is either:
        - absolute path to a wg-quick .conf
        - bare name like 'mullvad-se' resolved to /etc/wireguard/<name>.conf

        Either way, we copy to /etc/wireguard/snow-wg.conf so the iface name
        is stable and our killswitch can match on it deterministically.
        """
        self.config_arg = config
        self._iface = SNOW_IFACE
        self._staged_config_backup: Path | None = None
        self._endpoint: tuple[str, int] | None = None

    @property
    def iface(self) -> str:
        return self._iface

    def ensure_installed(self) -> None:
        for tool in ("wg", "wg-quick"):
            if not shutil.which(tool):
                log("wg/wg-quick not installed — apt installing wireguard-tools")
                sh("apt-get install -y wireguard-tools", timeout=120)
                return

    def write_config(self) -> None:
        src = Path(self.config_arg)
        if not src.is_absolute():
            src = WG_DIR / f"{self.config_arg}.conf"
        if not src.exists():
            raise FileNotFoundError(f"WireGuard config not found: {src}")

        # Split-tunnel check. If the config does not route a default
        # (0.0.0.0/0), traffic outside AllowedIPs egresses clearnet with the
        # real IP — a leak the kill-switch cannot catch, because WG egress is
        # authorized by iface and that traffic never enters the tunnel iface.
        # Warn loudly; do not refuse (split tunnel is a valid operator choice,
        # just not one that delivers anonymity).
        _allowed = " ".join(
            ln for ln in src.read_text().splitlines()
            if ln.strip().lower().startswith("allowedips")
        )
        if "0.0.0.0/0" not in _allowed:
            log("WireGuard config has no 0.0.0.0/0 in AllowedIPs — this is a "
                "SPLIT TUNNEL: traffic outside AllowedIPs leaves clearnet with "
                "your real IP. Use a full-tunnel config for anonymity.", "warn")

        WG_DIR.mkdir(parents=True, exist_ok=True)
        dst = WG_DIR / f"{self._iface}.conf"

        # If our target already exists (prior engage), back it up — restore can
        # then put it back exactly as it was. Both the backup and the staged
        # config hold the tunnel's PRIVATE KEY: 0600 at creation via the
        # atomic writer (no write-then-chmod exposure window), and honoring
        # dry-run (the old direct write_text() staged a real /etc/wireguard
        # file during a --dry-run engage, contradicting its contract).
        if dst.exists() and dst.resolve() != src.resolve():
            bk = backup_path(f"{self._iface}.conf.save")
            write_system_file(bk, dst.read_text(), 0o600)
            self._staged_config_backup = bk

        if src.resolve() != dst.resolve():
            write_system_file(dst, src.read_text(), 0o600)
        else:
            dst.chmod(0o600)
        log(f"WG config staged at {dst} (source: {src.name})", "ok")
        # Resolve the peer endpoint NOW, while DNS still works: the pre-engage
        # kill-switch lock arms before `wg-quick up`, and the handshake's
        # encrypted UDP must already be in its allow list or the tunnel can
        # never come up. _resolve_endpoint() re-checks against the live iface
        # after the handshake and overwrites this.
        self._parse_endpoint_from_config(src)
        journal_append({
            "module": "upstream", "subtype": "wireguard",
            "action": "configure",
            "iface": self._iface,
            "config": str(dst),
            "source_config": str(src),
            "backup": str(self._staged_config_backup) if self._staged_config_backup else "",
        })

    def _parse_endpoint_from_config(self, src: Path) -> None:
        """Pull `Endpoint = host:port` out of the staged config and resolve it
        to an IPv4 while DNS is still usable (write_config runs before the
        pre-engage kill-switch lock)."""
        import socket
        try:
            text = src.read_text()
        except OSError:
            return
        for raw in text.splitlines():
            line = raw.strip()
            if not line.lower().startswith("endpoint") or "=" not in line:
                continue
            value = line.split("=", 1)[1].strip()
            host, _, port = value.rpartition(":")
            host = host.strip("[]")
            if not host or not port.isdigit():
                continue
            try:
                import ipaddress
                try:
                    ip_object = ipaddress.ip_address(host)
                    if ip_object.version != 4:
                        return  # IPv6 endpoint — stack is killed anyway
                    ip = host
                except ValueError:
                    ip = socket.gethostbyname(host)  # resolves A records only
            except OSError:
                log(f"could not resolve WG endpoint {host!r} — the pre-engage "
                    f"lock cannot allow the handshake UDP; tunnel start may "
                    f"time out", "warn")
                return
            self._endpoint = (ip, int(port))
            log(f"WG endpoint pre-resolved for the kill-switch: {ip}:{port}", "ok")
            return

    def start(self, timeout: int = 20) -> bool:
        if is_dry_run():
            log(f"[dry] would `wg-quick up {self._iface}` and verify handshake", "warn")
            return True
        cp = sh(["wg-quick", "up", self._iface], check=False)
        if cp.returncode != 0:
            log(f"wg-quick up failed (rc={cp.returncode}): {cp.stderr.strip() if cp.stderr else ''}", "err")
            return False

        # Confirm peer handshake within timeout — the iface is up but a route
        # without an established handshake is dead silicon.
        deadline = time.time() + timeout
        while time.time() < deadline:
            cp = sh(["wg", "show", self._iface, "latest-handshakes"], check=False)
            if cp.returncode == 0 and cp.stdout.strip():
                for line in cp.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) > 0:
                        log(f"WG handshake established on {self._iface}", "ok")
                        self._resolve_endpoint()
                        journal_append({
                            "module": "upstream", "subtype": "wireguard",
                            "action": "start", "iface": self._iface,
                        })
                        return True
            time.sleep(1)

        log(f"WG handshake timeout ({timeout}s) on {self._iface}", "err")
        # Bring it down so we don't leave a half-started iface
        sh(["wg-quick", "down", self._iface], check=False)
        return False

    def stop(self) -> None:
        sh(["wg-quick", "down", self._iface], check=False)
        log(f"WG stopped ({self._iface})", "ok")
        # Restore prior config if we replaced one
        if self._staged_config_backup and self._staged_config_backup.exists():
            dst = WG_DIR / f"{self._iface}.conf"
            write_system_file(dst, self._staged_config_backup.read_text(), 0o600)
            self._staged_config_backup.unlink()
            log(f"WG config restored from backup", "ok")

    @property
    def needs_dns_redirect(self) -> bool:
        # wg-quick sets the system DNS via the [Interface] DNS= line in the
        # config, so libc resolves through the VPN's DNS over the tunnel.
        # No transproxy DNS REDIRECT needed.
        return False

    @property
    def trans_port(self) -> int | None:
        # Kernel routing (added by wg-quick) pulls all outbound through the
        # tunnel; no NAT REDIRECT needed.
        return None

    @property
    def dns_port(self) -> int | None:
        return None

    def killswitch_owner_uids(self) -> list[int]:
        # WG has no service-uid to match; killswitch authorizes by iface.
        return []

    def killswitch_egress_ifaces(self) -> list[str]:
        return [self._iface]

    def _resolve_endpoint(self) -> None:
        """Record the peer's resolved endpoint IP:port after the tunnel is up.

        The kill-switch then ACCEPTs the encrypted WG packets to the VPN
        server explicitly. Those packets leave on the REAL iface as UDP;
        without an explicit accept they survive only as long as a conntrack
        ESTABLISHED entry, so an idle tunnel without PersistentKeepalive
        would be dropped once that entry expires.
        """
        cp = sh(["wg", "show", self._iface, "endpoints"], check=False)
        if cp.returncode != 0 or not cp.stdout.strip():
            return
        for line in cp.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            host, _, port = parts[1].rpartition(":")
            host = host.strip("[]")
            if host and port.isdigit():
                self._endpoint = (host, int(port))
                log(f"WG endpoint pinned for kill-switch: {host}:{port}", "ok")
                return

    def killswitch_extra_accepts(self) -> list[tuple[str, str, int]]:
        if self._endpoint is None:
            return []
        ip, port = self._endpoint
        return [("udp", ip, port)]

    def verify_egress(self) -> dict:
        """Direct HTTPS to an IP-echo service. If egress is via WG, the
        observed IP is the WG exit. Compare to baseline elsewhere for leak
        detection.
        """
        try:
            req = urllib.request.Request(
                "https://api.ipify.org",
                headers={"User-Agent": USER_AGENT},
            )
            with urllib.request.urlopen(req, timeout=8) as r:
                ip = r.read().decode().strip()
            # Also pull the latest handshake info for context
            hs = ""
            cp = sh(["wg", "show", self._iface, "latest-handshakes"], check=False)
            if cp.returncode == 0:
                hs = cp.stdout.strip()
            return {
                "via_upstream": bool(ip),
                "observed_ip": ip,
                "exit_info": {"iface": self._iface, "handshakes": hs},
            }
        except Exception as e:
            return {"via_upstream": False, "observed_ip": "", "exit_info": {"error": str(e)}}
