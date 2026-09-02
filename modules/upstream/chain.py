"""Chain upstream — WireGuard then Tor on top.

The operational shape: outbound traffic from non-Tor processes hits the
transproxy NAT REDIRECT into Tor's local TransPort. Tor reaches its guard
relay using the host's default route — which, because WireGuard is up,
goes through the WG tunnel to the VPN exit, and Tor then builds its
circuit from that VPN exit. Observed source IP at the target = a Tor
exit relay, but the entry-point to the Tor network is the operator's
WG provider, not the operator's real ISP.

Why this matters for the threat model:
- An adversary watching the operator's ISP sees only WireGuard traffic
  to the VPN provider (no Tor fingerprint).
- An adversary watching the VPN provider sees only Tor traffic (no
  destination plaintext).
- An adversary watching Tor exits sees only the VPN exit, not the
  operator's ISP.

Tradeoff: latency stacks (WG handshake + Tor circuit build), and a
compromise of *both* the VPN provider and Tor guards correlates the
operator. Don't use this if Tor alone is the right egress (disclosure
research, etc.); the added VPN layer just costs latency for no gain.

Constructor takes a WireGuard subspec (config name or path) and optional
Tor exit_country pinning. See modules/upstream/__init__.py:from_spec for
spec parsing.
"""
from __future__ import annotations

from ..util import journal_append, log
from . import tor as _tor_up
from . import wireguard as _wg_up


class ChainUpstream:
    name = "chain:wg+tor"

    def __init__(self, wg_config: str, exit_country: str | None = None):
        self.wg = _wg_up.WireGuardUpstream(config=wg_config)
        self.tor = _tor_up.TorUpstream(exit_country=exit_country)
        self._wg_started = False
        self._tor_started = False

    def ensure_installed(self) -> None:
        self.wg.ensure_installed()
        self.tor.ensure_installed()

    def write_config(self) -> None:
        # Stage configs for both; order doesn't matter for staging.
        self.wg.write_config()
        self.tor.write_config()

    def start(self, timeout: int = 60) -> bool:
        """Bring up WG first, verify handshake, then start Tor. Tor's
        bootstrap traffic will exit through WG since kernel routes are
        already in place by then.
        """
        log("chain: bringing up WireGuard layer")
        if not self.wg.start(timeout=20):
            log("chain: WG layer failed — aborting before starting Tor", "err")
            return False
        self._wg_started = True

        log("chain: WG up; bringing up Tor layer (will egress through WG)")
        if not self.tor.start(timeout=timeout):
            log("chain: Tor layer failed — tearing down WG", "err")
            self.wg.stop()
            self._wg_started = False
            return False
        self._tor_started = True

        journal_append({
            "module": "upstream", "subtype": "chain",
            "action": "start",
            "wg_iface": self.wg.iface,
            "tor_uid": "debian-tor",
        })
        return True

    def stop(self) -> None:
        # Reverse order: Tor first (so its in-flight circuits get to close
        # gracefully while WG is still up), then WG.
        if self._tor_started:
            self.tor.stop()
            self._tor_started = False
        if self._wg_started:
            self.wg.stop()
            self._wg_started = False

    @property
    def needs_dns_redirect(self) -> bool:
        # Tor's DNSPort is the resolver of record once the chain is up.
        return True

    @property
    def trans_port(self) -> int | None:
        return self.tor.trans_port

    @property
    def dns_port(self) -> int | None:
        return self.tor.dns_port

    def killswitch_owner_uids(self) -> list[int]:
        # Tor must be allowed to send to its guards (which goes via WG iface).
        return self.tor.killswitch_owner_uids()

    def killswitch_egress_ifaces(self) -> list[str]:
        # WG iface must be allowed so Tor's outbound packets can reach the guards.
        return self.wg.killswitch_egress_ifaces()

    def killswitch_extra_accepts(self) -> list[tuple[str, str, int]]:
        # The WG layer's encrypted packets to the VPN endpoint must be allowed.
        return self.wg.killswitch_extra_accepts()

    def verify_egress(self) -> dict:
        """Verify both layers. Tor's check.torproject.org test is the
        authoritative endpoint check (egress emerges from a Tor exit);
        WG handshake is the path-to-Tor check.
        """
        tor_v = self.tor.verify_egress()
        wg_v = self.wg.verify_egress()
        return {
            "via_upstream": tor_v.get("via_upstream", False),
            "observed_ip": tor_v.get("observed_ip", ""),
            "exit_info": {
                "chain": "wg+tor",
                "tor": tor_v.get("exit_info", {}),
                "wg": wg_v.get("exit_info", {}),
            },
        }
