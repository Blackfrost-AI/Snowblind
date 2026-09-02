"""Tor upstream — adapter over modules.tor that satisfies the Upstream protocol.

The underlying mechanics (torrc generation, S2K control-pw hash, bootstrap
polling with proc liveness, PID-based stop, ControlPort circuit query) live
in modules.tor. This file is a thin object face so the rest of the codebase
can talk to "an upstream" without caring whether it's Tor or WireGuard.
"""
from __future__ import annotations

from .. import tor as _tor


class TorUpstream:
    name = "tor"

    def __init__(self, exit_country: str | None = None, persona: str | None = None):
        self.exit_country = exit_country
        self.persona = persona

    def ensure_installed(self) -> None:
        _tor.ensure_installed()

    def write_config(self) -> None:
        _tor.write_config(exit_country=self.exit_country, persona=self.persona)

    def start(self, timeout: int = 45) -> bool:
        return _tor.start(timeout=timeout)

    def stop(self) -> None:
        _tor.stop()

    @property
    def needs_dns_redirect(self) -> bool:
        return True

    @property
    def trans_port(self) -> int | None:
        return _tor.TRANS_PORT

    @property
    def dns_port(self) -> int | None:
        return _tor.DNS_PORT

    def killswitch_owner_uids(self) -> list[int]:
        return [_tor.tor_uid()]

    def killswitch_egress_ifaces(self) -> list[str]:
        return []   # Tor uses uid-match, not iface-match

    def killswitch_extra_accepts(self) -> list[tuple[str, str, int]]:
        return []   # Tor's egress is authorized by uid; no explicit accepts

    def verify_egress(self) -> dict:
        # check.torproject.org via SOCKS — IsTor=true on the JSON means egress
        # is genuinely emerging through a Tor exit relay.
        from .. import leaktest
        info = leaktest._check_tor_exit()
        return {
            "via_upstream": info.get("IsTor") is True,
            "observed_ip": info.get("IP", ""),
            "exit_info": info,
        }
