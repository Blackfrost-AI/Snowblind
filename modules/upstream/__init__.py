"""Pluggable upstream — the egress mechanism that everything leaving the box
gets pushed through.

Why pluggable: Tor is the right upstream for some intended uses (research,
disclosure, threat-modeling) and the wrong one for others (bug bounty against
WAF-protected targets that block Tor exits; red-team work that wants to
blend with normal residential VPN users). The kill-switch, journal, restore,
and target-FQDN-bypass discipline is the same regardless of upstream — only
the egress mechanism varies.

Implementations:
    TorUpstream         — current default; SOCKS+DNS+Trans + Control via local tor
    WireGuardUpstream   — operator-provided wg-quick config (Mullvad/IVPN/AzireVPN)

Future:
    ChainUpstream(WG, Tor)  — WG -> Tor on top, residential-VPN-fronted Tor
    SocksUpstream(host:port) — talk through an external SOCKS5 (operator's bastion)
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Upstream(Protocol):
    """The contract every egress mechanism must satisfy.

    `name` is a stable short identifier (used in journals and logs).
    The lifecycle is: ensure_installed -> write_config -> start -> [usage] -> stop.
    """

    name: str

    def ensure_installed(self) -> None: ...
    def write_config(self) -> None: ...
    def start(self, timeout: int = 45) -> bool: ...
    def stop(self) -> None: ...

    # Transproxy hints — what the NAT chain needs to know to redirect into us.
    @property
    def needs_dns_redirect(self) -> bool: ...
    @property
    def trans_port(self) -> int | None: ...
    @property
    def dns_port(self) -> int | None: ...

    # Killswitch hints — what to permit through the default-DROP OUTPUT policy.
    def killswitch_owner_uids(self) -> list[int]: ...
    def killswitch_egress_ifaces(self) -> list[str]: ...

    # Explicit (proto, dst_ip, dport) accepts the kill-switch must add — e.g.
    # a WireGuard tunnel's encrypted packets to the VPN endpoint. Return []
    # for upstreams that need none.
    def killswitch_extra_accepts(self) -> list[tuple[str, str, int]]: ...

    # Verification — does egress actually leave through us?
    def verify_egress(self) -> dict: ...


def from_spec(spec: str | None, persona: str | None = None, **kwargs) -> Upstream:
    """Parse an `--upstream` spec string into an Upstream instance.

    Forms:
        None / "" / "tor"                -> TorUpstream (default)
        "tor:exit_country=us,ca"         -> TorUpstream with country pinning
        "wg:/etc/wireguard/mullvad.conf" -> WireGuard from absolute config path
        "wg:mullvad-se"                  -> WireGuard from /etc/wireguard/mullvad-se.conf

    `persona` plumbs through to upstreams that need per-persona binding
    (currently Tor — adds gateway-IP SocksPort/DNSPort/TransPort lines).

    Extra kwargs are passed to the concrete constructor. For Tor, recognized
    kwargs: exit_country.
    """
    spec = (spec or "tor").strip()

    if spec == "tor":
        from .tor import TorUpstream
        return TorUpstream(persona=persona, **kwargs)

    if spec.startswith("tor:"):
        params: dict[str, str] = {}
        for token in spec[4:].split(","):
            if "=" in token:
                k, v = token.split("=", 1)
                params[k.strip()] = v.strip()
        merged = {**kwargs, **params}
        from .tor import TorUpstream
        return TorUpstream(persona=persona, **merged)

    if spec.startswith("wg:"):
        from .wireguard import WireGuardUpstream
        return WireGuardUpstream(config=spec[3:])

    if spec.startswith("chain:"):
        # Parse "chain:wg=mullvad-se,tor" or "chain:wg=mullvad-se,tor:exit_country=us"
        body = spec[6:]
        params: dict[str, str] = {}
        for tok in body.split(","):
            tok = tok.strip()
            if not tok:
                continue
            if tok == "tor":
                params.setdefault("tor", "1")
            elif tok.startswith("tor:"):
                # tor:exit_country=us,ca — but commas already split it; need different parse
                # Workaround: chain accepts only single-country exit pinning via tor_exit=us
                kv = tok[4:]
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params["tor_" + k] = v
            elif tok.startswith("wg="):
                params["wg"] = tok[3:]
            elif "=" in tok:
                k, v = tok.split("=", 1)
                params[k] = v
        if "wg" not in params:
            raise ValueError("chain spec requires wg=<config_name_or_path>, e.g. "
                             "'chain:wg=mullvad-se,tor'")
        from .chain import ChainUpstream
        return ChainUpstream(
            wg_config=params["wg"],
            exit_country=params.get("tor_exit_country"),
        )

    raise ValueError(f"unknown upstream spec: {spec!r}. Valid forms: "
                     "tor | tor:exit_country=... | wg:CONFIG | chain:wg=CONFIG,tor")
