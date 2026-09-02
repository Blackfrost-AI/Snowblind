"""IPv6 kill. Tor doesn't route v6, so leaving it on is a leak.

Disabling only net.ipv6.conf.{all,default,lo} is not enough: NetworkManager
re-enables IPv6 per-interface (net.ipv6.conf.<iface>.disable_ipv6 = 0) every
time a connection comes up, so a real interface can carry live IPv6 while the
global knobs still read 1. We therefore enumerate every disable_ipv6 knob the
kernel exposes — all, default, lo, and one per interface — and disable each.
"""
from __future__ import annotations

from pathlib import Path

from .util import journal_append, log, sh

_CONF_DIR = Path("/proc/sys/net/ipv6/conf")
_GLOBAL_KNOBS = {
    "net.ipv6.conf.all.disable_ipv6",
    "net.ipv6.conf.default.disable_ipv6",
    "net.ipv6.conf.lo.disable_ipv6",
}


def _conf_knobs() -> list[str]:
    """Every `disable_ipv6` sysctl the kernel currently exposes — `all`,
    `default`, `lo`, and one per network interface. Enumerated live because
    the per-interface set changes as interfaces appear/disappear."""
    if not _CONF_DIR.is_dir():
        return []  # kernel built without IPv6
    return [f"net.ipv6.conf.{d.name}.disable_ipv6"
            for d in sorted(_CONF_DIR.iterdir())
            if (d / "disable_ipv6").exists()]


def _knob_value(knob: str) -> str | None:
    """Current value of a sysctl knob, or None if it no longer exists."""
    try:
        return Path("/proc/sys/" + knob.replace(".", "/")).read_text().strip()
    except OSError:
        return None


def fully_disabled() -> bool:
    """True only if IPv6 is disabled on EVERY knob (all/default/lo + every
    interface). A single knob reading anything other than '1' is a potential
    leak path — exactly the per-interface gap NetworkManager opens on
    reconnect. Used by `leaktest` and `status` so they can't be fooled by the
    global knobs alone."""
    knobs = _conf_knobs()
    if not knobs:
        return True  # no IPv6 stack at all
    return all(_knob_value(k) == "1" for k in knobs)


def disable() -> None:
    prev: dict[str, str] = {}
    for k in _conf_knobs():
        val = _knob_value(k)
        if val is None:
            continue
        prev[k] = val
        sh(f"sysctl -w {k}=1", check=False)
    n_iface = sum(1 for k in prev if k not in _GLOBAL_KNOBS)
    log(f"IPv6 disabled ({len(prev)} knobs: all/default/lo + "
        f"{n_iface} interface(s))", "ok")
    journal_append({"module": "ipv6", "action": "disable", "previous": prev})


def enable(previous: dict[str, str] | None = None) -> None:
    """Restore each knob recorded by disable() to its prior value. Iterates
    the recorded dict (not a static list) so per-interface knobs are reverted
    too; falls back to zeroing the live knob set if no record is available."""
    previous = previous or {}
    knobs = list(previous.keys()) or _conf_knobs()
    for k in knobs:
        sh(f"sysctl -w {k}={previous.get(k, '0')}", check=False)
    log("IPv6 re-enabled", "ok")
