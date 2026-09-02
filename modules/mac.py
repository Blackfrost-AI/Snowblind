"""MAC randomization via macchanger."""
from __future__ import annotations

import time
from pathlib import Path

from .util import journal_append, log, sh


def _current_mac(iface: str) -> str:
    return Path(f"/sys/class/net/{iface}/address").read_text().strip()


def _nm_manages(iface: str) -> bool:
    """True if NetworkManager owns this iface — meaning it'll overwrite any MAC
    macchanger sets as soon as it reconfigures the link."""
    cp = sh(f"nmcli -t -f GENERAL.NM-MANAGED dev show {iface}", check=False)
    return cp.returncode == 0 and "yes" in cp.stdout.lower()


def randomize(iface: str = "wlan0") -> str:
    """Bring iface down, randomize MAC, bring back up. Returns the MAC that
    is actually live after the operation (which may differ from what
    macchanger set, if NetworkManager reverted it).
    """
    nm_owned = _nm_manages(iface)
    if nm_owned:
        log(f"{iface} is managed by NetworkManager — macchanger MAC may be "
            "overwritten on next link reconfigure. Prefer NM's wifi.mac-address=random "
            f"(set via /etc/NetworkManager/conf.d/) or `nmcli dev set {iface} managed no` first.", "warn")
    original = _current_mac(iface)
    log(f"current MAC on {iface}: {original}")
    sh(f"ip link set {iface} down")
    # -A = random vendor-valid MAC; safer than fully random (-r) which can hit unroutable OUIs
    sh(f"macchanger -A {iface}")
    sh(f"ip link set {iface} up")
    new = _current_mac(iface)

    if nm_owned:
        # Give NM a couple seconds to reconfigure the link, then re-read the MAC.
        # If it reverted, journal the actual live value (not the value macchanger
        # set) so restore() aims at the right "original" baseline later.
        time.sleep(2)
        live = _current_mac(iface)
        if live != new:
            log(f"NetworkManager reverted MAC: macchanger set {new} but iface "
                f"is now {live}. Use NM's wifi.mac-address=random or unmanage "
                f"{iface} first.", "err")
            new = live

    log(f"new MAC on {iface}: {new}", "ok")
    journal_append({
        "module": "mac",
        "action": "randomize",
        "iface": iface,
        "original": original,
        "new": new,
    })
    return new


def restore(iface: str = "wlan0") -> None:
    """Restore permanent (hardware) MAC."""
    sh(f"ip link set {iface} down")
    sh(f"macchanger -p {iface}")
    sh(f"ip link set {iface} up")
    log(f"restored permanent MAC on {iface}", "ok")
