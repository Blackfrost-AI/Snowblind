"""Force new Tor circuit via NEWNYM through the ControlPort."""
from __future__ import annotations

import socket
from pathlib import Path

from .util import log
from .tor import CONTROL_PORT, CONTROL_PW_FILE


def new_circuit() -> None:
    if not CONTROL_PW_FILE.exists():
        log("control password file missing — run `ghost engage` first", "err")
        return
    pw = CONTROL_PW_FILE.read_text().strip()
    try:
        with socket.create_connection(("127.0.0.1", CONTROL_PORT), timeout=5) as s:
            s.sendall(f'AUTHENTICATE "{pw}"\r\n'.encode())
            resp = s.recv(256).decode()
            if not resp.startswith("250"):
                log(f"AUTH failed: {resp.strip()}", "err")
                return
            s.sendall(b"SIGNAL NEWNYM\r\n")
            resp = s.recv(256).decode()
            if resp.startswith("250"):
                log("new circuit requested — Tor will pick a new exit", "ok")
            else:
                log(f"NEWNYM failed: {resp.strip()}", "err")
    except (ConnectionRefusedError, socket.timeout) as e:
        log(f"could not reach Tor ControlPort {CONTROL_PORT}: {e}", "err")
