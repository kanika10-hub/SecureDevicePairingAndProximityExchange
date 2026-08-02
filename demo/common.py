"""Shared helpers for demo/device_a.py and demo/device_b.py: per-device state paths and the
tiny length-framed socket helpers used only during --pair (proximity uses transport_wifi.py /
transport_ble.py instead, which have their own framing)."""
import os
import socket
import struct
import time
from pathlib import Path

from proximity.transport_wifi import WifiTransport

STATE_ROOT = Path(__file__).resolve().parent / "state"


def device_state_dir(device_id: str) -> Path:
    d = STATE_ROOT / device_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def log(device_id: str, message: str):
    print(f"[{time.strftime('%H:%M:%S')}] [{device_id}] {message}", flush=True)


def send_framed(conn: socket.socket, data: bytes):
    conn.sendall(struct.pack(">I", len(data)) + data)


def recv_framed(conn: socket.socket) -> bytes:
    length = struct.unpack(">I", _recv_exact(conn, 4))[0]
    return _recv_exact(conn, length)


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ConnectionError("connection closed before full message received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def make_transport(name: str):
    if name == "wifi":
        return WifiTransport()
    if name == "ble":
        from proximity.transport_ble import BleTransport

        return BleTransport()
    raise ValueError(f"unknown transport: {name}")


def resolve_passphrase(cli_value: str | None) -> str | None:
    """`--passphrase` on the command line wins; falls back to the `DEVICE_PASSPHRASE` env var
    (so you don't have to retype it, or leave it in shell history, on every command); `None`
    (no at-rest encryption -- the original behavior) if neither is set."""
    return cli_value or os.environ.get("DEVICE_PASSPHRASE") or None


def make_trust_manager(state_dir: Path):
    """Trust manager for one device's `trust_db.json`, backed by `trust/`'s revocation/expiry
    framework instead of the legacy binary `pairing/trust_store.py`.

    If this is the first time a given device's state dir is opened under the new store and an
    old `trust_store.json` already exists there (from pairing before this switch), migrates its
    peers in once so existing pairings survive the switch -- see
    `trust.integration.migrate_legacy_store`.
    """
    from trust import JsonTrustStore, TrustManager
    from trust.integration import migrate_legacy_store

    db_path = state_dir / "trust_db.json"
    is_new = not db_path.exists()
    manager = TrustManager(JsonTrustStore(db_path))

    if is_new:
        legacy_path = state_dir / "trust_store.json"
        if legacy_path.exists():
            from pairing.trust_store import TrustStore

            migrated = migrate_legacy_store(manager, TrustStore(legacy_path))
            if migrated:
                log(state_dir.name, f"migrated {len(migrated)} peer(s) from legacy trust_store.json into trust_db.json")

    return manager
