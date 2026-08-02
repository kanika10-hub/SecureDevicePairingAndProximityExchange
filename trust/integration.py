"""Adapters bridging the trust framework to the existing pairing/proximity protocol.

**No file outside `trust/` is modified.** The existing protocol keeps working exactly as before;
this module is opt-in.

The protocol reaches its peer store through one method -- `get_peer(peer_id)` returning a dict
or `None` (`proximity/proximity_protocol.py:165`, `:128`). `ProtocolPeerStore` implements that
same shape on top of a `TrustManager` and returns `None` for any device the active policy does
not currently trust. Because both `initiate_encounter` and `respond_to_encounter` already treat
`None` as `UnpairedPeerError`, revocation and expiry become enforceable at the session boundary
with no change to protocol code:

    manager = TrustManager(JsonTrustStore("trust_db.json"))
    peer_store = ProtocolPeerStore(manager)
    respond_to_encounter(transport, identity, peer_store, token)   # unchanged call site

A revoked peer is now rejected before the MAC is even computed, and the rejection is
indistinguishable on the wire from "never paired" -- which is the right answer: telling an
attacker "you were revoked" rather than "you are unknown" leaks the device's history.

Everything here that touches the crypto layer imports it **lazily, inside the function**. That
keeps the core `trust/` package importable with nothing but the standard library, so trust
logic can be unit-tested without `liboqs`, a BLE stack, or a webcam present.
"""
from __future__ import annotations

from typing import Any

from trust.models import DeviceRecord
from trust.trust_manager import TrustManager


class ProtocolPeerStore:
    """Drop-in replacement for `pairing.trust_store.TrustStore` backed by a `TrustManager`.

    Implements the read surface the proximity protocol relies on. Trust evaluation happens on
    every `get_peer` call, so a device revoked mid-run is refused on its very next encounter
    without restarting anything.

    Args:
        manager: The trust manager to consult.
        record_connections: When `True` (default), a successful `get_peer` for a trusted device
            does **not** stamp `last_connected_at` -- call `note_session_complete` after the
            handshake actually succeeds instead. The flag exists to make that ordering explicit
            and is honoured by `note_session_complete`; see `TrustManager.record_connection`
            for why stamping on attempt would be wrong.
    """

    def __init__(self, manager: TrustManager, record_connections: bool = True):
        self._manager = manager
        self._record_connections = record_connections

    def get_peer(self, peer_id: str) -> dict[str, Any] | None:
        """Return the peer's key material, or `None` if unknown or not currently trusted.

        The returned dict matches `pairing.trust_store.TrustStore.get_peer`'s shape exactly
        (`x25519_pub`, `mlkem_pub`, `fingerprint`, `paired_at`) so protocol code needs no
        changes, plus lifecycle fields the protocol ignores but callers may find useful.
        """
        record = self._manager.find_device(peer_id)
        if record is None or not self._manager.is_trusted(peer_id):
            return None
        return {
            "x25519_pub": record.x25519_pub,
            "mlkem_pub": record.mlkem_pub,
            "fingerprint": record.fingerprint,
            "paired_at": record.paired_at,
            "key_version": record.key_version,
            "alias": record.alias,
        }

    def is_paired(self, peer_id: str) -> bool:
        """Whether this peer is known *and* currently trusted."""
        return self.get_peer(peer_id) is not None

    def list_peers(self) -> list[str]:
        """Device ids of all currently trusted peers."""
        return [r.device_id for r in self._manager.list_devices() if self._manager.is_trusted(r.device_id)]

    def note_session_complete(self, peer_id: str) -> None:
        """Record a successful encounter. Call after the handshake completes, not before.

        Silently does nothing if the device vanished (e.g. removed concurrently) so a
        bookkeeping call can never fail a session that already succeeded.
        """
        if not self._record_connections:
            return
        if self._manager.find_device(peer_id) is not None:
            self._manager.record_connection(peer_id)


def register_paired_peer(
    manager: TrustManager,
    peer_info: dict[str, Any],
    fingerprint: str,
    alias: str | None = None,
    valid_for_seconds: float | None = None,
) -> DeviceRecord:
    """Register the peer dict produced by the pairing handshake.

    `pairing.pairing_protocol.respond_to_qr` and `complete_pairing` both return a `peer` dict
    (`device_id`, `x25519_pub`, `mlkem_pub`) alongside the computed fingerprint. This unpacks
    that pair into a trust record so the pairing flow needs no knowledge of this framework's
    field names.

    Args:
        manager: Trust manager to register into.
        peer_info: The `peer` dict from the pairing handshake.
        fingerprint: The safety number the handshake computed. Passed through verbatim -- this
            framework never recomputes it.
        alias: Optional human-facing name; defaults to the peer's `device_id`.
        valid_for_seconds: Optional trust lifetime from now.

    Returns:
        The stored record.

    Raises:
        DuplicateDeviceError: this peer is already registered.
        KeyError: `peer_info` is missing a required field.
    """
    return manager.register_device(
        device_id=peer_info["device_id"],
        x25519_pub=peer_info["x25519_pub"],
        mlkem_pub=peer_info["mlkem_pub"],
        fingerprint=fingerprint,
        alias=alias,
        valid_for_seconds=valid_for_seconds,
    )


def compute_pairing_fingerprint(
    local_device_id: str,
    local_x25519_pub: bytes,
    local_mlkem_pub: bytes,
    peer_info: dict[str, Any],
) -> str:
    """Compute a safety number by delegating to the existing pairing implementation.

    Provided for callers that need a fingerprint outside the pairing handshake (e.g. after a
    key rotation). It is a thin delegation to
    `pairing.pairing_protocol.compute_fingerprint` on purpose: reimplementing the digest here
    would fork the definition of a safety number, and two subtly different fingerprints for the
    same device pair is exactly the failure the human comparison step exists to catch.

    The import is deferred to call time so the rest of `trust/` stays free of crypto
    dependencies.
    """
    from pairing.pairing_protocol import compute_fingerprint

    return compute_fingerprint(
        local_device_id,
        local_x25519_pub,
        local_mlkem_pub,
        peer_info["device_id"],
        peer_info["x25519_pub"],
        peer_info["mlkem_pub"],
    )


def migrate_legacy_store(manager: TrustManager, legacy_store: Any) -> list[DeviceRecord]:
    """Copy records from a `pairing.trust_store.TrustStore` into a `TrustManager`.

    One-way migration for deployments already holding pairings in the original store. Peers
    already present in `manager` are skipped rather than overwritten, so re-running the
    migration is safe and cannot resurrect a device that was revoked after migrating.

    The legacy store has no lifecycle fields, so migrated devices start trusted with no expiry.
    `paired_at` is preserved from the legacy record; key version starts at 1.

    Args:
        manager: Destination.
        legacy_store: Any object with `list_peers()` and `get_peer(peer_id)` -- structurally
            typed so a test double works without importing the crypto-dependent original.

    Returns:
        The records created, in migration order.
    """
    migrated: list[DeviceRecord] = []
    for peer_id in legacy_store.list_peers():
        if manager.find_device(peer_id) is not None:
            continue
        legacy = legacy_store.get_peer(peer_id)
        if legacy is None:
            continue
        record = manager.register_device(
            device_id=peer_id,
            x25519_pub=legacy["x25519_pub"],
            mlkem_pub=legacy["mlkem_pub"],
            fingerprint=legacy["fingerprint"],
        )
        # Preserve the original pairing time rather than the migration time.
        record = manager.registry.update(peer_id, paired_at=legacy["paired_at"])
        migrated.append(record)
    return migrated
