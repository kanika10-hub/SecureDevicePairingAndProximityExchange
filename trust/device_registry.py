"""Device registry: CRUD over `DeviceRecord`s.

Single responsibility -- this class stores, retrieves, and mutates records. It makes **no trust
decisions**: it will happily return a revoked or expired record, because deciding what that
means is `trust_policy.TrustPolicy`'s job and gating on it is `trust_manager.TrustManager`'s.
Keeping the two apart is what lets the policy be swapped without touching storage, and lets the
registry be tested without a clock.

Consistency model: the full snapshot is held in memory under a re-entrant lock and written
through to the backend on every mutation. That makes multi-field updates (e.g. rotation, which
touches `current_key` and `key_history` together) atomic with respect to other threads, which a
read-modify-write against the file on each call would not be.
"""
from __future__ import annotations

import copy
import threading
from typing import Callable, Iterable

from trust.exceptions import DeviceNotFoundError, DuplicateDeviceError
from trust.models import (
    INITIAL_KEY_VERSION,
    DeviceRecord,
    KeyMaterial,
    new_uuid,
)
from trust.trust_store import TrustStoreBackend


class DeviceRegistry:
    """Owns the collection of known devices and every mutation to it.

    Args:
        backend: Persistence implementation. Injected rather than constructed here so callers
            choose durability (`JsonTrustStore`) or speed (`InMemoryTrustStore`).
    """

    def __init__(self, backend: TrustStoreBackend):
        self._backend = backend
        self._lock = threading.RLock()
        self._records: dict[str, DeviceRecord] = backend.load()

    # ------------------------------------------------------------------ internals

    def _flush(self) -> None:
        """Write the in-memory snapshot through to the backend. Caller must hold `_lock`."""
        self._backend.save(self._records)

    def _require(self, device_id: str) -> DeviceRecord:
        """Return the live record for `device_id` or raise. Caller must hold `_lock`."""
        record = self._records.get(device_id)
        if record is None:
            raise DeviceNotFoundError(device_id)
        return record

    def reload(self) -> None:
        """Discard the in-memory snapshot and re-read it from the backend.

        Only needed when another process may have written the same store.
        """
        with self._lock:
            self._records = self._backend.load()

    # ------------------------------------------------------------------ create

    def register(
        self,
        device_id: str,
        x25519_pub: bytes,
        mlkem_pub: bytes,
        fingerprint: str,
        paired_at: float,
        alias: str | None = None,
        expires_at: float | None = None,
        metadata: dict | None = None,
    ) -> DeviceRecord:
        """Add a newly paired device.

        Args:
            device_id: On-the-wire peer identifier; must be unique and non-empty.
            x25519_pub: Peer's long-term X25519 public key, as produced by pairing.
            mlkem_pub: Peer's long-term ML-KEM-768 public key.
            fingerprint: Safety number computed by the pairing protocol. Stored verbatim; this
                module performs no cryptography and never recomputes it.
            paired_at: POSIX timestamp of the pairing event.
            alias: Human-facing name. Defaults to `device_id`.
            expires_at: Optional trust deadline. `None` means trust does not expire.
            metadata: Optional free-form application data.

        Returns:
            A copy of the stored record.

        Raises:
            DuplicateDeviceError: `device_id` is already registered. Deliberately not
                idempotent -- see the exception's docstring.
            ValueError: `device_id` is empty, or key material is empty.
        """
        if not device_id:
            raise ValueError("device_id must be a non-empty string")
        if not x25519_pub or not mlkem_pub:
            raise ValueError("both x25519_pub and mlkem_pub are required")

        with self._lock:
            if device_id in self._records:
                raise DuplicateDeviceError(device_id)

            record = DeviceRecord(
                device_id=device_id,
                uuid=new_uuid(),
                alias=alias if alias is not None else device_id,
                current_key=KeyMaterial(
                    x25519_pub=x25519_pub,
                    mlkem_pub=mlkem_pub,
                    version=INITIAL_KEY_VERSION,
                    created_at=paired_at,
                ),
                fingerprint=fingerprint,
                paired_at=paired_at,
                expires_at=expires_at,
                metadata=dict(metadata or {}),
            )
            self._records[device_id] = record
            self._flush()
            return copy.deepcopy(record)

    # ------------------------------------------------------------------ read

    def get(self, device_id: str) -> DeviceRecord:
        """Return a copy of the record for `device_id`.

        Returns a copy so callers cannot mutate registry state without going through a
        mutator (and therefore without persisting).

        Raises:
            DeviceNotFoundError: no such device.
        """
        with self._lock:
            return copy.deepcopy(self._require(device_id))

    def find(self, device_id: str) -> DeviceRecord | None:
        """Like `get`, but returns `None` instead of raising when absent.

        For call sites where absence is an expected outcome rather than an error -- notably the
        protocol adapter in `integration.py`, where an unknown peer is a routine event.
        """
        with self._lock:
            record = self._records.get(device_id)
            return copy.deepcopy(record) if record is not None else None

    def exists(self, device_id: str) -> bool:
        """Whether a record exists for `device_id`, regardless of its trust state."""
        with self._lock:
            return device_id in self._records

    def list_devices(self) -> list[DeviceRecord]:
        """Every registered device, sorted by alias then `device_id` for stable display."""
        with self._lock:
            records = copy.deepcopy(list(self._records.values()))
        return sorted(records, key=lambda r: (r.alias.lower(), r.device_id))

    def search(
        self,
        query: str = "",
        predicate: Callable[[DeviceRecord], bool] | None = None,
    ) -> list[DeviceRecord]:
        """Find devices by free-text match and/or an arbitrary predicate.

        Args:
            query: Case-insensitive substring matched against `alias`, `device_id`, `uuid`, and
                `fingerprint`. An empty query matches everything.
            predicate: Optional extra filter applied after the text match. Accepting a callable
                rather than a fixed set of keyword filters keeps this one method sufficient for
                status filters, date ranges, and anything a caller invents later -- the
                `TrustManager` uses it to implement status-based search without the registry
                needing to know what a status is.

        Returns:
            Matching records, ordered as `list_devices`.
        """
        needle = query.lower().strip()
        results: list[DeviceRecord] = []
        for record in self.list_devices():
            if needle:
                haystack = (
                    record.alias.lower(),
                    record.device_id.lower(),
                    record.uuid.lower(),
                    record.fingerprint.lower(),
                )
                if not any(needle in field for field in haystack):
                    continue
            if predicate is not None and not predicate(record):
                continue
            results.append(record)
        return results

    # ------------------------------------------------------------------ update

    def rename(self, device_id: str, alias: str) -> DeviceRecord:
        """Change a device's human-facing alias.

        Raises:
            DeviceNotFoundError: no such device.
            ValueError: `alias` is empty or whitespace-only.
        """
        if not alias or not alias.strip():
            raise ValueError("alias must be a non-empty string")

        with self._lock:
            record = self._require(device_id)
            record.alias = alias.strip()
            self._flush()
            return copy.deepcopy(record)

    def update(self, device_id: str, **fields) -> DeviceRecord:
        """Set arbitrary record fields in one atomic write.

        The single mutation primitive every lifecycle operation funnels through, so persistence
        and locking exist in exactly one place rather than being re-implemented per operation.
        `TrustManager` builds revoke/restore/expire on top of it.

        Args:
            device_id: Device to update.
            **fields: Attribute names on `DeviceRecord` and their new values.

        Raises:
            DeviceNotFoundError: no such device.
            AttributeError: a named field does not exist on `DeviceRecord` -- guards against a
                typo silently creating a junk attribute that never persists.
        """
        with self._lock:
            record = self._require(device_id)
            for name, value in fields.items():
                if not hasattr(record, name):
                    raise AttributeError(f"DeviceRecord has no field {name!r}")
                setattr(record, name, value)
            self._flush()
            return copy.deepcopy(record)

    def replace_key(self, device_id: str, new_key: KeyMaterial, retired_at: float) -> DeviceRecord:
        """Promote `new_key` to current and archive the outgoing generation.

        The storage half of key rotation; validation of the transition lives in
        `TrustManager.rotate_key`, which owns the policy question of what makes a rotation
        legal. Both halves of the swap happen under one lock and one write, so a record can
        never be observed with the new key but an unarchived old one.

        Raises:
            DeviceNotFoundError: no such device.
        """
        with self._lock:
            record = self._require(device_id)
            outgoing = KeyMaterial(
                x25519_pub=record.current_key.x25519_pub,
                mlkem_pub=record.current_key.mlkem_pub,
                version=record.current_key.version,
                created_at=record.current_key.created_at,
                retired_at=retired_at,
            )
            record.key_history.append(outgoing)
            record.current_key = new_key
            self._flush()
            return copy.deepcopy(record)

    # ------------------------------------------------------------------ delete

    def remove(self, device_id: str) -> None:
        """Delete a device's record entirely -- the "unpair" operation.

        Distinct from revocation: revoking keeps the record and its audit trail and is
        reversible via `TrustManager.restore_trust`; removing discards both. Prefer revocation
        unless the record genuinely should stop existing.

        Raises:
            DeviceNotFoundError: no such device.
        """
        with self._lock:
            self._require(device_id)
            del self._records[device_id]
            self._flush()

    def clear(self) -> None:
        """Remove every record. Used by `ImportMode.REPLACE`."""
        with self._lock:
            self._records = {}
            self._flush()

    def bulk_put(self, records: Iterable[DeviceRecord]) -> None:
        """Insert or overwrite several records in a single atomic write.

        Used by database import, where writing per-record would leave the store in a
        half-imported state if the process died midway.
        """
        with self._lock:
            for record in records:
                self._records[record.device_id] = copy.deepcopy(record)
            self._flush()

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def __contains__(self, device_id: object) -> bool:
        return isinstance(device_id, str) and self.exists(device_id)
