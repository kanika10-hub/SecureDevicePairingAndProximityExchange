"""Persistence layer for trust records.

Defines the `TrustStoreBackend` abstraction and two implementations. Nothing above this layer
knows how records are stored, so swapping JSON for SQLite, an OS keychain, or a TPM-backed
store is a constructor argument rather than a refactor (Dependency Inversion).

This module is **separate from and additive to** `pairing/trust_store.py`. That module remains
the protocol's own minimal peer store and is not modified; see `trust/integration.py` for the
adapter that lets this richer store stand in for it.

Backends deal only in whole snapshots (`load()` / `save()`). A per-record CRUD interface would
push transaction management down into every implementation; snapshot semantics keep backends
trivial to write correctly and let `DeviceRegistry` own consistency in one place.
"""
from __future__ import annotations

import copy
import json
import os
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Mapping

from trust.exceptions import TrustStoreCorruptError, TrustStoreError
from trust.models import SCHEMA_VERSION, DeviceRecord


class TrustStoreBackend(ABC):
    """A durable collection of `DeviceRecord`s keyed by `device_id`.

    Implementations must be safe to call from multiple threads, and `save()` must be atomic:
    a crash mid-write must leave either the previous snapshot or the new one, never a partial
    file. A truncated trust database is a security-relevant failure, not just a data loss --
    peers silently become unknown.
    """

    @abstractmethod
    def load(self) -> dict[str, DeviceRecord]:
        """Return every stored record, keyed by `device_id`.

        Returns an empty dict for a store that has never been written. Raises
        `TrustStoreCorruptError` if data exists but cannot be parsed.
        """

    @abstractmethod
    def save(self, records: Mapping[str, DeviceRecord]) -> None:
        """Atomically replace the stored snapshot with `records`."""


class InMemoryTrustStore(TrustStoreBackend):
    """Non-durable backend for tests and ephemeral sessions.

    Deep-copies on the way in and out so callers cannot mutate stored state by holding onto a
    record they passed to `save()`. That matches the isolation a real file-backed store gives
    for free, and stops tests from passing for the wrong reason.
    """

    def __init__(self, initial: Mapping[str, DeviceRecord] | None = None):
        self._lock = threading.RLock()
        self._records: dict[str, DeviceRecord] = copy.deepcopy(dict(initial or {}))

    def load(self) -> dict[str, DeviceRecord]:
        with self._lock:
            return copy.deepcopy(self._records)

    def save(self, records: Mapping[str, DeviceRecord]) -> None:
        with self._lock:
            self._records = copy.deepcopy(dict(records))


class JsonTrustStore(TrustStoreBackend):
    """Default backend: a single JSON document on local disk.

    Writes go to a temporary file in the same directory and are moved into place with
    `os.replace`, which is atomic on both POSIX and Windows. The envelope carries a
    `schema_version` so a future format change can be detected and migrated rather than
    misparsed.

    Note on confidentiality: this file holds public keys and metadata only, no private key
    material, so it is not encrypted at rest. It is nonetheless integrity-critical -- an
    attacker who can rewrite it can insert their own public key for a trusted `device_id`.
    Protecting it is a filesystem-permissions concern, out of scope for this module.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.RLock()

    def load(self) -> dict[str, DeviceRecord]:
        with self._lock:
            if not self.path.exists():
                return {}
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise TrustStoreCorruptError(
                    f"trust store at {self.path} could not be read: {exc}"
                ) from exc

            if not isinstance(raw, dict) or "devices" not in raw:
                raise TrustStoreCorruptError(
                    f"trust store at {self.path} is missing the 'devices' envelope"
                )

            version = raw.get("schema_version")
            if version != SCHEMA_VERSION:
                raise TrustStoreCorruptError(
                    f"trust store at {self.path} has schema_version {version!r}, "
                    f"this build understands {SCHEMA_VERSION}"
                )

            try:
                return {
                    device_id: DeviceRecord.from_dict(record)
                    for device_id, record in raw["devices"].items()
                }
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise TrustStoreCorruptError(
                    f"trust store at {self.path} contains a malformed record: {exc}"
                ) from exc

    def save(self, records: Mapping[str, DeviceRecord]) -> None:
        with self._lock:
            envelope = {
                "schema_version": SCHEMA_VERSION,
                "devices": {device_id: record.to_dict() for device_id, record in records.items()},
            }
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_name(self.path.name + ".tmp")
                tmp.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
                os.replace(tmp, self.path)
            except OSError as exc:
                raise TrustStoreError(
                    f"trust store at {self.path} could not be written: {exc}"
                ) from exc
