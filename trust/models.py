"""Domain model for the trust lifecycle framework.

Pure data + pure functions. This module deliberately has **no** dependency on the crypto core,
on persistence, or on policy evaluation -- it is the innermost layer of the architecture and
everything else depends inward on it.

Key modelling decision: a device's trust *status* is **derived**, never stored. The record
persists only primitive facts (`revoked`, `revoked_at`, `expires_at`), and
`trust_policy.TrustPolicy` maps those facts onto a `TrustStatus` at read time. Storing a
`status` column alongside the flags that determine it would create two sources of truth that
can silently disagree after a clock change or a partial write.

Identifier decision: every record carries **both** identifiers, because they answer different
questions.

* `device_id` -- the on-the-wire identifier the existing protocol already keys everything by
  (`pairing/trust_store.py`, `proximity/proximity_protocol.py`). It is the registry's lookup
  key, so a `TrustManager` can stand in for the protocol's peer store.
* `uuid` -- a locally generated, immutable primary key. A `device_id` is chosen by the peer and
  a peer could in principle re-pair under a new one; the `uuid` gives local records (audit
  logs, exports, UI selections) a handle that never changes.
"""
from __future__ import annotations

import time
import uuid as uuid_module
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

SCHEMA_VERSION = 1
"""Version of the serialized record format. Bumped when `to_dict`/`from_dict` change shape."""

INITIAL_KEY_VERSION = 1
"""Key version assigned at registration; `TrustManager.rotate_key` increments from here."""


class TrustStatus(str, Enum):
    """Result of evaluating a device against a trust policy.

    Inherits from `str` so it serializes to plain JSON and compares equal to its own value,
    which keeps exported trust databases human-readable.
    """

    TRUSTED = "trusted"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ImportMode(str, Enum):
    """Collision strategy for `TrustManager.import_database`."""

    REPLACE = "replace"
    """Discard the entire local database and adopt the imported one verbatim."""

    SKIP_EXISTING = "skip_existing"
    """Add only devices absent locally; leave local records for colliding ids untouched."""

    OVERWRITE_EXISTING = "overwrite_existing"
    """Add new devices and replace local records for colliding ids with the imported ones."""


@runtime_checkable
class Clock(Protocol):
    """Time source, injected so expiry logic is testable without sleeping.

    Structural (`Protocol`) rather than nominal so callers may pass any object with a `now()`
    returning a POSIX timestamp -- including `unittest.mock` doubles.
    """

    def now(self) -> float:
        """Return the current time as a POSIX timestamp (seconds since the epoch)."""
        ...


class SystemClock:
    """Default `Clock`, backed by the wall clock.

    Wall clock rather than `time.monotonic()` on purpose: expiry deadlines must survive a
    process restart, and a monotonic reading is meaningless across restarts.
    """

    def now(self) -> float:
        return time.time()


@dataclass
class FixedClock:
    """Deterministic `Clock` for tests: time only moves when `advance()` is called."""

    current: float = 0.0

    def now(self) -> float:
        return self.current

    def advance(self, seconds: float) -> float:
        """Move the clock forward and return the new time."""
        self.current += seconds
        return self.current


@dataclass(frozen=True)
class KeyMaterial:
    """One generation of a peer's long-term public keys.

    Frozen because a key generation is an immutable historical fact: rotation appends a new
    `KeyMaterial` and retires the previous one rather than mutating it. Holds public keys only
    -- this framework never sees a private key.
    """

    x25519_pub: bytes
    mlkem_pub: bytes
    version: int = INITIAL_KEY_VERSION
    created_at: float = 0.0
    retired_at: float | None = None
    """Set when this generation is superseded by a rotation; `None` while current."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe primitives (key bytes become hex strings)."""
        return {
            "x25519_pub": self.x25519_pub.hex(),
            "mlkem_pub": self.mlkem_pub.hex(),
            "version": self.version,
            "created_at": self.created_at,
            "retired_at": self.retired_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KeyMaterial:
        """Inverse of `to_dict`. Raises `KeyError`/`ValueError` on malformed input; callers in
        `trust_store.py` translate those into `TrustStoreCorruptError`."""
        return cls(
            x25519_pub=bytes.fromhex(data["x25519_pub"]),
            mlkem_pub=bytes.fromhex(data["mlkem_pub"]),
            version=int(data["version"]),
            created_at=float(data["created_at"]),
            retired_at=None if data.get("retired_at") is None else float(data["retired_at"]),
        )


@dataclass
class DeviceRecord:
    """Everything the local device durably knows about one trusted peer.

    Exposes only *facts* about itself. It deliberately does not answer "should I talk to this
    device?" -- that question belongs to `trust_policy.TrustPolicy`, which can be swapped
    without touching the model.
    """

    device_id: str
    """On-the-wire peer identifier; the registry's lookup key. See module docstring."""

    uuid: str
    """Immutable local primary key, generated at registration."""

    alias: str
    """Human-facing name. Mutable via `TrustManager.rename_device`."""

    current_key: KeyMaterial
    """The key generation currently in force for this peer."""

    fingerprint: str
    """Safety number computed at pairing time by `pairing.pairing_protocol.compute_fingerprint`.
    Stored, never recomputed here -- this module contains no cryptography."""

    paired_at: float
    last_connected_at: float | None = None
    revoked: bool = False
    revoked_at: float | None = None
    revocation_reason: str | None = None
    expires_at: float | None = None
    """POSIX timestamp after which trust lapses. `None` means "never expires"."""

    key_history: list[KeyMaterial] = field(default_factory=list)
    """Retired key generations, oldest first. Never includes `current_key`."""

    metadata: dict[str, Any] = field(default_factory=dict)
    """Free-form application data. Carried through persistence and export untouched, so callers
    can attach their own fields without a schema change here."""

    @property
    def key_version(self) -> int:
        """Version number of the key generation currently in force."""
        return self.current_key.version

    @property
    def x25519_pub(self) -> bytes:
        """Current long-term X25519 public key. Convenience for protocol-facing adapters."""
        return self.current_key.x25519_pub

    @property
    def mlkem_pub(self) -> bytes:
        """Current long-term ML-KEM-768 public key."""
        return self.current_key.mlkem_pub

    def is_expired(self, now: float) -> bool:
        """Whether this record's own explicit deadline has passed.

        A narrow fact about `expires_at` only. Policies may treat further conditions (e.g.
        prolonged inactivity) as expiry; those live in `trust_policy.py`, not here.
        """
        return self.expires_at is not None and now >= self.expires_at

    def all_keys(self) -> list[KeyMaterial]:
        """Every key generation ever recorded, oldest first, current one last."""
        return [*self.key_history, self.current_key]

    def find_key_version(self, version: int) -> KeyMaterial | None:
        """Look up a specific key generation, current or retired. `None` if never recorded."""
        for key in self.all_keys():
            if key.version == version:
                return key
        return None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe primitives."""
        return {
            "device_id": self.device_id,
            "uuid": self.uuid,
            "alias": self.alias,
            "current_key": self.current_key.to_dict(),
            "fingerprint": self.fingerprint,
            "paired_at": self.paired_at,
            "last_connected_at": self.last_connected_at,
            "revoked": self.revoked,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
            "expires_at": self.expires_at,
            "key_history": [k.to_dict() for k in self.key_history],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceRecord:
        """Inverse of `to_dict`. Raises `KeyError`/`ValueError` on malformed input."""
        return cls(
            device_id=str(data["device_id"]),
            uuid=str(data["uuid"]),
            alias=str(data["alias"]),
            current_key=KeyMaterial.from_dict(data["current_key"]),
            fingerprint=str(data["fingerprint"]),
            paired_at=float(data["paired_at"]),
            last_connected_at=(
                None if data.get("last_connected_at") is None else float(data["last_connected_at"])
            ),
            revoked=bool(data.get("revoked", False)),
            revoked_at=None if data.get("revoked_at") is None else float(data["revoked_at"]),
            revocation_reason=data.get("revocation_reason"),
            expires_at=None if data.get("expires_at") is None else float(data["expires_at"]),
            key_history=[KeyMaterial.from_dict(k) for k in data.get("key_history", [])],
            metadata=dict(data.get("metadata", {})),
        )


def new_uuid() -> str:
    """Generate a fresh local primary key for a device record."""
    return str(uuid_module.uuid4())
