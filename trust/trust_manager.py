"""`TrustManager` -- the façade the rest of the application talks to.

Composes the three collaborators it is given (registry, policy, clock) and owns the operations
that need more than one of them: anything that combines a stored fact with a trust decision or
a timestamp. Pure CRUD stays delegated to `DeviceRegistry`; pure decisions stay in
`TrustPolicy`. This class adds the orchestration and nothing else, which is why it has no
persistence code and no rule logic of its own.

All three collaborators are injected and all three have sensible defaults, so the common case
is one line::

    manager = TrustManager(JsonTrustStore("trust_db.json"))

while a test can be fully deterministic and hardware-free::

    manager = TrustManager(InMemoryTrustStore(), clock=FixedClock(1000.0))

This module performs **no cryptography**. It stores public keys and a fingerprint produced by
`pairing.pairing_protocol`, and never derives, compares, or verifies key material itself.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from trust.device_registry import DeviceRegistry
from trust.exceptions import (
    KeyRotationError,
    TrustExportError,
    TrustImportError,
)
from trust.models import (
    SCHEMA_VERSION,
    Clock,
    DeviceRecord,
    ImportMode,
    KeyMaterial,
    SystemClock,
    TrustStatus,
)
from trust.trust_policy import DefaultTrustPolicy, TrustPolicy
from trust.trust_store import TrustStoreBackend


class TrustManager:
    """Lifecycle and trust management for paired devices.

    Args:
        backend: Where records are persisted. Required -- there is no implicit default path,
            because silently writing a trust database to a surprising location is worse than
            making the caller name it.
        policy: Rules for evaluating trust. Defaults to `DefaultTrustPolicy()`.
        clock: Time source. Defaults to `SystemClock()`.
        registry: Pre-built registry, mainly for tests that need to inject a double. When
            omitted (the normal case) one is constructed over `backend`.
    """

    def __init__(
        self,
        backend: TrustStoreBackend,
        policy: TrustPolicy | None = None,
        clock: Clock | None = None,
        registry: DeviceRegistry | None = None,
    ):
        self._registry = registry if registry is not None else DeviceRegistry(backend)
        self._policy = policy if policy is not None else DefaultTrustPolicy()
        self._clock = clock if clock is not None else SystemClock()

    @property
    def registry(self) -> DeviceRegistry:
        """The underlying registry, for callers needing raw CRUD without trust evaluation."""
        return self._registry

    @property
    def policy(self) -> TrustPolicy:
        """The active trust policy."""
        return self._policy

    # ================================================================== registry

    def register_device(
        self,
        device_id: str,
        x25519_pub: bytes,
        mlkem_pub: bytes,
        fingerprint: str,
        alias: str | None = None,
        expires_at: float | None = None,
        valid_for_seconds: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DeviceRecord:
        """Register a device that has just completed pairing.

        Args:
            device_id: On-the-wire peer identifier. Must be unique.
            x25519_pub: Peer's long-term X25519 public key.
            mlkem_pub: Peer's long-term ML-KEM-768 public key.
            fingerprint: Safety number from `pairing.pairing_protocol.compute_fingerprint`.
            alias: Human-facing name; defaults to `device_id`.
            expires_at: Absolute expiry timestamp, or `None` for no expiry.
            valid_for_seconds: Relative alternative to `expires_at`, resolved against the
                injected clock. Convenience for the common "trust this for 30 days" case.
            metadata: Free-form application data stored alongside the record.

        Returns:
            The stored record.

        Raises:
            DuplicateDeviceError: `device_id` is already registered.
            ValueError: both `expires_at` and `valid_for_seconds` were given, or the identifier
                or key material is empty.
        """
        now = self._clock.now()
        deadline = self._resolve_deadline(expires_at, valid_for_seconds, now)
        return self._registry.register(
            device_id=device_id,
            x25519_pub=x25519_pub,
            mlkem_pub=mlkem_pub,
            fingerprint=fingerprint,
            paired_at=now,
            alias=alias,
            expires_at=deadline,
            metadata=metadata,
        )

    def remove_device(self, device_id: str) -> None:
        """Permanently delete a device's record ("unpair").

        Irreversible and discards the audit trail. Prefer `revoke_trust` unless the record
        genuinely should stop existing.

        Raises:
            DeviceNotFoundError: no such device.
        """
        self._registry.remove(device_id)

    def rename_device(self, device_id: str, alias: str) -> DeviceRecord:
        """Change a device's alias. Purely cosmetic -- affects no trust decision.

        Raises:
            DeviceNotFoundError: no such device.
            ValueError: `alias` is empty or whitespace-only.
        """
        return self._registry.rename(device_id, alias)

    def get_device(self, device_id: str) -> DeviceRecord:
        """Return a device's record regardless of its trust state.

        Raises:
            DeviceNotFoundError: no such device.
        """
        return self._registry.get(device_id)

    def find_device(self, device_id: str) -> DeviceRecord | None:
        """Like `get_device`, but returns `None` when absent instead of raising."""
        return self._registry.find(device_id)

    def list_devices(self, status: TrustStatus | None = None) -> list[DeviceRecord]:
        """List registered devices, optionally filtered by current trust status.

        Args:
            status: If given, only devices currently evaluating to this status.
        """
        devices = self._registry.list_devices()
        if status is None:
            return devices
        now = self._clock.now()
        return [d for d in devices if self._policy.evaluate(d, now) is status]

    def search_devices(
        self,
        query: str = "",
        status: TrustStatus | None = None,
        predicate: Callable[[DeviceRecord], bool] | None = None,
    ) -> list[DeviceRecord]:
        """Search by free text, current trust status, and/or a custom predicate.

        Args:
            query: Case-insensitive substring over alias, device id, uuid, and fingerprint.
            status: Optional current-status filter, evaluated through the active policy.
            predicate: Optional additional filter.

        Returns:
            Matching records, sorted by alias.
        """
        now = self._clock.now()

        def combined(record: DeviceRecord) -> bool:
            if status is not None and self._policy.evaluate(record, now) is not status:
                return False
            return predicate(record) if predicate is not None else True

        return self._registry.search(query, predicate=combined)

    # ================================================================== trust state

    def get_status(self, device_id: str) -> TrustStatus:
        """Evaluate a device's current trust status.

        Raises:
            DeviceNotFoundError: no such device.
        """
        return self._policy.evaluate(self._registry.get(device_id), self._clock.now())

    def is_trusted(self, device_id: str) -> bool:
        """Whether a device is currently usable. `False` for unknown devices.

        The non-raising form of `validate_session`, for call sites making a routine yes/no
        check where an unknown peer is not exceptional.
        """
        record = self._registry.find(device_id)
        if record is None:
            return False
        return self._policy.is_trusted(record, self._clock.now())

    def validate_session(self, device_id: str) -> DeviceRecord:
        """Gate a session on trust. Call this before every protocol exchange.

        Returns the record when trust is intact, so the caller can proceed straight to using
        the key material without a second lookup.

        Raises:
            DeviceNotFoundError: device was never paired.
            DeviceRevokedError: trust was explicitly withdrawn.
            DeviceExpiredError: trust has lapsed.
        """
        record = self._registry.get(device_id)
        self._policy.validate(record, self._clock.now())
        return record

    def revoke_trust(self, device_id: str, reason: str | None = None) -> DeviceRecord:
        """Withdraw trust in a device without deleting its record.

        Reversible via `restore_trust`. Idempotent -- revoking an already-revoked device
        refreshes the reason and timestamp rather than raising, so an incident-response script
        can be re-run safely.

        Args:
            device_id: Device to revoke.
            reason: Optional human-readable justification, surfaced in `DeviceRevokedError`.

        Raises:
            DeviceNotFoundError: no such device.
        """
        return self._registry.update(
            device_id,
            revoked=True,
            revoked_at=self._clock.now(),
            revocation_reason=reason,
        )

    def restore_trust(
        self,
        device_id: str,
        expires_at: float | None = None,
        valid_for_seconds: float | None = None,
        clear_expiry: bool = True,
    ) -> DeviceRecord:
        """Return a revoked or expired device to trusted status.

        Clears revocation and, by default, clears any lapsed expiry deadline too -- restoring a
        device while leaving it expired would report success yet leave it unusable, which is a
        confusing outcome for the obvious call `restore_trust(device_id)`.

        Args:
            device_id: Device to restore.
            expires_at: New absolute expiry to apply on restore.
            valid_for_seconds: New relative expiry, resolved against the clock.
            clear_expiry: When `True` (default) and neither deadline argument is given, removes
                the existing `expires_at`. Set `False` to restore from revocation while leaving
                an existing deadline in force.

        Returns:
            The restored record.

        Raises:
            DeviceNotFoundError: no such device.
            ValueError: both `expires_at` and `valid_for_seconds` were given.
        """
        now = self._clock.now()
        deadline = self._resolve_deadline(expires_at, valid_for_seconds, now)

        fields: dict[str, Any] = {
            "revoked": False,
            "revoked_at": None,
            "revocation_reason": None,
        }
        if deadline is not None:
            fields["expires_at"] = deadline
        elif clear_expiry:
            fields["expires_at"] = None

        return self._registry.update(device_id, **fields)

    def expire_trust(self, device_id: str) -> DeviceRecord:
        """Expire a device's trust immediately by setting its deadline to now.

        The passive counterpart to `revoke_trust`: use it when trust should lapse for a
        routine reason (a lease ended, a rotation is overdue) rather than because the device is
        suspect. Reversible via `restore_trust`.

        Raises:
            DeviceNotFoundError: no such device.
        """
        return self._registry.update(device_id, expires_at=self._clock.now())

    def set_expiry(
        self,
        device_id: str,
        expires_at: float | None = None,
        valid_for_seconds: float | None = None,
    ) -> DeviceRecord:
        """Set or clear a device's expiry deadline.

        Passing neither argument clears the deadline (trust never expires).

        Raises:
            DeviceNotFoundError: no such device.
            ValueError: both deadline arguments were given.
        """
        deadline = self._resolve_deadline(expires_at, valid_for_seconds, self._clock.now())
        return self._registry.update(device_id, expires_at=deadline)

    def record_connection(self, device_id: str) -> DeviceRecord:
        """Stamp a successful connection with the current time.

        Feeds the inactivity rule in `DefaultTrustPolicy(max_inactivity_seconds=...)`. Call it
        after a session completes, not before -- a failed handshake is not proof of liveness,
        and stamping on attempt would let an attacker who cannot authenticate keep a stale
        device's trust alive by repeatedly connecting.

        Raises:
            DeviceNotFoundError: no such device.
        """
        return self._registry.update(device_id, last_connected_at=self._clock.now())

    # ================================================================== key lifecycle

    def rotate_key(
        self,
        device_id: str,
        x25519_pub: bytes,
        mlkem_pub: bytes,
        fingerprint: str | None = None,
    ) -> DeviceRecord:
        """Record a new generation of a peer's long-term public keys.

        Archives the outgoing generation into `key_history` with a `retired_at` stamp and
        installs the new one at `key_version + 1`. History is kept so that a record signed or
        referenced under an older version can still be interpreted after rotation, and so an
        operator can audit when a key changed.

        This method performs no cryptography: it does not generate, validate, or verify the
        keys. Producing them is the caller's job, using the existing `core/` primitives and a
        re-pairing or key-agreement exchange. That is what makes rotation supportable here
        without modifying the protocol.

        Args:
            device_id: Device whose key is rotating.
            x25519_pub: New long-term X25519 public key.
            mlkem_pub: New long-term ML-KEM-768 public key.
            fingerprint: New safety number, if the caller recomputed one. When omitted the
                stored fingerprint is left as-is.

        Returns:
            The updated record, with `key_version` incremented.

        Raises:
            DeviceNotFoundError: no such device.
            KeyRotationError: the supplied keys are identical to the current generation. A
                no-op rotation almost always means a caller bug (re-submitting the old key),
                and silently accepting it would inflate the version counter while leaving the
                device on unchanged key material.
            ValueError: either key is empty.
        """
        if not x25519_pub or not mlkem_pub:
            raise ValueError("both x25519_pub and mlkem_pub are required")

        current = self._registry.get(device_id).current_key
        if x25519_pub == current.x25519_pub and mlkem_pub == current.mlkem_pub:
            raise KeyRotationError(
                f"rotation for {device_id!r} supplies the same key material as version "
                f"{current.version}; nothing to rotate"
            )

        now = self._clock.now()
        new_key = KeyMaterial(
            x25519_pub=x25519_pub,
            mlkem_pub=mlkem_pub,
            version=current.version + 1,
            created_at=now,
        )
        record = self._registry.replace_key(device_id, new_key, retired_at=now)

        if fingerprint is not None:
            record = self._registry.update(device_id, fingerprint=fingerprint)
        return record

    def get_key_version(self, device_id: str) -> int:
        """Current key version for a device.

        Raises:
            DeviceNotFoundError: no such device.
        """
        return self._registry.get(device_id).key_version

    def get_key_history(self, device_id: str) -> list[KeyMaterial]:
        """Every key generation for a device, oldest first, current one last.

        Raises:
            DeviceNotFoundError: no such device.
        """
        return self._registry.get(device_id).all_keys()

    def get_key(self, device_id: str, version: int | None = None) -> KeyMaterial:
        """Fetch a specific key generation, or the current one when `version` is `None`.

        Raises:
            DeviceNotFoundError: no such device.
            KeyRotationError: that version was never recorded for this device.
        """
        record = self._registry.get(device_id)
        if version is None:
            return record.current_key
        key = record.find_key_version(version)
        if key is None:
            raise KeyRotationError(
                f"device {device_id!r} has no key version {version} "
                f"(known versions: {[k.version for k in record.all_keys()]})"
            )
        return key

    # ================================================================== backup

    def export_database(self, path: str | Path) -> Path:
        """Write the full trust database to a portable JSON file.

        The export is a self-describing envelope (`schema_version`, `exported_at`, `devices`)
        rather than a copy of the backend's on-disk layout, so a database exported from a JSON
        store can be imported into a future SQLite or keychain-backed store unchanged.

        Contains public keys and metadata only -- no private key material -- but it does define
        which devices this one trusts, so an attacker able to substitute an export file before
        import can insert their own key under a trusted `device_id`. Treat exports as
        integrity-sensitive and transfer them over an authenticated channel.

        Args:
            path: Destination file. Parent directories are created if needed.

        Returns:
            The path written.

        Raises:
            TrustExportError: the file could not be written.
        """
        destination = Path(path)
        envelope = {
            "schema_version": SCHEMA_VERSION,
            "exported_at": self._clock.now(),
            "devices": [record.to_dict() for record in self._registry.list_devices()],
        }
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
        except OSError as exc:
            raise TrustExportError(f"could not write trust export to {destination}: {exc}") from exc
        return destination

    def import_database(
        self,
        path: str | Path,
        mode: ImportMode = ImportMode.SKIP_EXISTING,
    ) -> list[DeviceRecord]:
        """Load a trust database previously written by `export_database`.

        The whole import is validated before anything is written, so a malformed file leaves
        the existing database untouched rather than half-replaced.

        Args:
            path: Source file.
            mode: Collision behaviour. Defaults to `SKIP_EXISTING`, the conservative choice --
                an import cannot clobber a local record (and its revocation state) unless the
                caller explicitly asks for `OVERWRITE_EXISTING` or `REPLACE`.

        Returns:
            The records actually written, in file order. Empty when every record was skipped.

        Raises:
            TrustImportError: the file is missing, unreadable, not a valid export envelope, has
                an unsupported schema version, or contains a malformed record.
        """
        source = Path(path)
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TrustImportError(f"could not read trust export {source}: {exc}") from exc

        if not isinstance(raw, dict) or not isinstance(raw.get("devices"), list):
            raise TrustImportError(
                f"{source} is not a trust export (expected an object with a 'devices' list)"
            )
        version = raw.get("schema_version")
        if version != SCHEMA_VERSION:
            raise TrustImportError(
                f"{source} has schema_version {version!r}, this build understands {SCHEMA_VERSION}"
            )

        try:
            incoming = [DeviceRecord.from_dict(item) for item in raw["devices"]]
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise TrustImportError(f"{source} contains a malformed device record: {exc}") from exc

        if mode is ImportMode.REPLACE:
            self._registry.clear()
            to_write = incoming
        elif mode is ImportMode.OVERWRITE_EXISTING:
            to_write = incoming
        elif mode is ImportMode.SKIP_EXISTING:
            to_write = [r for r in incoming if not self._registry.exists(r.device_id)]
        else:  # pragma: no cover - guards against a future enum member with no branch
            raise TrustImportError(f"unsupported import mode: {mode!r}")

        if to_write:
            self._registry.bulk_put(to_write)
        return to_write

    # ================================================================== internals

    @staticmethod
    def _resolve_deadline(
        expires_at: float | None,
        valid_for_seconds: float | None,
        now: float,
    ) -> float | None:
        """Normalize the two mutually exclusive ways of expressing an expiry deadline.

        Exists so the absolute/relative choice is validated identically everywhere it is
        offered (`register_device`, `restore_trust`, `set_expiry`) rather than three times.

        Raises:
            ValueError: both forms were supplied, which is ambiguous.
        """
        if expires_at is not None and valid_for_seconds is not None:
            raise ValueError("pass either expires_at or valid_for_seconds, not both")
        if valid_for_seconds is not None:
            return now + valid_for_seconds
        return expires_at
