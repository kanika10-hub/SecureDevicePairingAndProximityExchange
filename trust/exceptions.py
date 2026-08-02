"""Exception hierarchy for the trust framework.

Shaped so callers can catch at whatever granularity they need:

    TrustError                     -- catch-all for anything this package raises
    +-- DeviceNotFoundError        -- lookup miss
    +-- DuplicateDeviceError       -- registration collision
    +-- TrustValidationError       -- a device exists but must not be used right now
    |   +-- DeviceRevokedError
    |   +-- DeviceExpiredError
    +-- KeyRotationError           -- invalid key lifecycle transition
    +-- TrustStoreError            -- persistence failure
    |   +-- TrustStoreCorruptError
    +-- TrustBackupError           -- export/import failure
        +-- TrustImportError
        +-- TrustExportError

`TrustValidationError` is the one to catch at a session boundary: it means "known device,
currently untrusted", which is exactly the pre-session gate. It carries the evaluated
`TrustStatus` so a caller can log *why* without re-running the policy.

Named `TrustImportError` rather than `ImportError` deliberately -- shadowing the builtin would
make `except ImportError` in unrelated code catch trust failures.
"""
from __future__ import annotations

from trust.models import TrustStatus


class TrustError(Exception):
    """Base class for every error raised by the trust framework."""


class DeviceNotFoundError(TrustError):
    """No record exists for the requested device."""

    def __init__(self, device_id: str):
        self.device_id = device_id
        super().__init__(f"no trust record for device {device_id!r}")


class DuplicateDeviceError(TrustError):
    """A device with this id is already registered.

    Registration is not idempotent by design: silently overwriting an existing record would
    discard its key history and revocation state, which is precisely the audit trail this
    framework exists to keep. Callers that genuinely want to replace a record should remove it
    first, or rotate the key on the existing one.
    """

    def __init__(self, device_id: str):
        self.device_id = device_id
        super().__init__(f"device {device_id!r} is already registered")


class TrustValidationError(TrustError):
    """A known device failed its pre-session trust check."""

    def __init__(self, device_id: str, status: TrustStatus, message: str):
        self.device_id = device_id
        self.status = status
        super().__init__(message)


class DeviceRevokedError(TrustValidationError):
    """Trust in this device was explicitly withdrawn and has not been restored."""

    def __init__(self, device_id: str, reason: str | None = None):
        detail = f" (reason: {reason})" if reason else ""
        super().__init__(
            device_id,
            TrustStatus.REVOKED,
            f"device {device_id!r} is revoked{detail}",
        )
        self.reason = reason


class DeviceExpiredError(TrustValidationError):
    """Trust in this device has lapsed and must be renewed before use."""

    def __init__(self, device_id: str, detail: str = ""):
        suffix = f" ({detail})" if detail else ""
        super().__init__(
            device_id,
            TrustStatus.EXPIRED,
            f"device {device_id!r} trust has expired{suffix}",
        )


class KeyRotationError(TrustError):
    """An invalid key lifecycle transition was attempted.

    Raised when a rotation would not actually change the key material, or when a requested key
    version does not exist in the record's history.
    """


class TrustStoreError(TrustError):
    """The persistence backend could not complete an operation."""


class TrustStoreCorruptError(TrustStoreError):
    """Stored trust data could not be parsed into the current schema.

    Raised instead of silently starting from an empty database: losing a trust database without
    warning would downgrade every paired peer to "unknown" and, in a deployment that treats
    unknown peers as pairable, invite a re-pairing attack.
    """


class TrustBackupError(TrustError):
    """Base class for export/import failures."""


class TrustImportError(TrustBackupError):
    """A trust database could not be imported (unreadable, malformed, or wrong schema)."""


class TrustExportError(TrustBackupError):
    """A trust database could not be written to the export destination."""
