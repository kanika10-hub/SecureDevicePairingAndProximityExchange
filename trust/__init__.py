"""Security Lifecycle & Trust Management Framework.

Device registry, trust metadata, lifecycle policies, key-version tracking, and backup for the
secure pairing system. Sits *above* the cryptographic core and contains no cryptographic
primitives of its own -- it stores public keys and fingerprints produced by `core/` and
`pairing/`, and decides which peers may be used.

Typical use::

    from trust import TrustManager, JsonTrustStore

    manager = TrustManager(JsonTrustStore("trust_db.json"))
    manager.register_device("device-b", x25519_pub, mlkem_pub, fingerprint, alias="Kanika's phone")
    manager.validate_session("device-b")        # raises if revoked or expired

To enforce trust inside the existing proximity protocol without changing it, see
`trust.integration.ProtocolPeerStore`.

`trust.integration` is intentionally **not** imported here: it touches `pairing/`, which pulls
in `liboqs`. Keeping it out of this namespace means `import trust` needs only the standard
library, so trust logic is testable in environments with no crypto stack installed.
"""
from trust.device_registry import DeviceRegistry
from trust.exceptions import (
    DeviceExpiredError,
    DeviceNotFoundError,
    DeviceRevokedError,
    DuplicateDeviceError,
    KeyRotationError,
    TrustBackupError,
    TrustError,
    TrustExportError,
    TrustImportError,
    TrustStoreCorruptError,
    TrustStoreError,
    TrustValidationError,
)
from trust.models import (
    SCHEMA_VERSION,
    Clock,
    DeviceRecord,
    FixedClock,
    ImportMode,
    KeyMaterial,
    SystemClock,
    TrustStatus,
)
from trust.trust_manager import TrustManager
from trust.trust_policy import (
    AlwaysTrustPolicy,
    CompositeTrustPolicy,
    DefaultTrustPolicy,
    MaximumKeyAgePolicy,
    TrustPolicy,
)
from trust.trust_store import InMemoryTrustStore, JsonTrustStore, TrustStoreBackend

__all__ = [
    "SCHEMA_VERSION",
    "AlwaysTrustPolicy",
    "Clock",
    "CompositeTrustPolicy",
    "DefaultTrustPolicy",
    "DeviceExpiredError",
    "DeviceNotFoundError",
    "DeviceRecord",
    "DeviceRegistry",
    "DeviceRevokedError",
    "DuplicateDeviceError",
    "FixedClock",
    "ImportMode",
    "InMemoryTrustStore",
    "JsonTrustStore",
    "KeyMaterial",
    "KeyRotationError",
    "MaximumKeyAgePolicy",
    "SystemClock",
    "TrustBackupError",
    "TrustError",
    "TrustExportError",
    "TrustImportError",
    "TrustManager",
    "TrustPolicy",
    "TrustStatus",
    "TrustStoreBackend",
    "TrustStoreCorruptError",
    "TrustStoreError",
    "TrustValidationError",
]
