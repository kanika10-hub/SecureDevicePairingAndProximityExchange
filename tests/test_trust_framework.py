"""Unit tests for the trust lifecycle framework (`trust/`).

Every test runs against `InMemoryTrustStore` + `FixedClock` unless it is specifically about
persistence or wall-clock behaviour, so the suite is deterministic, needs no crypto stack, and
never sleeps to test expiry.

Key material here is arbitrary filler bytes of the right length. That is deliberate: this
framework performs no cryptography, so tests that generated real X25519/ML-KEM keys would be
asserting nothing extra while making the suite depend on `liboqs`.
"""
import json

import pytest

from trust import (
    AlwaysTrustPolicy,
    CompositeTrustPolicy,
    DefaultTrustPolicy,
    DeviceExpiredError,
    DeviceNotFoundError,
    DeviceRevokedError,
    DuplicateDeviceError,
    FixedClock,
    ImportMode,
    InMemoryTrustStore,
    JsonTrustStore,
    KeyRotationError,
    MaximumKeyAgePolicy,
    TrustImportError,
    TrustManager,
    TrustStatus,
    TrustStoreCorruptError,
    TrustValidationError,
)
from trust.integration import ProtocolPeerStore, migrate_legacy_store

X25519_A = b"\x01" * 32
MLKEM_A = b"\x02" * 1184
X25519_B = b"\x03" * 32
MLKEM_B = b"\x04" * 1184
FINGERPRINT = "AB12-CD34-EF56-7890-1234-5678"

START_TIME = 1_700_000_000.0
DAY = 86_400.0


@pytest.fixture
def clock():
    return FixedClock(START_TIME)


@pytest.fixture
def manager(clock):
    """A manager with no devices, an in-memory store, and a clock the test controls."""
    return TrustManager(InMemoryTrustStore(), clock=clock)


@pytest.fixture
def populated(manager):
    """A manager holding one registered device, `device-b`."""
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, alias="Kanika's phone")
    return manager


# ====================================================================== registration


def test_register_device(manager, clock):
    record = manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, alias="Phone")

    assert record.device_id == "device-b"
    assert record.alias == "Phone"
    assert record.x25519_pub == X25519_A
    assert record.mlkem_pub == MLKEM_A
    assert record.fingerprint == FINGERPRINT
    assert record.paired_at == clock.now()
    assert record.key_version == 1
    assert record.key_history == []
    assert record.uuid  # a local primary key was generated
    assert record.last_connected_at is None
    assert manager.get_status("device-b") is TrustStatus.TRUSTED


def test_register_defaults_alias_to_device_id(manager):
    assert manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT).alias == "device-b"


def test_register_assigns_unique_uuids(manager):
    first = manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    second = manager.register_device("device-c", X25519_B, MLKEM_B, FINGERPRINT)
    assert first.uuid != second.uuid


def test_duplicate_registration_rejected(populated):
    """Registration is not idempotent by design: a silent overwrite would discard the existing
    record's key history and revocation state."""
    with pytest.raises(DuplicateDeviceError) as exc:
        populated.register_device("device-b", X25519_B, MLKEM_B, "OTHER-FINGERPRINT")
    assert exc.value.device_id == "device-b"

    # the original record survived the failed attempt untouched
    assert populated.get_device("device-b").x25519_pub == X25519_A


def test_duplicate_registration_does_not_clear_revocation(populated):
    """An attacker who can trigger a re-registration must not be able to launder a revocation."""
    populated.revoke_trust("device-b", reason="lost")
    with pytest.raises(DuplicateDeviceError):
        populated.register_device("device-b", X25519_B, MLKEM_B, FINGERPRINT)
    assert populated.get_status("device-b") is TrustStatus.REVOKED


@pytest.mark.parametrize(
    "device_id, x25519, mlkem",
    [("", X25519_A, MLKEM_A), ("device-b", b"", MLKEM_A), ("device-b", X25519_A, b"")],
)
def test_register_rejects_empty_arguments(manager, device_id, x25519, mlkem):
    with pytest.raises(ValueError):
        manager.register_device(device_id, x25519, mlkem, FINGERPRINT)


def test_register_rejects_ambiguous_expiry(manager):
    with pytest.raises(ValueError, match="not both"):
        manager.register_device(
            "device-b", X25519_A, MLKEM_A, FINGERPRINT, expires_at=1.0, valid_for_seconds=1.0
        )


# ====================================================================== rename / remove


def test_rename_device(populated):
    renamed = populated.rename_device("device-b", "Work laptop")
    assert renamed.alias == "Work laptop"
    assert populated.get_device("device-b").alias == "Work laptop"


def test_rename_preserves_identity_and_trust(populated):
    before = populated.get_device("device-b")
    after = populated.rename_device("device-b", "New name")

    assert after.uuid == before.uuid
    assert after.device_id == before.device_id
    assert after.x25519_pub == before.x25519_pub
    assert populated.get_status("device-b") is TrustStatus.TRUSTED


def test_rename_strips_surrounding_whitespace(populated):
    assert populated.rename_device("device-b", "  Padded  ").alias == "Padded"


@pytest.mark.parametrize("alias", ["", "   "])
def test_rename_rejects_blank_alias(populated, alias):
    with pytest.raises(ValueError):
        populated.rename_device("device-b", alias)


def test_rename_unknown_device_raises(manager):
    with pytest.raises(DeviceNotFoundError):
        manager.rename_device("ghost", "Nope")


def test_remove_device(populated):
    populated.remove_device("device-b")

    assert populated.find_device("device-b") is None
    assert populated.list_devices() == []
    with pytest.raises(DeviceNotFoundError):
        populated.get_device("device-b")


def test_remove_unknown_device_raises(manager):
    with pytest.raises(DeviceNotFoundError):
        manager.remove_device("ghost")


def test_remove_is_not_reversible_unlike_revoke(populated):
    """Removal discards the record; restore_trust cannot bring it back. This is the documented
    difference between unpairing and revoking."""
    populated.remove_device("device-b")
    with pytest.raises(DeviceNotFoundError):
        populated.restore_trust("device-b")


# ====================================================================== lookup / search


def test_invalid_device_lookup_raises(manager):
    with pytest.raises(DeviceNotFoundError) as exc:
        manager.get_device("never-paired")
    assert exc.value.device_id == "never-paired"
    assert "never-paired" in str(exc.value)


def test_invalid_device_lookup_non_raising_variants(manager):
    assert manager.find_device("never-paired") is None
    assert manager.is_trusted("never-paired") is False


def test_status_of_unknown_device_raises(manager):
    with pytest.raises(DeviceNotFoundError):
        manager.get_status("never-paired")


def test_list_devices_sorted_by_alias(manager):
    manager.register_device("device-z", X25519_A, MLKEM_A, FINGERPRINT, alias="alpha")
    manager.register_device("device-a", X25519_B, MLKEM_B, FINGERPRINT, alias="zulu")

    assert [d.alias for d in manager.list_devices()] == ["alpha", "zulu"]


def test_search_matches_alias_and_device_id_case_insensitively(manager):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, alias="Kanika's Phone")
    manager.register_device("laptop-1", X25519_B, MLKEM_B, FINGERPRINT, alias="Work Laptop")

    assert [d.device_id for d in manager.search_devices("phone")] == ["device-b"]
    assert [d.device_id for d in manager.search_devices("LAPTOP")] == ["laptop-1"]
    assert len(manager.search_devices("")) == 2


def test_search_matches_uuid_and_fingerprint(populated):
    record = populated.get_device("device-b")
    assert populated.search_devices(record.uuid)[0].device_id == "device-b"
    assert populated.search_devices(FINGERPRINT)[0].device_id == "device-b"


def test_search_filters_by_status(manager):
    manager.register_device("good", X25519_A, MLKEM_A, FINGERPRINT)
    manager.register_device("bad", X25519_B, MLKEM_B, FINGERPRINT)
    manager.revoke_trust("bad")

    assert [d.device_id for d in manager.search_devices(status=TrustStatus.TRUSTED)] == ["good"]
    assert [d.device_id for d in manager.search_devices(status=TrustStatus.REVOKED)] == ["bad"]
    assert [d.device_id for d in manager.list_devices(status=TrustStatus.REVOKED)] == ["bad"]


def test_search_accepts_custom_predicate(manager):
    manager.register_device("v1", X25519_A, MLKEM_A, FINGERPRINT)
    manager.register_device("v2", X25519_B, MLKEM_B, FINGERPRINT)
    manager.rotate_key("v2", X25519_A, MLKEM_A)

    found = manager.search_devices(predicate=lambda r: r.key_version > 1)
    assert [d.device_id for d in found] == ["v2"]


# ====================================================================== revoke / restore


def test_revoke_trust(populated, clock):
    record = populated.revoke_trust("device-b", reason="phone stolen")

    assert record.revoked is True
    assert record.revoked_at == clock.now()
    assert record.revocation_reason == "phone stolen"
    assert populated.get_status("device-b") is TrustStatus.REVOKED
    assert populated.is_trusted("device-b") is False


def test_revoked_device_fails_session_validation(populated):
    populated.revoke_trust("device-b", reason="phone stolen")

    with pytest.raises(DeviceRevokedError) as exc:
        populated.validate_session("device-b")
    assert exc.value.status is TrustStatus.REVOKED
    assert exc.value.reason == "phone stolen"
    assert "phone stolen" in str(exc.value)


def test_revoked_device_still_listed_and_retrievable(populated):
    """Revocation keeps the record and its audit trail -- that is what distinguishes it from
    removal."""
    populated.revoke_trust("device-b")

    assert populated.get_device("device-b").device_id == "device-b"
    assert len(populated.list_devices()) == 1


def test_revoke_is_idempotent(populated, clock):
    populated.revoke_trust("device-b", reason="first")
    clock.advance(60)
    record = populated.revoke_trust("device-b", reason="second")

    assert record.revoked is True
    assert record.revocation_reason == "second"
    assert record.revoked_at == clock.now()


def test_revoke_unknown_device_raises(manager):
    with pytest.raises(DeviceNotFoundError):
        manager.revoke_trust("ghost")


def test_restore_trust(populated):
    populated.revoke_trust("device-b", reason="misplaced")
    record = populated.restore_trust("device-b")

    assert record.revoked is False
    assert record.revoked_at is None
    assert record.revocation_reason is None
    assert populated.get_status("device-b") is TrustStatus.TRUSTED
    populated.validate_session("device-b")  # must not raise


def test_restore_clears_lapsed_expiry_by_default(manager, clock):
    """`restore_trust(id)` with no arguments must leave the device actually usable; returning
    success while it stays expired would be a confusing outcome."""
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, valid_for_seconds=DAY)
    clock.advance(2 * DAY)
    assert manager.get_status("device-b") is TrustStatus.EXPIRED

    manager.restore_trust("device-b")
    assert manager.get_status("device-b") is TrustStatus.TRUSTED


def test_restore_can_set_a_new_deadline(manager, clock):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    manager.revoke_trust("device-b")

    manager.restore_trust("device-b", valid_for_seconds=DAY)
    assert manager.get_status("device-b") is TrustStatus.TRUSTED

    clock.advance(DAY + 1)
    assert manager.get_status("device-b") is TrustStatus.EXPIRED


def test_restore_can_preserve_existing_expiry(manager, clock):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, valid_for_seconds=DAY)
    deadline = manager.get_device("device-b").expires_at
    manager.revoke_trust("device-b")

    restored = manager.restore_trust("device-b", clear_expiry=False)
    assert restored.expires_at == deadline
    assert manager.get_status("device-b") is TrustStatus.TRUSTED


def test_restore_unknown_device_raises(manager):
    with pytest.raises(DeviceNotFoundError):
        manager.restore_trust("ghost")


# ====================================================================== expiry


def test_expired_device(manager, clock):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, valid_for_seconds=DAY)
    assert manager.get_status("device-b") is TrustStatus.TRUSTED

    clock.advance(DAY + 1)

    assert manager.get_status("device-b") is TrustStatus.EXPIRED
    assert manager.is_trusted("device-b") is False
    with pytest.raises(DeviceExpiredError) as exc:
        manager.validate_session("device-b")
    assert exc.value.status is TrustStatus.EXPIRED


def test_expiry_boundary_is_inclusive(manager, clock):
    """A device expires *at* its deadline, not one tick after -- the conservative reading."""
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, valid_for_seconds=DAY)
    clock.advance(DAY)
    assert manager.get_status("device-b") is TrustStatus.EXPIRED


def test_expire_trust_immediately(populated):
    populated.expire_trust("device-b")

    assert populated.get_status("device-b") is TrustStatus.EXPIRED
    with pytest.raises(DeviceExpiredError):
        populated.validate_session("device-b")


def test_set_and_clear_expiry(manager, clock):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, valid_for_seconds=DAY)
    clock.advance(DAY + 1)
    assert manager.get_status("device-b") is TrustStatus.EXPIRED

    manager.set_expiry("device-b")  # no arguments clears the deadline
    assert manager.get_device("device-b").expires_at is None
    assert manager.get_status("device-b") is TrustStatus.TRUSTED


def test_registration_without_expiry_never_expires(manager, clock):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    clock.advance(3650 * DAY)
    assert manager.get_status("device-b") is TrustStatus.TRUSTED


def test_revocation_takes_precedence_over_expiry(manager, clock):
    """Both conditions true -> report REVOKED, so an operator sees the deliberate decision
    rather than the passive deadline, and cannot 'fix' it by renewing the expiry."""
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, valid_for_seconds=DAY)
    manager.revoke_trust("device-b", reason="compromised")
    clock.advance(DAY + 1)

    assert manager.get_status("device-b") is TrustStatus.REVOKED
    with pytest.raises(DeviceRevokedError):
        manager.validate_session("device-b")


def test_validation_errors_share_a_base_class(populated):
    """Call sites that only need 'is this session allowed?' can catch one exception type."""
    populated.revoke_trust("device-b")
    with pytest.raises(TrustValidationError):
        populated.validate_session("device-b")


# ====================================================================== policies


def test_inactivity_policy_expires_stale_device(clock):
    manager = TrustManager(
        InMemoryTrustStore(),
        policy=DefaultTrustPolicy(max_inactivity_seconds=30 * DAY),
        clock=clock,
    )
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)

    clock.advance(31 * DAY)
    assert manager.get_status("device-b") is TrustStatus.EXPIRED

    # a fresh connection re-establishes liveness
    manager.record_connection("device-b")
    assert manager.get_status("device-b") is TrustStatus.TRUSTED


def test_inactivity_policy_measures_from_pairing_when_never_connected(clock):
    manager = TrustManager(
        InMemoryTrustStore(), policy=DefaultTrustPolicy(max_inactivity_seconds=DAY), clock=clock
    )
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)

    clock.advance(DAY + 1)
    assert manager.get_status("device-b") is TrustStatus.EXPIRED


def test_default_policy_has_inactivity_disabled(manager, clock):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    clock.advance(365 * DAY)
    assert manager.get_status("device-b") is TrustStatus.TRUSTED


def test_maximum_key_age_policy_forces_rotation(clock):
    manager = TrustManager(
        InMemoryTrustStore(), policy=MaximumKeyAgePolicy(max_age_seconds=90 * DAY), clock=clock
    )
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)

    clock.advance(91 * DAY)
    assert manager.get_status("device-b") is TrustStatus.EXPIRED

    manager.rotate_key("device-b", X25519_B, MLKEM_B)
    assert manager.get_status("device-b") is TrustStatus.TRUSTED


def test_composite_policy_first_failure_wins(clock):
    manager = TrustManager(
        InMemoryTrustStore(),
        policy=CompositeTrustPolicy([DefaultTrustPolicy(), MaximumKeyAgePolicy(90 * DAY)]),
        clock=clock,
    )
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    assert manager.get_status("device-b") is TrustStatus.TRUSTED

    manager.revoke_trust("device-b")
    assert manager.get_status("device-b") is TrustStatus.REVOKED


def test_composite_policy_requires_at_least_one_member():
    with pytest.raises(ValueError):
        CompositeTrustPolicy([])


def test_always_trust_policy_ignores_revocation(clock):
    manager = TrustManager(InMemoryTrustStore(), policy=AlwaysTrustPolicy(), clock=clock)
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    manager.revoke_trust("device-b")

    assert manager.get_status("device-b") is TrustStatus.TRUSTED


def test_policy_is_injectable_without_touching_the_manager(clock):
    """The Open/Closed claim: a brand-new rule needs no change to TrustManager."""

    class BlocklistPolicy(DefaultTrustPolicy):
        def __init__(self, blocked):
            super().__init__()
            self.blocked = blocked

        def evaluate(self, record, now):
            if record.device_id in self.blocked:
                return TrustStatus.REVOKED
            return super().evaluate(record, now)

    manager = TrustManager(InMemoryTrustStore(), policy=BlocklistPolicy({"device-b"}), clock=clock)
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)

    assert manager.get_status("device-b") is TrustStatus.REVOKED


# ====================================================================== key lifecycle


def test_rotate_key_increments_version_and_archives_the_old_one(manager, clock):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    rotated_at = clock.advance(DAY)

    record = manager.rotate_key("device-b", X25519_B, MLKEM_B)

    assert record.key_version == 2
    assert record.x25519_pub == X25519_B
    assert record.mlkem_pub == MLKEM_B
    assert len(record.key_history) == 1

    retired = record.key_history[0]
    assert retired.version == 1
    assert retired.x25519_pub == X25519_A
    assert retired.retired_at == rotated_at
    assert record.current_key.created_at == rotated_at


def test_rotate_key_preserves_device_identity(manager):
    before = manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, alias="Phone")
    after = manager.rotate_key("device-b", X25519_B, MLKEM_B)

    assert after.uuid == before.uuid
    assert after.alias == "Phone"
    assert after.paired_at == before.paired_at


def test_rotate_key_can_update_the_fingerprint(manager):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    record = manager.rotate_key("device-b", X25519_B, MLKEM_B, fingerprint="NEW-FINGERPRINT")
    assert record.fingerprint == "NEW-FINGERPRINT"


def test_rotate_key_leaves_fingerprint_alone_when_not_supplied(manager):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    assert manager.rotate_key("device-b", X25519_B, MLKEM_B).fingerprint == FINGERPRINT


def test_repeated_rotations_build_ordered_history(manager):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    manager.rotate_key("device-b", X25519_B, MLKEM_B)
    manager.rotate_key("device-b", b"\x05" * 32, b"\x06" * 1184)

    assert manager.get_key_version("device-b") == 3
    assert [k.version for k in manager.get_key_history("device-b")] == [1, 2, 3]


def test_rotate_to_identical_key_rejected(manager):
    """A no-op rotation is almost always a caller bug; accepting it would inflate the version
    counter while leaving the device on unchanged key material."""
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)

    with pytest.raises(KeyRotationError):
        manager.rotate_key("device-b", X25519_A, MLKEM_A)
    assert manager.get_key_version("device-b") == 1


def test_rotate_unknown_device_raises(manager):
    with pytest.raises(DeviceNotFoundError):
        manager.rotate_key("ghost", X25519_B, MLKEM_B)


def test_get_key_by_version(manager):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    manager.rotate_key("device-b", X25519_B, MLKEM_B)

    assert manager.get_key("device-b", version=1).x25519_pub == X25519_A
    assert manager.get_key("device-b", version=2).x25519_pub == X25519_B
    assert manager.get_key("device-b").x25519_pub == X25519_B  # None -> current


def test_get_unknown_key_version_raises(manager):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    with pytest.raises(KeyRotationError, match="no key version 9"):
        manager.get_key("device-b", version=9)


def test_rotation_does_not_alter_trust_status(manager):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    manager.revoke_trust("device-b")
    manager.rotate_key("device-b", X25519_B, MLKEM_B)

    assert manager.get_status("device-b") is TrustStatus.REVOKED


# ====================================================================== backup


def test_export_and_import_database_round_trip(manager, tmp_path, clock):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, alias="Phone")
    manager.register_device("device-c", X25519_B, MLKEM_B, "OTHER", alias="Laptop")
    manager.rotate_key("device-c", X25519_A, MLKEM_A)
    manager.revoke_trust("device-b", reason="stolen")

    export_path = manager.export_database(tmp_path / "backup.json")
    assert export_path.exists()

    restored = TrustManager(InMemoryTrustStore(), clock=clock)
    imported = restored.import_database(export_path)

    assert len(imported) == 2
    assert {d.device_id for d in restored.list_devices()} == {"device-b", "device-c"}

    phone = restored.get_device("device-b")
    assert phone.alias == "Phone"
    assert phone.x25519_pub == X25519_A
    assert phone.uuid == manager.get_device("device-b").uuid
    assert phone.revoked is True
    assert phone.revocation_reason == "stolen"
    assert restored.get_status("device-b") is TrustStatus.REVOKED

    laptop = restored.get_device("device-c")
    assert laptop.key_version == 2
    assert [k.version for k in laptop.all_keys()] == [1, 2]
    assert laptop.key_history[0].x25519_pub == X25519_B


def test_export_is_self_describing_json(populated, tmp_path):
    path = populated.export_database(tmp_path / "backup.json")
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["schema_version"] == 1
    assert "exported_at" in payload
    assert isinstance(payload["devices"], list)
    assert payload["devices"][0]["device_id"] == "device-b"


def test_export_creates_missing_parent_directories(populated, tmp_path):
    path = populated.export_database(tmp_path / "nested" / "dir" / "backup.json")
    assert path.exists()


def test_import_skip_existing_is_the_default(manager, tmp_path, clock):
    """The conservative default: an import must not silently clobber local records (and their
    revocation state) unless the caller explicitly asks."""
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, alias="Original")
    export_path = manager.export_database(tmp_path / "backup.json")

    other = TrustManager(InMemoryTrustStore(), clock=clock)
    other.register_device("device-b", X25519_B, MLKEM_B, "LOCAL", alias="Local")
    other.revoke_trust("device-b", reason="local decision")

    written = other.import_database(export_path)

    assert written == []
    assert other.get_device("device-b").alias == "Local"
    assert other.get_status("device-b") is TrustStatus.REVOKED


def test_import_overwrite_existing(manager, tmp_path, clock):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, alias="Original")
    export_path = manager.export_database(tmp_path / "backup.json")

    other = TrustManager(InMemoryTrustStore(), clock=clock)
    other.register_device("device-b", X25519_B, MLKEM_B, "LOCAL", alias="Local")
    other.register_device("device-z", X25519_B, MLKEM_B, "KEEP", alias="Keeper")

    other.import_database(export_path, mode=ImportMode.OVERWRITE_EXISTING)

    assert other.get_device("device-b").alias == "Original"
    assert other.find_device("device-z") is not None  # untouched, not part of the import


def test_import_replace_discards_local_records(manager, tmp_path, clock):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    export_path = manager.export_database(tmp_path / "backup.json")

    other = TrustManager(InMemoryTrustStore(), clock=clock)
    other.register_device("device-z", X25519_B, MLKEM_B, "GONE")

    other.import_database(export_path, mode=ImportMode.REPLACE)

    assert [d.device_id for d in other.list_devices()] == ["device-b"]


def test_import_of_empty_database_is_valid(manager, tmp_path, clock):
    export_path = manager.export_database(tmp_path / "empty.json")
    other = TrustManager(InMemoryTrustStore(), clock=clock)
    assert other.import_database(export_path) == []


def test_import_missing_file_raises(manager, tmp_path):
    with pytest.raises(TrustImportError):
        manager.import_database(tmp_path / "does-not-exist.json")


def test_import_malformed_json_raises(manager, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(TrustImportError):
        manager.import_database(path)


def test_import_wrong_envelope_raises(manager, tmp_path):
    path = tmp_path / "wrong.json"
    path.write_text(json.dumps({"schema_version": 1, "peers": []}), encoding="utf-8")
    with pytest.raises(TrustImportError, match="not a trust export"):
        manager.import_database(path)


def test_import_unsupported_schema_version_raises(manager, tmp_path):
    path = tmp_path / "future.json"
    path.write_text(json.dumps({"schema_version": 99, "devices": []}), encoding="utf-8")
    with pytest.raises(TrustImportError, match="schema_version"):
        manager.import_database(path)


def test_import_malformed_record_leaves_database_untouched(populated, tmp_path):
    """Validation happens before any write, so a bad file cannot half-replace the database."""
    path = tmp_path / "bad-record.json"
    path.write_text(
        json.dumps({"schema_version": 1, "devices": [{"device_id": "x"}]}), encoding="utf-8"
    )

    with pytest.raises(TrustImportError, match="malformed device record"):
        populated.import_database(path, mode=ImportMode.REPLACE)

    assert [d.device_id for d in populated.list_devices()] == ["device-b"]


# ====================================================================== persistence


def test_json_store_round_trip_across_manager_instances(tmp_path, clock):
    path = tmp_path / "trust_db.json"

    first = TrustManager(JsonTrustStore(path), clock=clock)
    first.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, alias="Phone")
    first.rotate_key("device-b", X25519_B, MLKEM_B)
    first.revoke_trust("device-b", reason="stolen")

    second = TrustManager(JsonTrustStore(path), clock=clock)
    record = second.get_device("device-b")

    assert record.alias == "Phone"
    assert record.key_version == 2
    assert record.x25519_pub == X25519_B
    assert record.key_history[0].x25519_pub == X25519_A
    assert second.get_status("device-b") is TrustStatus.REVOKED


def test_json_store_starts_empty_when_file_absent(tmp_path, clock):
    manager = TrustManager(JsonTrustStore(tmp_path / "absent.json"), clock=clock)
    assert manager.list_devices() == []


def test_json_store_creates_parent_directories(tmp_path, clock):
    manager = TrustManager(JsonTrustStore(tmp_path / "a" / "b" / "trust.json"), clock=clock)
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)
    assert (tmp_path / "a" / "b" / "trust.json").exists()


def test_corrupt_store_raises_rather_than_starting_empty(tmp_path):
    """Silently discarding an unreadable trust database would downgrade every paired peer to
    'unknown', which in a deployment that auto-pairs unknown peers invites re-pairing attacks."""
    path = tmp_path / "corrupt.json"
    path.write_text("this is not json", encoding="utf-8")

    with pytest.raises(TrustStoreCorruptError):
        JsonTrustStore(path).load()


def test_store_with_unknown_schema_version_raises(tmp_path):
    path = tmp_path / "future.json"
    path.write_text(json.dumps({"schema_version": 99, "devices": {}}), encoding="utf-8")

    with pytest.raises(TrustStoreCorruptError, match="schema_version"):
        JsonTrustStore(path).load()


def test_registry_returns_copies_not_live_references(populated):
    """Mutating a returned record must not change stored state -- otherwise callers could
    bypass persistence and silently desynchronise memory from disk."""
    record = populated.get_device("device-b")
    record.alias = "Mutated"
    record.revoked = True

    stored = populated.get_device("device-b")
    assert stored.alias == "Kanika's phone"
    assert stored.revoked is False


def test_in_memory_store_isolates_saved_records(clock):
    backend = InMemoryTrustStore()
    manager = TrustManager(backend, clock=clock)
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT)

    snapshot = backend.load()
    snapshot["device-b"].alias = "Mutated"

    assert manager.get_device("device-b").alias == "device-b"


# ====================================================================== integration adapter


def test_protocol_peer_store_matches_legacy_shape(populated):
    """The adapter must return exactly the keys proximity_protocol.py reads, so no protocol
    code changes."""
    peer_store = ProtocolPeerStore(populated)
    peer = peer_store.get_peer("device-b")

    assert peer is not None
    assert peer["x25519_pub"] == X25519_A
    assert peer["mlkem_pub"] == MLKEM_A
    assert peer["fingerprint"] == FINGERPRINT
    assert "paired_at" in peer


def test_protocol_peer_store_hides_revoked_devices(populated):
    """Revocation becomes enforceable inside the unmodified proximity protocol: get_peer
    returning None is already how that code detects an unpaired peer."""
    peer_store = ProtocolPeerStore(populated)
    populated.revoke_trust("device-b", reason="stolen")

    assert peer_store.get_peer("device-b") is None
    assert peer_store.is_paired("device-b") is False
    assert peer_store.list_peers() == []


def test_protocol_peer_store_hides_expired_devices(manager, clock):
    manager.register_device("device-b", X25519_A, MLKEM_A, FINGERPRINT, valid_for_seconds=DAY)
    peer_store = ProtocolPeerStore(manager)
    assert peer_store.get_peer("device-b") is not None

    clock.advance(DAY + 1)
    assert peer_store.get_peer("device-b") is None


def test_protocol_peer_store_revocation_is_indistinguishable_from_unknown(populated):
    """A revoked peer and a never-paired peer must look identical to an attacker; reporting
    'revoked' would leak the device's history."""
    peer_store = ProtocolPeerStore(populated)
    populated.revoke_trust("device-b")

    assert peer_store.get_peer("device-b") == peer_store.get_peer("never-paired")


def test_protocol_peer_store_records_completed_sessions(populated, clock):
    peer_store = ProtocolPeerStore(populated)
    clock.advance(60)
    peer_store.note_session_complete("device-b")

    assert populated.get_device("device-b").last_connected_at == clock.now()


def test_note_session_complete_tolerates_removed_device(populated):
    peer_store = ProtocolPeerStore(populated)
    populated.remove_device("device-b")
    peer_store.note_session_complete("device-b")  # must not raise


def test_migrate_legacy_store(manager):
    """Migration from the original pairing/trust_store.py shape, using a structural double so
    the test needs no crypto stack."""

    class LegacyStore:
        def __init__(self, peers):
            self._peers = peers

        def list_peers(self):
            return list(self._peers)

        def get_peer(self, peer_id):
            return self._peers.get(peer_id)

    legacy = LegacyStore(
        {
            "device-b": {
                "x25519_pub": X25519_A,
                "mlkem_pub": MLKEM_A,
                "fingerprint": FINGERPRINT,
                "paired_at": 1234.0,
            }
        }
    )

    migrated = migrate_legacy_store(manager, legacy)

    assert len(migrated) == 1
    record = manager.get_device("device-b")
    assert record.x25519_pub == X25519_A
    assert record.paired_at == 1234.0  # original pairing time preserved
    assert record.key_version == 1
    assert manager.get_status("device-b") is TrustStatus.TRUSTED


def test_migrate_legacy_store_is_rerunnable(manager):
    class LegacyStore:
        def list_peers(self):
            return ["device-b"]

        def get_peer(self, peer_id):
            return {
                "x25519_pub": X25519_A,
                "mlkem_pub": MLKEM_A,
                "fingerprint": FINGERPRINT,
                "paired_at": 1234.0,
            }

    legacy = LegacyStore()
    migrate_legacy_store(manager, legacy)
    manager.revoke_trust("device-b", reason="revoked after migration")

    assert migrate_legacy_store(manager, legacy) == []
    assert manager.get_status("device-b") is TrustStatus.REVOKED
