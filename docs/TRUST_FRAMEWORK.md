# Security Lifecycle & Trust Management Framework

The `trust/` package answers a question the cryptographic protocol deliberately does not:
**should we still be talking to this device?**

The existing system establishes trust once, at pairing, and treats it as permanent. `docs/SECURITY_ANALYSIS.md`
names this as a known limitation:

> **Malicious but genuinely-paired peers.** Trust is binary and long-term once established --
> there's no revocation flow in this demo [...] and a paired device is fully trusted for every
> future encounter.

This framework closes that gap. It adds revocation, expiry, key-version tracking, aliasing,
search, and backup on top of the existing protocol **without changing a line of it**.

> **Scope boundary:** this package contains **no cryptographic primitives**. It stores public
> keys and fingerprints produced by `core/` and `pairing/`, and decides which peers are usable.
> X25519, ML-KEM-768, HKDF, ASCON-128a, the QR pairing handshake, the proximity handshake, and
> both transports are untouched.

---

## 1. Architecture

### Layering

Dependencies point strictly inward. Nothing in an inner ring knows the ring outside it exists.

```
        ┌────────────────────────────────────────────────────────┐
        │  integration.py        adapters to the existing system  │
        │  ┌──────────────────────────────────────────────────┐  │
        │  │  trust_manager.py    façade / orchestration       │  │
        │  │  ┌────────────────────────────────────────────┐  │  │
        │  │  │ device_registry.py  │  trust_policy.py     │  │  │
        │  │  │      (CRUD)         │    (decisions)       │  │  │
        │  │  │  ┌──────────────────────────────────────┐  │  │  │
        │  │  │  │ models.py  ·  exceptions.py           │  │  │  │
        │  │  │  │        (pure domain)                  │  │  │  │
        │  │  │  └──────────────────────────────────────┘  │  │  │
        │  │  └────────────────────────────────────────────┘  │  │
        │  │        trust_store.py  (persistence port)         │  │
        │  └──────────────────────────────────────────────────┘  │
        └────────────────────────────────────────────────────────┘
```

`models.py` and `exceptions.py` import nothing but the standard library. `trust_store.py`
defines a *port* (`TrustStoreBackend`) that outer layers implement, so persistence is a plug-in
rather than a dependency.

### File responsibilities

| File | Responsibility | Depends on |
|---|---|---|
| `models.py` | Dataclasses, enums, `Clock` protocol. No behaviour beyond serialization. | stdlib |
| `exceptions.py` | Error hierarchy. | `models` |
| `trust_store.py` | `TrustStoreBackend` port + JSON and in-memory adapters. | `models`, `exceptions` |
| `device_registry.py` | CRUD, search, atomic mutation. **No trust decisions.** | `trust_store`, `models` |
| `trust_policy.py` | Pure `(record, now) -> TrustStatus` rules. **No I/O.** | `models`, `exceptions` |
| `trust_manager.py` | Façade: orchestration, key lifecycle, backup. | all of the above |
| `integration.py` | Adapters to `pairing/` and `proximity/`. | `trust_manager` |

### How SOLID shows up here

- **Single responsibility** — the registry stores, the policy decides, the backend persists, the
  manager orchestrates. The registry will happily hand you a revoked record; refusing to use it
  is someone else's job. That split is why the policy is testable with no storage and the
  registry is testable with no clock.
- **Open/closed** — a new trust rule is a new `TrustPolicy` subclass, injected at construction.
  `TrustManager` never changes. `tests/test_trust_framework.py::test_policy_is_injectable_without_touching_the_manager`
  demonstrates a blocklist rule added with zero framework edits.
- **Liskov** — `TrustPolicy.validate()` is implemented once on the base class in terms of the
  abstract `evaluate()`. Any subclass overriding only `evaluate()` inherits correct raising
  behaviour, and the status→exception mapping cannot drift between implementations.
- **Interface segregation** — `TrustStoreBackend` is two methods (`load`/`save`). A backend
  author implements a snapshot read and a snapshot write; transaction management and locking
  stay in the registry rather than being re-solved by every implementation.
- **Dependency inversion** — `TrustManager` depends on the `TrustStoreBackend`, `TrustPolicy`,
  and `Clock` abstractions, never on `JsonTrustStore`, `DefaultTrustPolicy`, or `time.time()`.
  Every one is constructor-injected with a sane default.

---

## 2. Design decisions

### Trust status is derived, never stored

A record persists only primitive facts — `revoked`, `revoked_at`, `expires_at` — and
`TrustPolicy` computes a `TrustStatus` from them at read time.

*Why:* a stored `status` column plus the flags that determine it are two sources of truth that
drift. A record could be written `status="trusted"` with `expires_at` in the past after a clock
change or a partial write, and every subsequent read would trust a device that should have
lapsed. Deriving on read makes that class of bug unrepresentable.

### Revoked outranks expired

`DefaultTrustPolicy` reports `REVOKED` when a device is both revoked and past its deadline.

*Why:* revocation is a deliberate decision by a human or an incident-response process; expiry is
a passive deadline. Reporting the deadline would hide the decision, and would let an operator
"fix" the device by renewing its expiry — appearing to restore a device that was in fact revoked
because it was stolen.

### Registration is not idempotent

`register_device` on an existing `device_id` raises `DuplicateDeviceError` rather than
overwriting.

*Why:* an overwrite silently discards the record's key history **and its revocation state**. If
re-registration were allowed, any path that can trigger a re-pair becomes a way to launder a
revocation. Callers that genuinely want new key material use `rotate_key`; callers that want a
clean slate call `remove_device` first, which is explicit.

### Revocation and removal are different operations

| | keeps record | keeps key history | reversible |
|---|---|---|---|
| `revoke_trust` | yes | yes | yes, via `restore_trust` |
| `remove_device` | no | no | no |

*Why:* revocation is the security operation and needs an audit trail — you want to know that a
device was trusted, when trust was withdrawn, and why. Removal is the user-facing "unpair" and
should genuinely forget. Collapsing them into one operation would force a choice between losing
the audit trail and never truly forgetting a device.

### Revocation is invisible on the wire

`ProtocolPeerStore.get_peer()` returns `None` for a revoked device — byte-identical to the
answer for a device that was never paired.

*Why:* a distinct "you were revoked" response tells an attacker holding a stolen device that the
theft was noticed, and tells any prober that a given `device_id` was once trusted here. Both are
history leaks. Uniform rejection reveals nothing.

### A corrupt store raises instead of starting empty

`JsonTrustStore.load()` raises `TrustStoreCorruptError` when the file exists but cannot be
parsed.

*Why:* silently returning `{}` downgrades every paired peer to "unknown". In a deployment that
treats unknown peers as pairable, an attacker who can corrupt the trust file can therefore
trigger a re-pairing window. Failing loudly turns a stealthy security downgrade into a visible
outage.

### Import validates completely before writing anything

`import_database` parses and validates every record before the first write, and `SKIP_EXISTING`
is the default mode.

*Why:* a malformed file must not half-replace a trust database. And an import should not be able
to clobber a local record — silently resurrecting a locally-revoked device from a stale backup
is exactly the kind of quiet trust regression this framework exists to prevent. Overwriting is
available, but the caller has to ask for it by name.

### `last_connected_at` is stamped after success, never on attempt

*Why:* it feeds the inactivity rule in `DefaultTrustPolicy(max_inactivity_seconds=...)`. Stamping
on connection *attempt* would let an attacker who cannot authenticate keep a stale device's trust
alive indefinitely just by connecting to it.

### Time is injected

Everything reads the clock through the `Clock` protocol.

*Why:* expiry is the one feature that is otherwise untestable without `sleep()`. With
`FixedClock`, `test_expired_device` advances a day instantly and the whole suite runs in 0.36s.

### The core package has no crypto dependencies

`import trust` pulls in only the standard library. `integration.py` is excluded from
`trust/__init__.py`, and its `pairing` imports are deferred to call time.

*Why:* `liboqs` takes several minutes to build from source (see `README.md`). Trust logic — which
is pure bookkeeping — should not require a crypto toolchain, a BLE stack, or a webcam to test.
The 88 tests in `tests/test_trust_framework.py` run in a bare Python install.

---

## 3. API reference

### Construction

```python
from trust import TrustManager, JsonTrustStore, DefaultTrustPolicy

manager = TrustManager(JsonTrustStore("trust_db.json"))

# fully specified
manager = TrustManager(
    backend=JsonTrustStore("trust_db.json"),
    policy=DefaultTrustPolicy(max_inactivity_seconds=30 * 86400),
    clock=SystemClock(),
)
```

### Device registry

| Method | Returns | Raises |
|---|---|---|
| `register_device(device_id, x25519_pub, mlkem_pub, fingerprint, alias=None, expires_at=None, valid_for_seconds=None, metadata=None)` | `DeviceRecord` | `DuplicateDeviceError`, `ValueError` |
| `remove_device(device_id)` | `None` | `DeviceNotFoundError` |
| `rename_device(device_id, alias)` | `DeviceRecord` | `DeviceNotFoundError`, `ValueError` |
| `get_device(device_id)` | `DeviceRecord` | `DeviceNotFoundError` |
| `find_device(device_id)` | `DeviceRecord \| None` | — |
| `list_devices(status=None)` | `list[DeviceRecord]` | — |
| `search_devices(query="", status=None, predicate=None)` | `list[DeviceRecord]` | — |

`search_devices` matches case-insensitively across alias, `device_id`, `uuid`, and fingerprint,
then applies the optional status filter and predicate.

### Trust metadata (`DeviceRecord`)

| Field | Type | Notes |
|---|---|---|
| `device_id` | `str` | On-the-wire identifier; the registry key. |
| `uuid` | `str` | Immutable local primary key, generated at registration. |
| `alias` | `str` | Human-facing name. |
| `current_key` | `KeyMaterial` | Current generation; `.x25519_pub` / `.mlkem_pub` / `.key_version` are shortcuts. |
| `key_history` | `list[KeyMaterial]` | Retired generations, oldest first. |
| `fingerprint` | `str` | Safety number from the pairing protocol. Stored verbatim. |
| `paired_at` | `float` | POSIX timestamp of pairing. |
| `last_connected_at` | `float \| None` | Set by `record_connection`. |
| `revoked` / `revoked_at` / `revocation_reason` | `bool` / `float?` / `str?` | Revocation state. |
| `expires_at` | `float \| None` | `None` means never expires. |
| `metadata` | `dict` | Free-form; round-trips through persistence and export. |

Trust status is **not** a field — call `manager.get_status(device_id)`.

### Trust policies

| Method | Returns | Raises |
|---|---|---|
| `get_status(device_id)` | `TrustStatus` | `DeviceNotFoundError` |
| `is_trusted(device_id)` | `bool` (`False` for unknown) | — |
| `validate_session(device_id)` | `DeviceRecord` | `DeviceNotFoundError`, `DeviceRevokedError`, `DeviceExpiredError` |
| `revoke_trust(device_id, reason=None)` | `DeviceRecord` | `DeviceNotFoundError` |
| `restore_trust(device_id, expires_at=None, valid_for_seconds=None, clear_expiry=True)` | `DeviceRecord` | `DeviceNotFoundError` |
| `expire_trust(device_id)` | `DeviceRecord` | `DeviceNotFoundError` |
| `set_expiry(device_id, expires_at=None, valid_for_seconds=None)` | `DeviceRecord` | `DeviceNotFoundError` |
| `record_connection(device_id)` | `DeviceRecord` | `DeviceNotFoundError` |

**Validate before every session:**

```python
try:
    record = manager.validate_session(peer_id)
except TrustValidationError as e:
    log(f"refusing session with {peer_id}: {e} (status={e.status})")
    return
```

Bundled policies: `DefaultTrustPolicy(max_inactivity_seconds=None)`,
`MaximumKeyAgePolicy(max_age_seconds)`, `CompositeTrustPolicy([...])`, `AlwaysTrustPolicy()`.

### Key lifecycle

| Method | Returns | Raises |
|---|---|---|
| `rotate_key(device_id, x25519_pub, mlkem_pub, fingerprint=None)` | `DeviceRecord` | `DeviceNotFoundError`, `KeyRotationError`, `ValueError` |
| `get_key_version(device_id)` | `int` | `DeviceNotFoundError` |
| `get_key(device_id, version=None)` | `KeyMaterial` | `DeviceNotFoundError`, `KeyRotationError` |
| `get_key_history(device_id)` | `list[KeyMaterial]` | `DeviceNotFoundError` |

`rotate_key` archives the outgoing generation with a `retired_at` stamp and installs the new one
at `version + 1`. **It performs no cryptography** — generating the new keypair and agreeing it
with the peer is the caller's job, using the existing `core/` primitives. That is precisely what
makes rotation supportable without touching the protocol. Rotating to identical key material
raises `KeyRotationError`, since a no-op rotation that bumps the version counter is almost always
a caller bug.

### Backup

| Method | Returns | Raises |
|---|---|---|
| `export_database(path)` | `Path` | `TrustExportError` |
| `import_database(path, mode=ImportMode.SKIP_EXISTING)` | `list[DeviceRecord]` written | `TrustImportError` |

Modes: `SKIP_EXISTING` (default), `OVERWRITE_EXISTING`, `REPLACE`.

Export format — deliberately backend-independent, so a database exported from JSON imports
unchanged into a future SQLite or keychain store:

```json
{ "schema_version": 1, "exported_at": 1700000000.0, "devices": [ /* full records */ ] }
```

Exports contain **public keys and metadata only, never private key material**. They do define
which devices this one trusts, so an attacker who can substitute an export before import can
insert their own key under a trusted `device_id`. Treat exports as integrity-sensitive and
transfer them over an authenticated channel.

---

## 4. Integrating with the existing protocol

`proximity/proximity_protocol.py` reaches its peer store through exactly one method —
`get_peer(peer_id)`, returning a dict or `None` — and already treats `None` as
`UnpairedPeerError` on both the initiator ([`:128`](../proximity/proximity_protocol.py#L128)) and
responder ([`:165`](../proximity/proximity_protocol.py#L165)) paths.

`ProtocolPeerStore` implements that same shape over a `TrustManager` and returns `None` for any
device the policy does not currently trust. Revocation and expiry therefore become enforceable
at the session boundary with **no protocol change**:

```python
from trust import TrustManager, JsonTrustStore
from trust.integration import ProtocolPeerStore
from proximity.proximity_protocol import respond_to_encounter

manager = TrustManager(JsonTrustStore("trust_db.json"))
peer_store = ProtocolPeerStore(manager)

peer_id, token = respond_to_encounter(transport, identity, peer_store, my_token)  # unchanged
peer_store.note_session_complete(peer_id)
```

A revoked peer is now rejected *before* the MAC is computed, and cannot tell the difference
between "revoked" and "never paired".

**Registering after pairing:**

```python
from trust.integration import register_paired_peer

fingerprint, peer = complete_pairing(identity, response)   # existing code, unchanged
register_paired_peer(manager, peer, fingerprint, alias="Kanika's phone")
```

**Migrating an existing deployment** from `pairing/trust_store.py`:

```python
from trust.integration import migrate_legacy_store

migrate_legacy_store(manager, TrustStore("trust_store.json"))
```

One-way and re-runnable: peers already present are skipped, so a repeat migration cannot
resurrect a device revoked after the first run. Original `paired_at` timestamps are preserved.

> `pairing/trust_store.py` is **not** modified or deprecated by this framework. It remains the
> protocol's own minimal store; `trust/trust_store.py` is a separate, richer persistence layer in
> a different package.

---

## 5. Testing

`tests/test_trust_framework.py` — 88 tests, ~0.4s, no crypto stack, no network, no sleeping.

```bash
python -m pytest tests/test_trust_framework.py -q
```

Coverage of the required cases:

| Case | Tests |
|---|---|
| Register device | `test_register_device`, `test_register_defaults_alias_to_device_id`, `test_register_assigns_unique_uuids` |
| Duplicate registration | `test_duplicate_registration_rejected`, `test_duplicate_registration_does_not_clear_revocation` |
| Rename device | `test_rename_device`, `test_rename_preserves_identity_and_trust`, `test_rename_rejects_blank_alias` |
| Remove device | `test_remove_device`, `test_remove_unknown_device_raises`, `test_remove_is_not_reversible_unlike_revoke` |
| Revoke trust | `test_revoke_trust`, `test_revoked_device_fails_session_validation`, `test_revoke_is_idempotent` |
| Restore trust | `test_restore_trust`, `test_restore_clears_lapsed_expiry_by_default`, `test_restore_can_preserve_existing_expiry` |
| Expired device | `test_expired_device`, `test_expiry_boundary_is_inclusive`, `test_revocation_takes_precedence_over_expiry` |
| Invalid device lookup | `test_invalid_device_lookup_raises`, `test_status_of_unknown_device_raises` |
| Import / export | `test_export_and_import_database_round_trip`, plus 8 mode and malformed-input tests |

Beyond the required set: search and filtering, all four policies, policy injection, key rotation
and history, JSON persistence across manager instances, corrupt-store and schema-version
handling, defensive copying, and the `ProtocolPeerStore` / migration adapters.

---

## 6. Future extensibility

**Already supported by the existing seams:**

- *A different store* — implement `TrustStoreBackend.load`/`save` (SQLite, OS keychain, TPM) and
  pass it to `TrustManager`. Nothing else changes.
- *A new trust rule* — subclass `TrustPolicy`, or stack rules with `CompositeTrustPolicy`.
  Candidates: hardware attestation, per-network allow-lists, time-of-day windows.
- *Extra per-device fields* — use `DeviceRecord.metadata`, which round-trips through persistence
  and export without a schema change.

**Natural next steps, in rough priority order:**

1. **Wire the adapter into the demos.** `demo/device_a.py` and `demo/device_b.py` still use the
   original `pairing/trust_store.py`. Switching them to `ProtocolPeerStore` would let the demo
   show a revoked device being turned away — a stronger demonstration than the current
   `--as-stranger` flag, which only covers a never-paired peer.
2. **Encryption at rest.** `SECURITY_ANALYSIS.md` notes `identity.json` holds private keys in
   plaintext. The trust database holds no private keys, but it is integrity-critical: an
   attacker who can rewrite it can insert their own public key under a trusted `device_id`. A
   MAC over the store, keyed from the device identity, would detect that.
3. **A revocation transport.** Revocation is currently local-only — device A can revoke B, but B
   does not learn of it. A signed revocation notice distributed at the next encounter would make
   it bilateral.
4. **Rotation as a protocol flow.** `rotate_key` records the *outcome* of a rotation; agreeing new
   keys with a peer over an authenticated channel is not implemented. That is a protocol-layer
   addition, and the deliberate reason this framework stops at recording versions.
5. **Schema migrations.** `SCHEMA_VERSION` is checked and rejected on mismatch. A version-2 format
   would want an upgrade path rather than a hard failure.

**Deliberately out of scope:** anything that generates, derives, verifies, or compares key
material. That belongs in `core/` and `pairing/`, and keeping it out is what lets this framework
evolve without any risk to the audited crypto path.

---

## 7. Relationship to `SECURITY_ANALYSIS.md`

That document's "Malicious but genuinely-paired peers" limitation — no revocation, binary
permanent trust — is addressed *when `ProtocolPeerStore` is wired in*. Until the demos adopt the
adapter (item 1 above), the protocol as shipped still has no revocation, so that section remains
accurate for the current demo path and has intentionally been left unedited.

The other documented limitations are unaffected: this framework does not change physical-compromise
resistance, QR substitution, traffic analysis, or DoS behaviour.
