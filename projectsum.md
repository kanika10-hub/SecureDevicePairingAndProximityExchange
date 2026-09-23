# Secure Device Pairing and Proximity Exchange — Project Summary

## What This Project Is

A working, cryptographically rigorous system that solves two core problems:

1. How do two devices establish mutual trust for the first time, without being vulnerable to a man-in-the-middle?
2. After that trust is established, how do they automatically and securely reconnect every time they come near each other again?

Think of it as a transparent, open-source, quantum-resistant version of how AirDrop or Signal handle device pairing.

---

## The Problems Being Solved

### Problem 1: Initial Pairing Is Insecure by Default
Over a network, two devices can't verify each other's identity without a pre-shared secret. A classic MITM attack: Mallory sits between Alice and Bob, pretending to be each side. Both devices think they're talking to each other but are actually talking to Mallory.

**Solution:** The QR code is the out-of-band channel. Device A's public keys travel only over the QR — a physical/visual channel a remote network attacker cannot intercept. You can't MITM what you can't see.

### Problem 2: "Harvest Now, Decrypt Later" from Quantum Computers
Today's classical crypto (X25519 / Elliptic Curve DH) will be broken by future quantum computers. An attacker recording traffic today could decrypt it years later.

**Solution:** Hybrid key exchange — both X25519 (classical) and ML-KEM-768 (post-quantum, NIST FIPS 203). The session key requires breaking **both** simultaneously. A quantum computer breaking X25519 still leaves ML-KEM-768 intact.

### Problem 3: Reconnects Need to Be Authenticated Without Re-Pairing
Every time two devices see each other on WiFi or BLE, they need fresh session keys (forward secrecy) but also need to prove they're the same devices that originally paired — without scanning a QR again.

**Solution:** The long-term X25519 DH result from pairing acts as a permanent shared secret. This gets HKDF'd into a MAC key. Every proximity handshake signs the fresh ephemeral public keys with that MAC. An attacker without the original private key cannot forge the MAC.

### Problem 4: Paired Doesn't Mean Trusted Forever
Before the trust framework was added, once two devices paired, you couldn't revoke that trust without manually deleting a file. If a device was lost or stolen, there was no "cut access" switch.

**Solution:** The `trust/` module gives every peer a trust status: `TRUSTED`, `REVOKED`, or `EXPIRED`. The proximity protocol checks this before every single handshake. A revoked device gets rejected with the exact same error as a stranger — deliberately — so an attacker can't tell whether they were specifically revoked or never paired.

---

## The Crypto Stack (Layer by Layer)

```
┌──────────────────────────────────────────────────────────┐
│  Application Layer: tokens / messages                    │
│  Encrypted with ASCON-128a AEAD                          │
├──────────────────────────────────────────────────────────┤
│  Session Key: 16 bytes, from               │
│  Input: X25519 shared secret ++ ML-KEM-768 shared secret │
├────────────────────────┬─────────────────────────────────┤
│  Classical KEX         │  Post-Quantum KEX               │
│  X25519 (Curve25519)   │  ML-KEM-768 (NIST FIPS 203)     │
│  ~32 byte shared secret│  KEM: encapsulate/decapsulate   │
└────────────────────────┴─────────────────────────────────┘
```

**Why ASCON instead of AES?** ASCON won the NIST Lightweight Crypto competition (SP 800-232, 2023). It's designed for constrained devices (IoT, BLE microcontrollers) — no hardware AES acceleration needed, smaller RAM footprint. AES is secure and right for most systems; ASCON is the deliberate choice here because the "device" may be a microcontroller.

---

## The Two Protocols in Detail

### Protocol 1: QR Pairing (one-time setup)

```
Device A                              Device B
  │                                      │
  │── Generates long-term identity       │
  │   (X25519 keypair + ML-KEM keypair)  │
  │                                      │
  │══ QR Code (out-of-band, physical) ═>│
  │   [device_id_A, x25519_pub_A,        │
  │    mlkem_pub_A]                      │
  │                                      │
  │                B scans QR, derives   │
  │                session key via DH +  │
  │                ML-KEM encapsulation  │
  │                Sends own identity    │
  │                encrypted under key   │
  │<══════════════════════════ Response  │
  │   [x25519_pub_B, kem_ciphertext,     │
  │    nonce, ASCON(session_key, B_keys)]│
  │                                      │
  │  A decapsulates + DHs → same key    │
  │  Decrypts → gets B's public keys    │
  │                                      │
  │══ Both compute fingerprint ══════════│
  │   SHA-256(sorted(A's keys, B's keys))│
  │   User verifies they match out loud  │
  │                                      │
  │  Both save trust record to disk      │
```

### Protocol 2: Proximity Reconnect (every subsequent encounter)

```
Device A (initiator)                  Device B (responder)
  │                                      │
  │  Generate FRESH ephemeral keys       │
  │  Compute MAC = HMAC(long_term_key,   │
  │    device_id ∥ eph_x_pub ∥ eph_pq)  │
  │                                      │
  │══ INITIATE ════════════════════════>│
  │   [device_id, eph_x25519, eph_mlkem, │
  │    MAC]                              │
  │                                      │
  │                    Look up A's record│
  │                    Verify MAC ✓      │
  │                    Derive fresh      │
  │                    session key       │
  │<══════════════════════════ RESPONSE  │
  │   [device_id, eph_x25519, kem_ct,   │
  │    MAC]                              │
  │                                      │
  │  Verify B's MAC ✓                   │
  │  Decapsulate → same session key     │
  │                                      │
  │══ TOKEN (ASCON encrypted) ══════════>│
  │<══════════════════════════ TOKEN     │
```

---

## Trust Lifecycle Framework (`trust/`)

A full device lifecycle manager layered on top of the pairing/proximity protocols.

| State | Meaning | Reversible? |
|---|---|---|
| `TRUSTED` | Active, handshakes allowed | — |
| `REVOKED` | Manually cut off (e.g. lost device) | Yes, via `restore_trust` |
| `EXPIRED` | Time-based lapse | Yes, via `restore_trust` |

Key capabilities:
- **Register** a device after pairing
- **Revoke** with an optional reason (reversible; looks identical to a stranger on the wire)
- **Restore** a revoked or expired device
- **Expire** on a deadline (`valid_for_seconds`, `expires_at`)
- **Key rotation** with full version history
- **Search** by alias, device ID, fingerprint, or trust status
- **Export/import** the trust database for backup (schema-versioned JSON)

---

## Identity Protection at Rest

`identity.json` stores each device's private keys. Default: plaintext. With `--passphrase`:

```
passphrase → Scrypt(N=16384, r=8, p=1) → 16-byte key → ASCON-128a encrypt → private fields
```

The ASCON associated data includes the device ID + public keys, preventing transplanting the ciphertext to a different identity file. Forgetting the passphrase means the identity is unrecoverable — re-pair required.

---

## Known Limitations (By Design)

| Threat | Status |
|---|---|
| Network MITM during pairing | Blocked (QR is out-of-band) |
| Quantum decryption of recorded traffic | Blocked (ML-KEM-768 hybrid) |
| Impersonation at proximity stage | Blocked (HMAC over long-term key) |
| Tampering / message forgery | Blocked (ASCON-128a auth tag) |
| Physical device compromise (key extraction) | Mitigated (passphrase encryption, but not eliminated) |
| Physical QR substitution | Human backstop only (fingerprint comparison) |
| Traffic analysis (who met whom) | Not protected — device_id in cleartext on BLE/mDNS |
| DoS via bogus handshake attempts | Not rate-limited |
| BLE on Windows | Broken (`bless` library bug); WiFi works fine |

---

## Repository Layout

```
core/        Pure crypto: X25519, ML-KEM-768, hybrid HKDF combiner, ASCON-128a
pairing/     QR generation/scanning, pairing protocol, identity serialization
             (passphrase-encrypted identity.json via Scrypt + ASCON)
proximity/   BLE + WiFi transports, proximity handshake protocol
trust/       Trust lifecycle: revocation, expiry, key rotation, search, backup
demo/        device_a.py / device_b.py CLIs + trust_cli.py
             Flags: --message, --verbose, --passphrase, --as-stranger
website/     FastAPI backend (port 8000) + static HTML/CSS/JS crypto visualizer
ui/          React/Vite frontend (port 3000) — richer version of the visualizer
             Proxies /ws/, /qr, /pair, /message, /reconnect, /stranger → port 8000
benchmarks/  WiFi vs BLE latency benchmark (~6 ms/handshake over localhost WiFi)
tests/       131 pytest tests (38 base crypto/protocol + 88 trust framework + 5 others)
docs/        SECURITY_ANALYSIS.md, TRUST_FRAMEWORK.md
```

---

## Running the Project

### Interactive Visualizer (web app)
```bash
# Terminal 1 — Python backend
python website/server.py          # http://localhost:8000 (also serves static frontend)

# Terminal 2 — React frontend (optional, richer UI)
cd ui && pnpm dev                  # http://localhost:3000 (proxies API to port 8000)
```

### CLI Demo
```bash
# 1. Pair
python -m demo.device_a --pair
python -m demo.device_b --pair --qr-image demo/state/device-a/qr.png --peer-port <port>

# 2. Proximity reconnect
python -m demo.device_b --proximity --transport wifi --duration 30
python -m demo.device_a --proximity --transport wifi --verbose --message "hello"

# 3. Trust management
python -m demo.trust_cli device-a --list
python -m demo.trust_cli device-a --revoke device-b --reason "lost device"
python -m demo.trust_cli device-a --restore device-b

# 4. Tests
pytest tests/ -q --ignore=tests/test_transport_ble.py   # Windows: skip BLE
```

---

## Cryptographic Standards Used

| Component | Standard | Reference |
|---|---|---|
| X25519 | Curve25519 DH | Bernstein, PKC 2006 |
| ML-KEM-768 | Post-quantum KEM | NIST FIPS 203, Aug 2024 |
| HKDF | Key derivation | RFC 5869 (SHA-256) |
| ASCON-128a | Lightweight AEAD | NIST SP 800-232, 2023 |
| Hybrid construction | Concatenate-then-HKDF | Signal PQXDH, 2023 |
| Fingerprint comparison | Safety numbers | Signal protocol |
| Scrypt | Passphrase KDF | Colin Percival, 2009 |
