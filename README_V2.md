## Secure Device Pairing and Proximity Exchange

Two devices pair once via QR code (out-of-band, MITM-resistant) to establish long-term trust,
then automatically recognize and securely reconnect with each other whenever they're near again
(over BLE or WiFi) using fresh ephemeral keys authenticated against that trust.

Crypto core: hybrid **X25519 + ML-KEM-768** key exchange (NIST FIPS 203) combined via HKDF, and
**ASCON-128a** AEAD (NIST SP 800-232 lightweight crypto) for encryption. See
`docs/SECURITY_ANALYSIS.md` for the full threat model and citations, and `plan.md` for the
phase-by-phase build spec (see git history for how each phase landed).

## What's new here (not in the original README)

Three things were added on top of the original pairing/proximity system:

1. **You can now revoke a device that's already paired.** Before, once two devices paired, that
   trust was permanent -- the only way to "unpair" was to delete a file. Now there's an actual
   on/off switch (`trust/`, wired into the demo) that's checked on every single connection
   attempt, and a `demo/trust_cli.py` command to flip it. See step 4 below.
2. **You can send a real message between the two devices and watch it get encrypted and
   decrypted, live.** The demo used to only exchange a fixed, hardcoded string. Now you can pass
   your own text with `--message`, and `--verbose` prints the actual session key, nonce, and
   ciphertext at each step. See step 5 below.
3. **Private keys can now be encrypted at rest.** `identity.json` used to store each device's
   private keys as plain, readable text. Now you can protect it with a passphrase. See step 6
   below.

Plus **Windows-specific setup notes** (below, under Setup) for three real problems this project
hits on Windows that it doesn't hit on the Linux machine it was originally built on.

## Setup

Requires Python 3.11+ and a C toolchain (cmake, gcc/clang) -- `liboqs-python` builds the
`liboqs` C library from source on first install, which takes several minutes.

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
pytest tests/ -q                # ~35s, 38 tests (see "What's new" -- now 131 with the trust framework)
```

BLE (`bleak` + `bless`) needs a powered Bluetooth adapter and, on Linux, BlueZ over D-Bus
(`bluetoothctl power on` if it shows `PowerState: off-blocked`). WiFi (`zeroconf` + TCP sockets)
needs no special permissions and works out of the box; it's the transport this project verified
live end-to-end (see "What was not live-verified" in `docs/SECURITY_ANALYSIS.md` -- the dev
sandbox this was built in had no powered BLE radio, so BLE is implemented and unit-tested with a
mocked adapter but not live-demoed against two real radios).

> **NEW -- Windows-specific setup notes.** None of this was needed on the original Linux dev
> sandbox; these are three real installation problems hit while setting this project up on
> Windows, with the fix for each:
>
> - `liboqs-python`'s automatic `liboqs` build can fail on Windows (its `cd <tempdir> && git
>   clone` doesn't switch drives if your repo and `%TEMP%` are on different drives, so the clone
>   lands in your repo root instead and collides with a folder that's already there). If
>   `import oqs` fails with a `liboqs` install error, build it manually instead:
>   `cmake --build liboqs/build --parallel 4 && cmake --build liboqs/build --target install`
>   (requires `cmake` + a C compiler on `PATH`; installs to `%USERPROFILE%\_oqs`, which is where
>   `oqs` looks by default).
> - QR scanning (`pyzbar`) needs the **Microsoft Visual C++ 2013 Redistributable (x64)** installed
>   system-wide (`winget install --id Microsoft.VCRedist.2013.x64 -e`), or it fails to load
>   `libzbar-64.dll` even though the DLL file is sitting right there.
> - BLE's `bless` 0.3.0 WinRT backend has an upstream bug on Windows -- it imports a `pysetupdi`
>   package that doesn't exist on PyPI at all, so anything importing
>   `proximity/transport_ble.py` fails. `--transport wifi` is unaffected (that import is now
>   lazy -- only loaded if you actually pass `--transport ble`); BLE itself has no fix short of
>   patching `bless` or running on Linux.

## Running the demo

All commands run from the repo root with `venv` activated. Two terminals, both processes on the
same machine for this demo (loopback WiFi/localhost) -- see `demo/device_a.py` /
`demo/device_b.py` docstrings for why device_a is always the initiator and device_b the
responder here.

**1. Pair the two devices (QR code, one-time):**

```bash
# terminal 1
python -m demo.device_a --pair
# prints a port number and saves demo/state/device-a/qr.png

# terminal 2 (after terminal 1 prints its port)
python -m demo.device_b --pair --qr-image demo/state/device-a/qr.png --peer-port <printed-port>
```

Both terminals print a **safety number** (fingerprint) -- confirm they match, the same way you'd
check Signal safety numbers. If you have a real webcam, drop `--qr-image` from device_b's command
to scan the QR live instead of from the saved PNG.

**2. Proximity reconnect (after pairing, can be run repeatedly / after restarting both processes):**

```bash
# terminal 1
python -m demo.device_b --proximity --transport wifi --duration 30

# terminal 2
python -m demo.device_a --proximity --transport wifi
```

You'll see both sides log `ACCEPTED ...: authenticated handshake complete, received token ...`.
Swap `--transport wifi` for `--transport ble` if you have two real BLE-capable machines nearby.

**3. Demonstrate rejection of an unpaired device:**

```bash
python -m demo.device_a --proximity --transport wifi --as-stranger
```

Uses a fresh, never-paired identity; device_b's terminal will *not* show an ACCEPTED line for it
(the stranger's own trust store is empty, so it skips before even contacting device_b -- see
`tests/test_proximity_protocol.py` for the automated test of the responder-side rejection path,
i.e. an attacker who *does* attempt contact and gets turned away for a bad MAC).

---

**NEW -- steps 4 through 6 below did not exist in the original demo.**

**4. (NEW) Trust management -- revoke a device that's already paired, not just reject a stranger:**

Before this, a paired device was trusted forever -- there was no way to say "stop trusting this
specific device" without manually deleting its record from a file. Now `device_a.py`/
`device_b.py`'s proximity flow checks in with a real trust manager (`trust/`, via
`trust.integration.ProtocolPeerStore`) before every handshake, and `demo/trust_cli.py` lets you
flip that trust off and on:

```bash
python -m demo.trust_cli device-a --list                                     # see paired peers + status
python -m demo.trust_cli device-a --revoke device-b --reason "lost device"   # revoke (reversible)
```

Re-run step 2 and device_a now logs `SKIPPED device-b: ... is not a paired device` -- identical
wording to an unpaired stranger, because a revoked peer is deliberately indistinguishable on the
wire from one that was never paired (telling an attacker "you were revoked" leaks history). Undo
with `python -m demo.trust_cli device-a --restore device-b`.

**5. (NEW) Send a custom message and watch the encryption/decryption happen:**

Before this, the demo only ever exchanged one fixed, hardcoded string, and nothing about the
actual cryptography was visible. Now you can send your own text and see exactly what happens to
it:

```bash
python -m demo.device_a --proximity --transport wifi --verbose --message "hello from device-a"
```

`--message` replaces the default presence token with your own text; `--verbose` (on either or
both sides) prints the X25519 + ML-KEM-768 shared secrets, the combined HKDF session key, and the
ASCON-128a nonce/ciphertext/plaintext for each message sent and received during that encounter.

**6. (NEW) Encrypt a device's private keys at rest:**

Before this, `identity.json` stored each device's private keys as plain, readable text -- anyone
with file access could read them directly. Now you can lock that file behind a passphrase:

```bash
python -m demo.device_a --pair --passphrase "your passphrase here"
```

This upgrades `demo/state/device-a/identity.json` in place from plaintext to
passphrase-encrypted (Scrypt-derived key, ASCON-128a-wrapped) -- see
`pairing/pairing_protocol.py`'s `save_identity`/`load_identity`. Every subsequent command for
that device then needs the same `--passphrase` (or set the `DEVICE_PASSPHRASE` env var once per
shell session instead of retyping it every time). **Important:** if you forget the passphrase,
the identity is genuinely unrecoverable -- that's the point of encryption, but it means you'll
need to reset that device's identity and re-pair. Omitting `--passphrase` entirely leaves
identities in the original plaintext format, so this is opt-in and doesn't change default
behavior.

## Benchmark

```bash
python -m benchmarks.run_benchmark
```

Runs 20 full proximity handshakes over WiFi and (if a BLE adapter is available) BLE, writes raw
latencies to `benchmarks/results/latency_raw.csv` and a comparison chart to
`benchmarks/results/latency_comparison.png`. On the dev machine this was built on: WiFi averaged
~6 ms/handshake over localhost; BLE was skipped (no powered adapter) rather than faked.

## Repository layout

```
core/        X25519, ML-KEM-768, hybrid HKDF combiner, ASCON AEAD
pairing/     QR generation/scanning, trust store, pairing handshake
             (NEW: identity.json can now be passphrase-encrypted -- see pairing_protocol.py)
proximity/   BLE/WiFi transport abstraction, proximity handshake protocol
trust/       (NEW) Trust lifecycle: revocation, expiry, key rotation, search, backup
             -- see docs/TRUST_FRAMEWORK.md
demo/        device_a.py / device_b.py CLIs
             (NEW: demo/trust_cli.py for revoke/restore/list; --message/--verbose/--passphrase flags)
benchmarks/  BLE vs WiFi latency benchmark
docs/        SECURITY_ANALYSIS.md
             (NEW: TRUST_FRAMEWORK.md)
tests/       pytest suite -- 38 tests originally, 131 now (see "What's new")
```

## Tests

```bash
pytest tests/ -q
```

WiFi and proximity-over-loopback tests are live (real sockets/mDNS, no mocking). BLE tests mock
`BleakScanner`/`BlessServer` since no adapter was available in the dev sandbox -- see
`tests/test_transport_ble.py` and `docs/SECURITY_ANALYSIS.md`.

> **NEW.** On Windows, `test_transport_ble.py` also fails to even *collect* (not just skip) due
> to the `bless`/`pysetupdi` problem noted above under Setup --
> `pytest tests/ -q --ignore=tests/test_transport_ble.py` works around it.
>
> Also new: `tests/test_trust_framework.py` -- 88 tests covering everything in `trust/`
> (register/revoke/restore/expire/rotate/search/backup). These need no crypto stack, no network,
> and no BLE, so they run in under half a second even in an environment with nothing else set up
> -- see `docs/TRUST_FRAMEWORK.md` for why that separation was deliberate.
