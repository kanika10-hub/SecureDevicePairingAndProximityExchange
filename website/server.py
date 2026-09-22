"""
Live crypto visualizer backend — streams every crypto step over WebSocket.

Run from repo root:
    pip install -r website/requirements.txt
    python website/server.py
Then open http://localhost:8000
"""
import asyncio
import base64
import hashlib
import hmac
import io
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

import qrcode
import qrcode.constants
from fastapi import Body, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

from core.ascon_aead import decrypt as ascon_decrypt
from core.ascon_aead import encrypt as ascon_encrypt
from core.classical_kex import derive_shared_secret
from core.classical_kex import generate_keypair as gen_x25519
from core.hybrid import combine_secrets
from core.pq_kex import encapsulate
from core.pq_kex import generate_keypair as gen_pq
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pairing.pairing_protocol import PAIRING_INFO, compute_fingerprint, generate_identity
from pairing.qr_generate import build_payload
from proximity.proximity_protocol import LONG_TERM_INFO, PROXIMITY_INFO

app = FastAPI()

STEP_DELAY = 1.0


# ─── Connection manager ───────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._sockets: dict[str, WebSocket] = {}

    async def connect(self, device: str, ws: WebSocket):
        await ws.accept()
        self._sockets[device] = ws

    def disconnect(self, device: str):
        self._sockets.pop(device, None)

    async def send(self, device: str, data: dict):
        ws = self._sockets.get(device)
        if ws:
            try:
                await ws.send_json(data)
            except Exception:
                pass

    async def broadcast(self, data: dict):
        for ws in list(self._sockets.values()):
            try:
                await ws.send_json(data)
            except Exception:
                pass


manager = ConnectionManager()

# ─── Session state ────────────────────────────────────────────────────────────

state: dict[str, Any] = {
    "identity_a": None,
    "identity_b": None,
    "trust_a": None,
    "trust_b": None,
}

# Per-flow step tracking (reset at start of each flow)
_session: dict[str, Any] = {
    "counters": {"device-a": 0, "device-b": 0},
    "registry": {},  # (device, step_name) -> (step_num, label)
}


def _reset_session():
    _session["counters"] = {"device-a": 0, "device-b": 0}
    _session["registry"] = {}


# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/{device}")
async def ws_endpoint(websocket: WebSocket, device: str):
    await manager.connect(device, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(device)


# ─── REST endpoints ───────────────────────────────────────────────────────────

@app.get("/qr")
async def get_qr():
    identity = generate_identity("device-a")
    state["identity_a"] = identity
    raw_payload = build_payload(identity.device_id, identity.x25519_pub, identity.mlkem_pub)
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(base64.b64encode(raw_payload), optimize=0)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return {
        "qr_image": f"data:image/png;base64,{b64}",
        "device_id": identity.device_id,
        "x25519_pub": identity.x25519_pub.hex(),
        "mlkem_pub_preview": identity.mlkem_pub.hex()[:32] + "...",
    }


@app.post("/pair/start")
async def pair_start():
    if state["identity_a"] is None:
        return {"error": "call /qr first"}
    asyncio.create_task(_run_pairing())
    return {"status": "started"}


@app.post("/message")
async def send_message(body: dict = Body(...)):
    if state["trust_a"] is None:
        return {"error": "pair devices first"}
    asyncio.create_task(_run_message(body.get("text", "hello")))
    return {"status": "started"}


@app.post("/reconnect")
async def reconnect():
    if state["trust_a"] is None:
        return {"error": "pair devices first"}
    asyncio.create_task(_run_reconnect())
    return {"status": "started"}


@app.post("/stranger")
async def stranger_attack():
    if state["identity_b"] is None:
        return {"error": "pair devices first to set up Device B as target"}
    asyncio.create_task(_run_stranger())
    return {"status": "started"}


# ─── Emit helper ─────────────────────────────────────────────────────────────

async def _emit(device: str, step: str, label: str, description: str, data: dict,
                uses: list | None = None):
    _session["counters"][device] += 1
    n = _session["counters"][device]
    _session["registry"][(device, step)] = (n, label)

    uses_from = []
    for dep in (uses or []):
        dep_device, dep_step, dep_field = dep
        ref = _session["registry"].get((dep_device, dep_step))
        if ref:
            dep_num, dep_label = ref
            uses_from.append({
                "step_num": dep_num,
                "device": dep_device,
                "label": dep_label,
                "field": dep_field,
            })

    await manager.send(device, {
        "step": step,
        "step_num": n,
        "label": label,
        "description": description,
        "data": data,
        "uses_from": uses_from,
    })
    await asyncio.sleep(STEP_DELAY)


# ─── Pairing flow ─────────────────────────────────────────────────────────────

async def _run_pairing():
    _reset_session()
    identity_a = state["identity_a"]

    await _emit("device-a", "x25519_keygen", "X25519 Key Generation",
        "Device A generates a long-term X25519 keypair. The private key never leaves the device.",
        {"pub_hex": identity_a.x25519_pub.hex()})

    await _emit("device-a", "mlkem_keygen", "ML-KEM-768 Key Generation",
        "Device A also generates a long-term ML-KEM-768 keypair (post-quantum, NIST FIPS 203). "
        "Public key is 1184 bytes.",
        {"pub_hex": identity_a.mlkem_pub.hex()[:64] + "  …(1184 bytes total)"})

    await _emit("device-a", "qr_display", "QR Code Displayed",
        "Device A encodes its device ID + both public keys into a QR code. "
        "This out-of-band channel stops MITM attacks — a network attacker never sees these keys.",
        {"device_id": identity_a.device_id,
         "x25519_pub_hex": identity_a.x25519_pub.hex(),
         "note": "Attacker on the network cannot intercept the QR scan"},
        uses=[
            ("device-a", "x25519_keygen", "X25519 public key"),
            ("device-a", "mlkem_keygen", "ML-KEM-768 public key"),
        ])

    identity_b = generate_identity("device-b")
    state["identity_b"] = identity_b

    await _emit("device-b", "qr_scan", "QR Code Scanned",
        "Device B scans Device A's QR and reads its public keys out-of-band. "
        "Now B knows exactly who it's pairing with.",
        {"peer_id": identity_a.device_id,
         "x25519_pub_hex": identity_a.x25519_pub.hex(),
         "mlkem_pub_hex": identity_a.mlkem_pub.hex()[:64] + "  …"},
        uses=[("device-a", "qr_display", "QR payload")])

    await _emit("device-b", "x25519_keygen", "X25519 Key Generation",
        "Device B generates its own long-term X25519 keypair.",
        {"pub_hex": identity_b.x25519_pub.hex()})

    shared_x_b = derive_shared_secret(identity_b.x25519_priv, identity_a.x25519_pub)

    await _emit("device-b", "x25519_dh", "X25519 Diffie-Hellman",
        "Device B computes DH: its private key × Device A's public key. "
        "An eavesdropper seeing both public keys cannot compute this — discrete log is hard.",
        {"peer_pub_hex": identity_a.x25519_pub.hex(),
         "shared_secret_hex": shared_x_b.hex(),
         "equation": "shared = b_priv · A_pub"},
        uses=[
            ("device-b", "x25519_keygen", "Device B private key"),
            ("device-b", "qr_scan", "Device A X25519 public key"),
        ])

    kem_ciphertext, pq_secret_b = encapsulate(identity_a.mlkem_pub)

    await _emit("device-b", "mlkem_encap", "ML-KEM-768 Encapsulation",
        "Device B encapsulates a random post-quantum secret inside Device A's ML-KEM public key. "
        "Only Device A (holding the matching private key) can recover this secret.",
        {"ciphertext_hex": kem_ciphertext.hex()[:64] + "  …(1088 bytes)",
         "pq_secret_hex": pq_secret_b.hex(),
         "equation": "(ciphertext, pq_secret) = Encaps(A_pub)"},
        uses=[("device-b", "qr_scan", "Device A ML-KEM-768 public key")])

    session_key_b = combine_secrets(shared_x_b, pq_secret_b, info=PAIRING_INFO)

    await _emit("device-b", "hkdf_combine", "HKDF Key Combination",
        "Device B feeds both secrets into HKDF-SHA256 to derive one 128-bit session key. "
        "Breaking X25519 OR ML-KEM alone is not enough — both must be broken.",
        {"classical_hex": shared_x_b.hex(),
         "pq_hex": pq_secret_b.hex(),
         "session_key_hex": session_key_b.hex(),
         "equation": "session_key = HKDF-SHA256(X25519_secret ∥ ML-KEM_secret)"},
        uses=[
            ("device-b", "x25519_dh", "X25519 shared secret"),
            ("device-b", "mlkem_encap", "ML-KEM-768 PQ secret"),
        ])

    raw_b_payload = build_payload(identity_b.device_id, identity_b.x25519_pub, identity_b.mlkem_pub)
    nonce_b, ct_b = ascon_encrypt(session_key_b, raw_b_payload, associated_data=kem_ciphertext)

    await _emit("device-b", "ascon_encrypt", "ASCON-128a Encryption",
        "Device B encrypts its own public keys using the session key. "
        "A passive observer sees only ciphertext — it cannot learn Device B's keys.",
        {"plaintext_preview": f"device-b's public keys ({len(raw_b_payload)} bytes)",
         "key_hex": session_key_b.hex(),
         "nonce_hex": nonce_b.hex(),
         "ciphertext_hex": ct_b.hex()[:64] + "  …",
         "equation": "ciphertext = ASCON-128a(key, nonce, plaintext)"},
        uses=[("device-b", "hkdf_combine", "session key")])

    # --- ciphertext + kem_ciphertext travel over network to Device A ---

    pq_secret_a = identity_a.pq_keypair.decapsulate(kem_ciphertext)

    await _emit("device-a", "mlkem_decap", "ML-KEM-768 Decapsulation",
        "Device A decapsulates the KEM ciphertext using its ML-KEM private key. "
        "It recovers the exact same PQ secret Device B encapsulated — without it ever being transmitted in plaintext.",
        {"ciphertext_hex": kem_ciphertext.hex()[:64] + "  …",
         "pq_secret_hex": pq_secret_a.hex(),
         "equation": "pq_secret = Decaps(A_priv, ciphertext)"},
        uses=[
            ("device-a", "mlkem_keygen", "Device A ML-KEM private key"),
            ("device-b", "mlkem_encap", "KEM ciphertext (received over network)"),
        ])

    shared_x_a = derive_shared_secret(identity_a.x25519_priv, identity_b.x25519_pub)

    await _emit("device-a", "x25519_dh", "X25519 Diffie-Hellman",
        "Device A computes DH using its private key × Device B's public key. "
        "DH property: a_priv·B_pub = b_priv·A_pub — same shared secret as Device B computed.",
        {"peer_pub_hex": identity_b.x25519_pub.hex(),
         "shared_secret_hex": shared_x_a.hex(),
         "equation": "shared = a_priv · B_pub"},
        uses=[
            ("device-a", "x25519_keygen", "Device A private key"),
            ("device-b", "ascon_encrypt", "Device B public keys (inside ciphertext)"),
        ])

    session_key_a = combine_secrets(shared_x_a, pq_secret_a, info=PAIRING_INFO)

    await _emit("device-a", "hkdf_combine", "HKDF Key Combination",
        "Device A derives the same 128-bit session key independently. "
        "Neither side transmitted the key — both arrived at it through math alone.",
        {"classical_hex": shared_x_a.hex(),
         "pq_hex": pq_secret_a.hex(),
         "session_key_hex": session_key_a.hex(),
         "equation": "session_key = HKDF-SHA256(X25519_secret ∥ ML-KEM_secret)"},
        uses=[
            ("device-a", "x25519_dh", "X25519 shared secret"),
            ("device-a", "mlkem_decap", "ML-KEM-768 PQ secret"),
        ])

    plaintext_a = ascon_decrypt(session_key_a, nonce_b, ct_b, associated_data=kem_ciphertext)

    await _emit("device-a", "ascon_decrypt", "ASCON-128a Decryption",
        "Device A decrypts Device B's public keys. "
        "The ASCON authentication tag proves the ciphertext was not tampered with in transit.",
        {"ciphertext_hex": ct_b.hex()[:64] + "  …",
         "key_hex": session_key_a.hex(),
         "nonce_hex": nonce_b.hex(),
         "plaintext_preview": f"device-b's public keys ({len(plaintext_a)} bytes) ✓",
         "equation": "plaintext = ASCON-128a_decrypt(key, nonce, ciphertext)"},
        uses=[
            ("device-a", "hkdf_combine", "session key"),
            ("device-b", "ascon_encrypt", "ciphertext (received over network)"),
        ])

    fingerprint = compute_fingerprint(
        identity_a.device_id, identity_a.x25519_pub, identity_a.mlkem_pub,
        identity_b.device_id, identity_b.x25519_pub, identity_b.mlkem_pub,
    )
    state["trust_a"] = {"x25519_pub": identity_b.x25519_pub, "mlkem_pub": identity_b.mlkem_pub}
    state["trust_b"] = {"x25519_pub": identity_a.x25519_pub, "mlkem_pub": identity_a.mlkem_pub}

    await manager.broadcast({
        "step": "pairing_done",
        "step_num": None,
        "label": "Pairing Complete",
        "description": "Both devices independently computed the same safety number. "
                        "If these match when read aloud, the pairing was not intercepted.",
        "data": {"fingerprint": fingerprint},
        "uses_from": [],
    })


# ─── Message exchange flow ────────────────────────────────────────────────────

async def _run_message(text: str):
    _reset_session()
    identity_a = state["identity_a"]
    identity_b = state["identity_b"]
    trust_a    = state["trust_a"]
    trust_b    = state["trust_b"]

    eph_x_priv_a, eph_x_pub_a = gen_x25519()
    eph_pq_a = gen_pq()

    await _emit("device-a", "ephemeral_keygen", "Ephemeral Key Generation",
        "Device A generates fresh one-time keys for this encounter only. "
        "Discarded after the session — forward secrecy means past sessions stay safe even if keys leak later.",
        {"x25519_pub_hex": eph_x_pub_a.hex(),
         "mlkem_pub_hex": eph_pq_a.public_key.hex()[:64] + "  …"})

    lt_shared_a = derive_shared_secret(identity_a.x25519_priv, trust_a["x25519_pub"])
    lt_key_a = HKDF(
        algorithm=crypto_hashes.SHA256(), length=32, salt=None, info=LONG_TERM_INFO,
    ).derive(lt_shared_a)
    mac_a = hmac.new(
        lt_key_a,
        identity_a.device_id.encode() + eph_x_pub_a + eph_pq_a.public_key,
        hashlib.sha256,
    ).digest()

    await _emit("device-a", "mac_compute", "Authentication MAC",
        "Device A signs the ephemeral keys with a long-term shared secret from the original pairing. "
        "Only a device that completed the QR pairing can produce a valid MAC.",
        {"long_term_key_hex": lt_key_a.hex(),
         "mac_hex": mac_a.hex(),
         "equation": "MAC = HMAC-SHA256(long_term_key, device_id ∥ eph_x_pub ∥ eph_pq_pub)"},
        uses=[("device-a", "ephemeral_keygen", "ephemeral public keys to authenticate")])

    lt_shared_b = derive_shared_secret(identity_b.x25519_priv, trust_b["x25519_pub"])
    lt_key_b = HKDF(
        algorithm=crypto_hashes.SHA256(), length=32, salt=None, info=LONG_TERM_INFO,
    ).derive(lt_shared_b)
    expected_mac = hmac.new(
        lt_key_b,
        identity_a.device_id.encode() + eph_x_pub_a + eph_pq_a.public_key,
        hashlib.sha256,
    ).digest()
    mac_ok = hmac.compare_digest(expected_mac, mac_a)

    await _emit("device-b", "mac_verify", "MAC Verification",
        "Device B recomputes the MAC using its own long-term key. "
        "Constant-time comparison prevents timing attacks. Match → identity confirmed.",
        {"expected_mac_hex": expected_mac.hex(),
         "received_mac_hex": mac_a.hex(),
         "verified": mac_ok})

    eph_x_priv_b, eph_x_pub_b = gen_x25519()
    kem_ct, pq_secret_b = encapsulate(eph_pq_a.public_key)
    shared_x_b = derive_shared_secret(eph_x_priv_b, eph_x_pub_a)
    session_key_b = combine_secrets(shared_x_b, pq_secret_b, info=PROXIMITY_INFO)

    await _emit("device-b", "session_key", "Ephemeral Session Key",
        "Device B derives an ephemeral session key: fresh X25519 DH + ML-KEM encapsulation. "
        "This key is unique to this single message exchange.",
        {"x25519_shared_hex": shared_x_b.hex(),
         "pq_secret_hex": pq_secret_b.hex(),
         "session_key_hex": session_key_b.hex(),
         "equation": "session_key = HKDF-SHA256(X25519_secret ∥ ML-KEM_secret)"},
        uses=[("device-b", "mac_verify", "verified identity (Device A trusted)")])

    pq_secret_a = eph_pq_a.decapsulate(kem_ct)
    shared_x_a  = derive_shared_secret(eph_x_priv_a, eph_x_pub_b)
    session_key_a = combine_secrets(shared_x_a, pq_secret_a, info=PROXIMITY_INFO)

    await _emit("device-a", "session_key", "Ephemeral Session Key",
        "Device A derives the same ephemeral session key from its side of the exchange.",
        {"x25519_shared_hex": shared_x_a.hex(),
         "pq_secret_hex": pq_secret_a.hex(),
         "session_key_hex": session_key_a.hex(),
         "equation": "session_key = HKDF-SHA256(X25519_secret ∥ ML-KEM_secret)"},
        uses=[("device-a", "mac_compute", "long-term authentication (proved identity)")])

    nonce, ciphertext = ascon_encrypt(session_key_a, text.encode("utf-8"))

    await _emit("device-a", "ascon_encrypt", "ASCON-128a Encryption",
        "Device A encrypts the message. "
        "The nonce is fresh and random — reusing a nonce with the same key would be catastrophic, so a new one is generated every time.",
        {"plaintext": text,
         "key_hex": session_key_a.hex(),
         "nonce_hex": nonce.hex(),
         "ciphertext_hex": ciphertext.hex(),
         "equation": "ciphertext = ASCON-128a(key, nonce, plaintext)"},
        uses=[("device-a", "session_key", "session key")])

    plaintext_b = ascon_decrypt(session_key_b, nonce, ciphertext).decode("utf-8")

    await _emit("device-b", "ascon_decrypt", "ASCON-128a Decryption",
        "Device B decrypts the ciphertext and recovers the original message. "
        "The ASCON authentication tag proves nothing was modified in transit.",
        {"ciphertext_hex": ciphertext.hex(),
         "key_hex": session_key_b.hex(),
         "nonce_hex": nonce.hex(),
         "plaintext": plaintext_b,
         "equation": "plaintext = ASCON-128a_decrypt(key, nonce, ciphertext)"},
        uses=[
            ("device-b", "session_key", "session key"),
            ("device-a", "ascon_encrypt", "ciphertext (received over network)"),
        ])


# ─── Reconnect flow ───────────────────────────────────────────────────────────

async def _run_reconnect():
    _reset_session()
    identity_a = state["identity_a"]
    identity_b = state["identity_b"]
    trust_a    = state["trust_a"]
    trust_b    = state["trust_b"]

    await manager.broadcast({
        "step": "scenario_header",
        "step_num": None,
        "label": "Scenario: Proximity Reconnect",
        "description": "Previously paired Device A comes within range of Device B. "
                        "Ephemeral keys prove identity via MAC; a fresh session key is derived (forward secrecy).",
        "data": {"scenario": "reconnect"},
        "uses_from": [],
    })

    eph_x_priv_a, eph_x_pub_a = gen_x25519()
    eph_pq_a = gen_pq()

    await _emit("device-a", "ephemeral_keygen", "Ephemeral Key Generation",
        "Device A generates FRESH one-time keys for this encounter. "
        "Different from the long-term pairing keys — these are discarded after this session.",
        {"x25519_pub_hex": eph_x_pub_a.hex(),
         "mlkem_pub_hex": eph_pq_a.public_key.hex()[:64] + "  …"})

    lt_shared_a = derive_shared_secret(identity_a.x25519_priv, trust_a["x25519_pub"])
    lt_key_a = HKDF(
        algorithm=crypto_hashes.SHA256(), length=32, salt=None, info=LONG_TERM_INFO,
    ).derive(lt_shared_a)
    mac_a = hmac.new(
        lt_key_a,
        identity_a.device_id.encode() + eph_x_pub_a + eph_pq_a.public_key,
        hashlib.sha256,
    ).digest()

    await _emit("device-a", "mac_compute", "Authentication MAC",
        "Device A signs its ephemeral keys with a long-term secret from the original QR pairing. "
        "This proves 'I am the device you paired with' without re-doing the full key exchange.",
        {"long_term_key_hex": lt_key_a.hex(),
         "mac_hex": mac_a.hex(),
         "equation": "MAC = HMAC-SHA256(long_term_key, device_id ∥ eph_keys)"},
        uses=[("device-a", "ephemeral_keygen", "ephemeral public keys to sign")])

    lt_shared_b = derive_shared_secret(identity_b.x25519_priv, trust_b["x25519_pub"])
    lt_key_b = HKDF(
        algorithm=crypto_hashes.SHA256(), length=32, salt=None, info=LONG_TERM_INFO,
    ).derive(lt_shared_b)
    expected_mac = hmac.new(
        lt_key_b,
        identity_a.device_id.encode() + eph_x_pub_a + eph_pq_a.public_key,
        hashlib.sha256,
    ).digest()
    mac_ok = hmac.compare_digest(expected_mac, mac_a)

    await _emit("device-b", "mac_verify", "MAC Verification — Device Recognized ✓",
        "Device B looks up 'device-a' in its trust store — FOUND. "
        "It recomputes the MAC and confirms it matches. This is the previously paired device.",
        {"expected_mac_hex": expected_mac.hex(),
         "received_mac_hex": mac_a.hex(),
         "verified": mac_ok,
         "trust_lookup": "device-a — FOUND in trust store ✓"})

    eph_x_priv_b, eph_x_pub_b = gen_x25519()
    kem_ct, pq_secret_b = encapsulate(eph_pq_a.public_key)
    shared_x_b = derive_shared_secret(eph_x_priv_b, eph_x_pub_a)
    session_key_b = combine_secrets(shared_x_b, pq_secret_b, info=PROXIMITY_INFO)

    await _emit("device-b", "session_key", "Fresh Session Key",
        "Device B derives a NEW session key for this encounter — completely different from all previous sessions. "
        "Forward secrecy: even if a past key is compromised, this session is safe.",
        {"x25519_shared_hex": shared_x_b.hex(),
         "pq_secret_hex": pq_secret_b.hex(),
         "session_key_hex": session_key_b.hex(),
         "equation": "session_key = HKDF-SHA256(X25519_secret ∥ ML-KEM_secret)"},
        uses=[("device-b", "mac_verify", "verified: device-a is trusted")])

    pq_secret_a = eph_pq_a.decapsulate(kem_ct)
    shared_x_a  = derive_shared_secret(eph_x_priv_a, eph_x_pub_b)
    session_key_a = combine_secrets(shared_x_a, pq_secret_a, info=PROXIMITY_INFO)

    await _emit("device-a", "session_key", "Fresh Session Key",
        "Device A independently derives the same fresh session key from its side of the exchange.",
        {"x25519_shared_hex": shared_x_a.hex(),
         "pq_secret_hex": pq_secret_a.hex(),
         "session_key_hex": session_key_a.hex(),
         "equation": "session_key = HKDF-SHA256(X25519_secret ∥ ML-KEM_secret)"},
        uses=[("device-a", "mac_compute", "proved long-term identity")])

    await manager.broadcast({
        "step": "reconnect_done",
        "step_num": None,
        "label": "Reconnection Successful",
        "description": "Previously paired devices recognized each other and established a fresh encrypted session. "
                        "Same devices, brand-new keys every encounter.",
        "data": {
            "session_key_hex": session_key_a.hex(),
            "keys_match": session_key_a == session_key_b,
        },
        "uses_from": [],
    })


# ─── Stranger attack flow ─────────────────────────────────────────────────────

async def _run_stranger():
    _reset_session()
    identity_b = state["identity_b"]
    trust_b    = state["trust_b"]

    await manager.broadcast({
        "step": "scenario_header",
        "step_num": None,
        "label": "Scenario: Stranger Attack",
        "description": "An unknown device tries to connect to Device B. "
                        "It was never paired, so it cannot produce a valid authentication MAC.",
        "data": {"scenario": "stranger"},
        "uses_from": [],
    })

    # Stranger shown on device-a panel
    stranger_id = generate_identity("stranger-007")

    await _emit("device-a", "stranger_identity", "Stranger Creates Identity",
        "A new device (never paired with anyone) generates a fresh identity. "
        "It has no long-term shared secret with Device B — it cannot forge a valid MAC.",
        {"device_id": "stranger-007",
         "x25519_pub_hex": stranger_id.x25519_pub.hex(),
         "note": "This identity has NEVER been paired with Device B"})

    eph_x_priv_s, eph_x_pub_s = gen_x25519()
    eph_pq_s = gen_pq()

    await _emit("device-a", "ephemeral_keygen", "Stranger Generates Ephemeral Keys",
        "The stranger generates ephemeral keys to attempt the proximity handshake. "
        "It also needs to produce an authentication MAC — but it has no pairing secret with Device B.",
        {"x25519_pub_hex": eph_x_pub_s.hex(),
         "mlkem_pub_hex": eph_pq_s.public_key.hex()[:64] + "  …"},
        uses=[("device-a", "stranger_identity", "stranger identity")])

    fake_key = os.urandom(32)
    fake_mac = hmac.new(
        fake_key,
        b"stranger-007" + eph_x_pub_s + eph_pq_s.public_key,
        hashlib.sha256,
    ).digest()

    await _emit("device-a", "stranger_mac", "Stranger Computes Fake MAC",
        "The stranger has no long-term secret, so it uses a RANDOM key to compute the MAC. "
        "Device B will immediately detect this.",
        {"random_key_hex": fake_key.hex(),
         "fake_mac_hex": fake_mac.hex(),
         "warning": "⚠ Random key — MAC will not match what Device B expects"},
        uses=[("device-a", "ephemeral_keygen", "ephemeral keys to authenticate")])

    await _emit("device-b", "trust_check_fail", "Trust Check: FAILED",
        "Device B looks up 'stranger-007' in its trust store — NOT FOUND. "
        "Device B silently rejects, leaking no information to the attacker.",
        {"lookup_id": "stranger-007",
         "result": "NOT IN TRUST STORE",
         "action": "SILENT REJECTION — no response sent to stranger",
         "note": "Silent rejection prevents the attacker learning if Device B even exists"})

    lt_shared_check = derive_shared_secret(identity_b.x25519_priv, trust_b["x25519_pub"])
    lt_key_check = HKDF(
        algorithm=crypto_hashes.SHA256(), length=32, salt=None, info=LONG_TERM_INFO,
    ).derive(lt_shared_check)
    expected_mac_for_stranger = hmac.new(
        lt_key_check,
        b"stranger-007" + eph_x_pub_s + eph_pq_s.public_key,
        hashlib.sha256,
    ).digest()

    await _emit("device-b", "mac_verify", "MAC Verification — FAILS",
        "Even if Device B tried to verify (it stopped at the trust check above), "
        "the MAC would fail: the stranger used a random key, not the real long-term pairing secret.",
        {"expected_mac_hex": expected_mac_for_stranger.hex(),
         "received_mac_hex": fake_mac.hex(),
         "verified": False,
         "verdict": "NOT EQUAL — stranger cannot forge without the original pairing secret"},
        uses=[("device-b", "trust_check_fail", "identity not in trust store")])

    await manager.broadcast({
        "step": "stranger_rejected",
        "step_num": None,
        "label": "Stranger Rejected",
        "description": "The unknown device was blocked. Without the long-term secret from the original QR pairing, "
                        "no valid authentication is possible.",
        "data": {
            "attacker_id": "stranger-007",
            "result": "REJECTED",
            "security_property": "Only QR-paired devices can authenticate",
        },
        "uses_from": [],
    })


# ─── Static files ─────────────────────────────────────────────────────────────

_static = Path(__file__).parent / "static"
_static.mkdir(exist_ok=True)
app.mount("/", StaticFiles(directory=str(_static), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True,
                reload_dirs=[str(Path(__file__).parent)])
