"""Full QR-based pairing handshake.

Flow:
  1. Device A generates (or loads) its long-term identity and displays a QR code encoding
     (device_id_A, x25519_pub_A, mlkem_pub_A) -- see qr_generate.py. This QR is the *only*
     channel A's public keys travel over; that's what makes the handshake below resistant to
     a network-only attacker (they never see the QR, so they can't encapsulate against A's
     ML-KEM public key or complete the X25519 DH -- both require A's public key, which they
     don't have).
  2. Device B scans the QR (qr_scan.py) and calls `respond_to_qr()`: it derives a session key
     from a hybrid X25519 DH + ML-KEM encapsulation against A's long-term public keys, then
     sends back an ASCON-encrypted message containing B's own long-term public keys. B's
     x25519 public key and the KEM ciphertext travel in the clear alongside the encrypted
     blob -- that's fine, they're not secret, and an on-path attacker still can't derive the
     session key without breaking DH or ML-KEM.
  3. Device A receives B's response and calls `complete_pairing()`: decapsulates/DHs to
     recover the same session key, decrypts B's public keys.
  4. Both sides independently compute the same fingerprint (a la Signal safety numbers) over
     both devices' public keys and save a trust record.

This module only implements the protocol logic (pure functions over bytes); demo/device_a.py
and demo/device_b.py wire it up over an actual socket.
"""
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path

from core.ascon_aead import KEY_SIZE as ASCON_KEY_SIZE
from core.ascon_aead import decrypt as ascon_decrypt
from core.ascon_aead import encrypt as ascon_encrypt
from core.classical_kex import derive_shared_secret, generate_keypair as generate_x25519_keypair
from core.hybrid import combine_secrets
from core.pq_kex import encapsulate, generate_keypair as generate_pq_keypair, load_keypair as load_pq_keypair
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from pairing.qr_generate import build_payload, parse_payload

PAIRING_INFO = b"pairing-handshake"

# Scrypt cost parameters for identity-file passphrase encryption. N=2**14 costs ~100ms on
# ordinary hardware -- enough to make offline passphrase guessing expensive without making
# every `load_or_create_identity` call noticeably slow.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_SALT_SIZE = 16


class WrongPassphraseError(Exception):
    """Raised when an identity file is passphrase-encrypted and the given passphrase can't
    decrypt it (wrong passphrase, or the file was tampered with/corrupted)."""


def _derive_identity_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=ASCON_KEY_SIZE, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


@dataclass
class Identity:
    device_id: str
    x25519_priv: X25519PrivateKey
    x25519_pub: bytes
    pq_keypair: "object"  # core.pq_kex.PQKeypair

    @property
    def mlkem_pub(self) -> bytes:
        return self.pq_keypair.public_key


def generate_identity(device_id: str) -> Identity:
    x25519_priv, x25519_pub = generate_x25519_keypair()
    pq_keypair = generate_pq_keypair()
    return Identity(device_id, x25519_priv, x25519_pub, pq_keypair)


def save_identity(identity: Identity, path: str | Path, passphrase: str | None = None):
    """Save an identity to disk. If `passphrase` is given, the private key material (only) is
    encrypted at rest with a Scrypt-derived key under ASCON-128a, bound via associated data to
    the device_id and public keys so the ciphertext can't be swapped onto a different identity's
    public half. `device_id` and both public keys stay in cleartext either way -- they aren't
    secret, and the pairing/proximity protocols need to read them without a passphrase.

    Without a passphrase, saves in the original plaintext format (default, for backward
    compatibility with existing identity files and non-interactive use)."""
    x25519_priv_raw = identity.x25519_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    private_fields = {
        "x25519_priv": x25519_priv_raw.hex(),
        "mlkem_priv": identity.pq_keypair.export_secret_key().hex(),
    }
    data = {
        "device_id": identity.device_id,
        "x25519_pub": identity.x25519_pub.hex(),
        "mlkem_pub": identity.pq_keypair.public_key.hex(),
    }

    if passphrase:
        salt = os.urandom(SCRYPT_SALT_SIZE)
        key = _derive_identity_key(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
        associated_data = identity.device_id.encode("utf-8") + identity.x25519_pub + identity.pq_keypair.public_key
        nonce, ciphertext = ascon_encrypt(key, json.dumps(private_fields).encode("utf-8"), associated_data=associated_data)
        data.update({
            "encrypted": True,
            "kdf": "scrypt", "kdf_salt": salt.hex(), "kdf_n": SCRYPT_N, "kdf_r": SCRYPT_R, "kdf_p": SCRYPT_P,
            "nonce": nonce.hex(), "ciphertext": ciphertext.hex(),
        })
    else:
        data["encrypted"] = False
        data.update(private_fields)

    Path(path).write_text(json.dumps(data))


def load_identity(path: str | Path, passphrase: str | None = None) -> Identity | None:
    p = Path(path)
    if not p.exists():
        return None
    data = json.loads(p.read_text())
    x25519_pub = bytes.fromhex(data["x25519_pub"])
    mlkem_pub = bytes.fromhex(data["mlkem_pub"])

    if data.get("encrypted"):
        if not passphrase:
            raise WrongPassphraseError(f"{path} is passphrase-encrypted -- pass a passphrase to load it")
        salt = bytes.fromhex(data["kdf_salt"])
        key = _derive_identity_key(passphrase, salt, data["kdf_n"], data["kdf_r"], data["kdf_p"])
        associated_data = data["device_id"].encode("utf-8") + x25519_pub + mlkem_pub
        try:
            plaintext = ascon_decrypt(key, bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"]),
                                       associated_data=associated_data)
        except ValueError:
            raise WrongPassphraseError("wrong passphrase, or identity file is corrupted/tampered with") from None
        private_fields = json.loads(plaintext)
    else:
        private_fields = data

    x25519_priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_fields["x25519_priv"]))
    pq_keypair = load_pq_keypair(bytes.fromhex(private_fields["mlkem_priv"]), mlkem_pub)
    return Identity(data["device_id"], x25519_priv, x25519_pub, pq_keypair)


def load_or_create_identity(device_id: str, path: str | Path, passphrase: str | None = None) -> Identity:
    """Load the identity at `path`, creating it if absent. If `passphrase` is given and an
    existing identity at `path` is still in the old plaintext format, it's transparently
    upgraded in place to passphrase-encrypted on this call -- mirroring how
    `demo.common.make_trust_manager` migrates the legacy trust store, so turning encryption on
    doesn't require deleting and re-pairing."""
    p = Path(path)
    if not p.exists():
        identity = generate_identity(device_id)
        save_identity(identity, path, passphrase=passphrase)
        return identity

    data = json.loads(p.read_text())
    if passphrase and not data.get("encrypted"):
        identity = load_identity(path)
        save_identity(identity, path, passphrase=passphrase)
        return identity

    return load_identity(path, passphrase=passphrase)


def compute_fingerprint(id_a: str, x25519_pub_a: bytes, mlkem_pub_a: bytes,
                         id_b: str, x25519_pub_b: bytes, mlkem_pub_b: bytes) -> str:
    """Deterministic regardless of which side (A or B) computes it: sort by device_id."""
    devices = sorted(
        [(id_a, x25519_pub_a, mlkem_pub_a), (id_b, x25519_pub_b, mlkem_pub_b)],
        key=lambda d: d[0],
    )
    h = hashlib.sha256()
    for device_id, x25519_pub, mlkem_pub in devices:
        h.update(device_id.encode("utf-8"))
        h.update(x25519_pub)
        h.update(mlkem_pub)
    digest = h.hexdigest().upper()
    groups = [digest[i:i + 4] for i in range(0, 24, 4)]  # first 24 hex chars, 6 groups of 4
    return "-".join(groups)


def _pack_response(x25519_pub_b: bytes, kem_ciphertext: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return (
        x25519_pub_b
        + struct.pack(">H", len(kem_ciphertext)) + kem_ciphertext
        + nonce
        + ciphertext
    )


def _unpack_response(message: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    offset = 0
    x25519_pub_b = message[offset:offset + 32]
    offset += 32
    kem_len = struct.unpack(">H", message[offset:offset + 2])[0]
    offset += 2
    kem_ciphertext = message[offset:offset + kem_len]
    offset += kem_len
    nonce = message[offset:offset + 16]
    offset += 16
    ciphertext = message[offset:]
    return x25519_pub_b, kem_ciphertext, nonce, ciphertext


def make_qr_payload(identity: Identity) -> bytes:
    return build_payload(identity.device_id, identity.x25519_pub, identity.mlkem_pub)


def respond_to_qr(my_identity: Identity, scanned_qr_payload: bytes) -> tuple[bytes, str, dict]:
    """Device B's side. Returns (response_message_to_send_to_A, fingerprint, peer_info)."""
    peer = parse_payload(scanned_qr_payload)

    shared_x = derive_shared_secret(my_identity.x25519_priv, peer["x25519_pub"])
    kem_ciphertext, pq_secret = encapsulate(peer["mlkem_pub"])
    session_key = combine_secrets(shared_x, pq_secret, info=PAIRING_INFO)

    my_payload = build_payload(my_identity.device_id, my_identity.x25519_pub, my_identity.mlkem_pub)
    nonce, ciphertext = ascon_encrypt(session_key, my_payload, associated_data=kem_ciphertext)

    response = _pack_response(my_identity.x25519_pub, kem_ciphertext, nonce, ciphertext)

    fingerprint = compute_fingerprint(
        my_identity.device_id, my_identity.x25519_pub, my_identity.mlkem_pub,
        peer["device_id"], peer["x25519_pub"], peer["mlkem_pub"],
    )
    return response, fingerprint, peer


def complete_pairing(my_identity: Identity, response_message: bytes) -> tuple[str, dict]:
    """Device A's side. Returns (fingerprint, peer_info)."""
    x25519_pub_b, kem_ciphertext, nonce, ciphertext = _unpack_response(response_message)

    pq_secret = my_identity.pq_keypair.decapsulate(kem_ciphertext)
    shared_x = derive_shared_secret(my_identity.x25519_priv, x25519_pub_b)
    session_key = combine_secrets(shared_x, pq_secret, info=PAIRING_INFO)

    plaintext = ascon_decrypt(session_key, nonce, ciphertext, associated_data=kem_ciphertext)
    peer = parse_payload(plaintext)
    if peer["x25519_pub"] != x25519_pub_b:
        raise ValueError("x25519 public key in encrypted payload does not match cleartext header")

    fingerprint = compute_fingerprint(
        my_identity.device_id, my_identity.x25519_pub, my_identity.mlkem_pub,
        peer["device_id"], peer["x25519_pub"], peer["mlkem_pub"],
    )
    return fingerprint, peer


def demo():
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        alice = load_or_create_identity("device-a", Path(tmp) / "a.json")
        bob = load_or_create_identity("device-b", Path(tmp) / "b.json")

        qr_payload = make_qr_payload(alice)
        response, bob_fingerprint, alice_seen_by_bob = respond_to_qr(bob, qr_payload)
        alice_fingerprint, bob_seen_by_alice = complete_pairing(alice, response)

        assert bob_fingerprint == alice_fingerprint
        assert alice_seen_by_bob["device_id"] == "device-a"
        assert bob_seen_by_alice["device_id"] == "device-b"

        from pairing.trust_store import TrustStore

        alice_store = TrustStore(Path(tmp) / "alice_trust.json")
        bob_store = TrustStore(Path(tmp) / "bob_trust.json")
        alice_store.save_peer("device-b", bob_seen_by_alice["x25519_pub"], bob_seen_by_alice["mlkem_pub"], alice_fingerprint)
        bob_store.save_peer("device-a", alice_seen_by_bob["x25519_pub"], alice_seen_by_bob["mlkem_pub"], bob_fingerprint)

        assert alice_store.get_peer("device-b")["fingerprint"] == bob_store.get_peer("device-a")["fingerprint"]
        print(f"pairing_protocol demo OK, fingerprint: {alice_fingerprint}")


if __name__ == "__main__":
    demo()
