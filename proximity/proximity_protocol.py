"""Proximity protocol: previously-paired devices auto-reconnect with fresh ephemeral keys,
authenticated against the long-term trust established during QR pairing (pairing_protocol.py).

Long-term trust anchor: both sides' long-term X25519 keys never change after pairing, so a
classical DH between "my long-term private key" and "the peer's long-term public key stored in
my trust store" reproduces the exact same value every time, forever -- effectively a durable
pre-shared secret. We HKDF that into a MAC key and use it to authenticate each ephemeral
handshake (HMAC-SHA256 over the ephemeral public keys), *without* needing a fresh KEM
encapsulation just to prove identity. An attacker who was never paired (or who is trying to
impersonate a paired peer without that peer's long-term private key) cannot reproduce this DH
result and so cannot forge a valid MAC -- this is the mechanism that makes proximity reject
unpaired/impersonating devices.

Per-encounter secrecy: the actual *session* key used to encrypt the token payload comes from a
completely fresh ephemeral X25519 + ML-KEM handshake (forward secret -- discarded after the
encounter, unlike the long-term MAC key).

Wire messages (all fixed-size fields, no length ambiguity for the crypto material):
  INITIATE (initiator -> responder):
    [1B id_len][id][32B ephemeral_x25519_pub][1184B ephemeral_mlkem_pub][32B mac]
    mac = HMAC-SHA256(long_term_key, id || ephemeral_x25519_pub || ephemeral_mlkem_pub)

  RESPONSE (responder -> initiator):
    [1B id_len][id][32B ephemeral_x25519_pub][1088B kem_ciphertext][32B mac]
    mac = HMAC-SHA256(long_term_key, id || ephemeral_x25519_pub || kem_ciphertext)

  TOKEN (either direction, ASCON-AEAD under the fresh ephemeral session key):
    [16B nonce][ciphertext]
"""
import hashlib
import hmac
import struct

from core.ascon_aead import decrypt as ascon_decrypt
from core.ascon_aead import encrypt as ascon_encrypt
from core.classical_kex import derive_shared_secret, generate_keypair as generate_x25519_keypair
from core.hybrid import combine_secrets
from core.pq_kex import encapsulate, generate_keypair as generate_pq_keypair
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pairing.pairing_protocol import Identity
from pairing.trust_store import TrustStore

MLKEM_PUB_LEN = 1184
KEM_CIPHERTEXT_LEN = 1088
MAC_LEN = 32
PROXIMITY_INFO = b"proximity-ephemeral-session"
LONG_TERM_INFO = b"proximity-long-term-mac-key"


class UnpairedPeerError(Exception):
    """Raised when the peer is not in the local trust store -- pairing must happen first."""


class AuthenticationFailedError(Exception):
    """Raised when a peer's MAC doesn't verify -- they don't hold the paired long-term key."""


def compute_long_term_key(my_identity: Identity, peer_record: dict) -> bytes:
    shared_x = derive_shared_secret(my_identity.x25519_priv, peer_record["x25519_pub"])
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=LONG_TERM_INFO).derive(shared_x)


def _pack_id(device_id: str) -> bytes:
    id_bytes = device_id.encode("utf-8")
    return struct.pack("B", len(id_bytes)) + id_bytes


def _unpack_id(data: bytes, offset: int = 0) -> tuple[str, int]:
    id_len = data[offset]
    offset += 1
    device_id = data[offset:offset + id_len].decode("utf-8")
    return device_id, offset + id_len


def build_initiate_message(my_identity: Identity, ephemeral_x_pub: bytes, ephemeral_pq_pub: bytes,
                            long_term_key: bytes) -> bytes:
    mac = hmac.new(long_term_key, my_identity.device_id.encode("utf-8") + ephemeral_x_pub + ephemeral_pq_pub,
                    hashlib.sha256).digest()
    return _pack_id(my_identity.device_id) + ephemeral_x_pub + ephemeral_pq_pub + mac


def parse_initiate_message(data: bytes) -> dict:
    device_id, offset = _unpack_id(data)
    ephemeral_x_pub = data[offset:offset + 32]
    offset += 32
    ephemeral_pq_pub = data[offset:offset + MLKEM_PUB_LEN]
    offset += MLKEM_PUB_LEN
    mac = data[offset:offset + MAC_LEN]
    return {"device_id": device_id, "ephemeral_x_pub": ephemeral_x_pub, "ephemeral_pq_pub": ephemeral_pq_pub, "mac": mac}


def build_response_message(my_identity: Identity, ephemeral_x_pub: bytes, kem_ciphertext: bytes,
                            long_term_key: bytes) -> bytes:
    mac = hmac.new(long_term_key, my_identity.device_id.encode("utf-8") + ephemeral_x_pub + kem_ciphertext,
                    hashlib.sha256).digest()
    return _pack_id(my_identity.device_id) + ephemeral_x_pub + kem_ciphertext + mac


def parse_response_message(data: bytes) -> dict:
    device_id, offset = _unpack_id(data)
    ephemeral_x_pub = data[offset:offset + 32]
    offset += 32
    kem_ciphertext = data[offset:offset + KEM_CIPHERTEXT_LEN]
    offset += KEM_CIPHERTEXT_LEN
    mac = data[offset:offset + MAC_LEN]
    return {"device_id": device_id, "ephemeral_x_pub": ephemeral_x_pub, "kem_ciphertext": kem_ciphertext, "mac": mac}


def _verify_mac(expected_mac: bytes, long_term_key: bytes, *parts: bytes):
    computed = hmac.new(long_term_key, b"".join(parts), hashlib.sha256).digest()
    if not hmac.compare_digest(computed, expected_mac):
        raise AuthenticationFailedError("MAC verification failed: peer does not hold the paired long-term key")


def pack_token(nonce: bytes, ciphertext: bytes) -> bytes:
    return nonce + ciphertext


def unpack_token(data: bytes) -> tuple[bytes, bytes]:
    return data[:16], data[16:]


def initiate_encounter(transport, my_identity: Identity, trust_store: TrustStore, peer_id: str,
                        token: bytes, timeout: float = 10.0, verbose: bool = False) -> bytes:
    """Initiator side of one proximity encounter. Returns the token received back from the peer."""
    peer_record = trust_store.get_peer(peer_id)
    if peer_record is None:
        raise UnpairedPeerError(f"{peer_id} is not a paired device -- refusing to proceed")

    long_term_key = compute_long_term_key(my_identity, peer_record)

    ephemeral_x_priv, ephemeral_x_pub = generate_x25519_keypair()
    ephemeral_pq = generate_pq_keypair()

    transport.send(peer_id, build_initiate_message(my_identity, ephemeral_x_pub, ephemeral_pq.public_key, long_term_key))

    _sender, raw_response = transport.receive(timeout=timeout)
    response = parse_response_message(raw_response)
    _verify_mac(response["mac"], long_term_key,
                response["device_id"].encode("utf-8"), response["ephemeral_x_pub"], response["kem_ciphertext"])

    pq_secret = ephemeral_pq.decapsulate(response["kem_ciphertext"])
    shared_x = derive_shared_secret(ephemeral_x_priv, response["ephemeral_x_pub"])
    session_key = combine_secrets(shared_x, pq_secret, info=PROXIMITY_INFO)
    if verbose:
        tag = my_identity.device_id
        print(f"[{tag}] X25519 ephemeral shared secret: {shared_x.hex()}")
        print(f"[{tag}] ML-KEM-768 shared secret:        {pq_secret.hex()}")
        print(f"[{tag}] combined session key (HKDF-SHA256, {len(session_key)*8}-bit): {session_key.hex()}")

    nonce, ciphertext = ascon_encrypt(session_key, token)
    if verbose:
        print(f"[{tag}] encrypting message {token!r} with ASCON-128a")
        print(f"[{tag}]   nonce:      {nonce.hex()}")
        print(f"[{tag}]   ciphertext: {ciphertext.hex()}")
    transport.send(peer_id, pack_token(nonce, ciphertext))

    _sender, raw_token = transport.receive(timeout=timeout)
    peer_nonce, peer_ciphertext = unpack_token(raw_token)
    plaintext = ascon_decrypt(session_key, peer_nonce, peer_ciphertext)
    if verbose:
        print(f"[{tag}] received ciphertext from {peer_id}: {peer_ciphertext.hex()} (nonce {peer_nonce.hex()})")
        print(f"[{tag}] decrypted plaintext: {plaintext!r}")
    return plaintext


def respond_to_encounter(transport, my_identity: Identity, trust_store: TrustStore, token: bytes,
                          timeout: float = 10.0, verbose: bool = False) -> tuple[str, bytes]:
    """Responder side: waits for one INITIATE message and completes the handshake + token
    exchange. Returns (peer_id, token_received_from_initiator). Raises UnpairedPeerError or
    AuthenticationFailedError (without ever sending a response) if the peer isn't legitimately
    paired -- this is the actual security enforcement point, since anyone can *claim* a device_id
    on the network."""
    sender, raw_initiate = transport.receive(timeout=timeout)
    initiate = parse_initiate_message(raw_initiate)

    peer_record = trust_store.get_peer(initiate["device_id"])
    if peer_record is None:
        raise UnpairedPeerError(f"{initiate['device_id']} is not a paired device -- refusing to proceed")

    long_term_key = compute_long_term_key(my_identity, peer_record)
    _verify_mac(initiate["mac"], long_term_key,
                initiate["device_id"].encode("utf-8"), initiate["ephemeral_x_pub"], initiate["ephemeral_pq_pub"])

    ephemeral_x_priv, ephemeral_x_pub = generate_x25519_keypair()
    kem_ciphertext, pq_secret = encapsulate(initiate["ephemeral_pq_pub"])
    shared_x = derive_shared_secret(ephemeral_x_priv, initiate["ephemeral_x_pub"])
    session_key = combine_secrets(shared_x, pq_secret, info=PROXIMITY_INFO)
    if verbose:
        tag = my_identity.device_id
        print(f"[{tag}] X25519 ephemeral shared secret: {shared_x.hex()}")
        print(f"[{tag}] ML-KEM-768 shared secret:        {pq_secret.hex()}")
        print(f"[{tag}] combined session key (HKDF-SHA256, {len(session_key)*8}-bit): {session_key.hex()}")

    transport.send(initiate["device_id"], build_response_message(my_identity, ephemeral_x_pub, kem_ciphertext, long_term_key))

    _sender, raw_token = transport.receive(timeout=timeout)
    peer_nonce, peer_ciphertext = unpack_token(raw_token)
    received_token = ascon_decrypt(session_key, peer_nonce, peer_ciphertext)
    if verbose:
        print(f"[{tag}] received ciphertext from {initiate['device_id']}: {peer_ciphertext.hex()} (nonce {peer_nonce.hex()})")
        print(f"[{tag}] decrypted plaintext: {received_token!r}")

    nonce, ciphertext = ascon_encrypt(session_key, token)
    if verbose:
        print(f"[{tag}] encrypting reply {token!r} with ASCON-128a")
        print(f"[{tag}]   nonce:      {nonce.hex()}")
        print(f"[{tag}]   ciphertext: {ciphertext.hex()}")
    transport.send(initiate["device_id"], pack_token(nonce, ciphertext))

    return initiate["device_id"], received_token


def demo():
    import queue
    import threading

    from pairing.pairing_protocol import generate_identity

    class LoopbackTransport:
        """In-process stand-in for a real Transport -- same send/receive shape, two shared
        queues instead of sockets/BLE. Lets this module be demoed/tested with no networking."""

        def __init__(self, my_id, inbox, peer_id, peer_inbox):
            self.my_id = my_id
            self._inbox = inbox
            self.peer_id = peer_id
            self._peer_inbox = peer_inbox

        def send(self, peer_id, data):
            self._peer_inbox.put((self.my_id, data))

        def receive(self, timeout=None):
            return self._inbox.get(timeout=timeout)

    alice_identity = generate_identity("device-a")
    bob_identity = generate_identity("device-b")

    alice_store = TrustStore(__import__("pathlib").Path("/tmp") / "alice_prox_demo.json")
    bob_store = TrustStore(__import__("pathlib").Path("/tmp") / "bob_prox_demo.json")
    alice_store.save_peer("device-b", bob_identity.x25519_pub, bob_identity.mlkem_pub, "demo-fingerprint")
    bob_store.save_peer("device-a", alice_identity.x25519_pub, alice_identity.mlkem_pub, "demo-fingerprint")

    q_alice, q_bob = queue.Queue(), queue.Queue()
    alice_transport = LoopbackTransport("device-a", q_alice, "device-b", q_bob)
    bob_transport = LoopbackTransport("device-b", q_bob, "device-a", q_alice)

    results = {}

    def run_responder():
        results["bob_saw"] = respond_to_encounter(bob_transport, bob_identity, bob_store, b"token-from-bob")

    t = threading.Thread(target=run_responder)
    t.start()
    alice_received = initiate_encounter(alice_transport, alice_identity, alice_store, "device-b", b"token-from-alice")
    t.join(timeout=5)

    assert alice_received == b"token-from-bob"
    assert results["bob_saw"] == ("device-a", b"token-from-alice")
    print("proximity_protocol demo OK: authenticated ephemeral handshake + token exchange succeeded")

    # unpaired peer must be rejected
    mallory_identity = generate_identity("mallory")
    mallory_store = TrustStore(__import__("pathlib").Path("/tmp") / "mallory_prox_demo.json")
    q_mallory = queue.Queue()
    mallory_transport = LoopbackTransport("mallory", q_mallory, "device-b", q_bob)
    try:
        initiate_encounter(mallory_transport, mallory_identity, mallory_store, "device-b", b"token")
        raise AssertionError("expected UnpairedPeerError")
    except UnpairedPeerError as e:
        print(f"unpaired peer correctly rejected: {e}")


if __name__ == "__main__":
    demo()
