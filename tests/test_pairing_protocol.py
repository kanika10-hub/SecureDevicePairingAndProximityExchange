import json

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from pairing.pairing_protocol import (
    WrongPassphraseError,
    generate_identity, save_identity, load_identity, load_or_create_identity,
    make_qr_payload, respond_to_qr, complete_pairing, compute_fingerprint,
)


def test_full_pairing_handshake_matching_fingerprints(tmp_path):
    alice = generate_identity("device-a")
    bob = generate_identity("device-b")

    qr_payload = make_qr_payload(alice)
    response, bob_fingerprint, alice_seen_by_bob = respond_to_qr(bob, qr_payload)
    alice_fingerprint, bob_seen_by_alice = complete_pairing(alice, response)

    assert alice_fingerprint == bob_fingerprint
    assert alice_seen_by_bob["device_id"] == "device-a"
    assert alice_seen_by_bob["x25519_pub"] == alice.x25519_pub
    assert bob_seen_by_alice["device_id"] == "device-b"
    assert bob_seen_by_alice["x25519_pub"] == bob.x25519_pub


def test_fingerprint_order_independent():
    alice = generate_identity("device-a")
    bob = generate_identity("device-b")
    fp1 = compute_fingerprint("device-a", alice.x25519_pub, alice.mlkem_pub,
                               "device-b", bob.x25519_pub, bob.mlkem_pub)
    fp2 = compute_fingerprint("device-b", bob.x25519_pub, bob.mlkem_pub,
                               "device-a", alice.x25519_pub, alice.mlkem_pub)
    assert fp1 == fp2


def test_wrong_identity_cannot_complete_pairing():
    alice = generate_identity("device-a")
    mallory = generate_identity("mallory")  # attacker, doesn't have alice's private key
    bob = generate_identity("device-b")

    qr_payload = make_qr_payload(alice)
    response, _, _ = respond_to_qr(bob, qr_payload)

    with pytest.raises(ValueError):
        complete_pairing(mallory, response)


def test_identity_persists_across_reload(tmp_path):
    path = tmp_path / "identity.json"
    identity = generate_identity("device-a")
    save_identity(identity, path)

    reloaded = load_identity(path)
    assert reloaded.device_id == "device-a"
    assert reloaded.x25519_pub == identity.x25519_pub
    assert reloaded.mlkem_pub == identity.mlkem_pub

    # reloaded private key must actually work in the protocol, not just match public bytes
    bob = generate_identity("device-b")
    response, _, _ = respond_to_qr(bob, make_qr_payload(identity))
    complete_pairing(reloaded, response)


def test_load_or_create_identity_is_stable(tmp_path):
    path = tmp_path / "identity.json"
    first = load_or_create_identity("device-a", path)
    second = load_or_create_identity("device-a", path)
    assert first.x25519_pub == second.x25519_pub
    assert first.mlkem_pub == second.mlkem_pub


def test_encrypted_identity_round_trips_with_correct_passphrase(tmp_path):
    path = tmp_path / "identity.json"
    identity = generate_identity("device-a")
    save_identity(identity, path, passphrase="correct horse battery staple")

    reloaded = load_identity(path, passphrase="correct horse battery staple")
    assert reloaded.device_id == "device-a"
    assert reloaded.x25519_pub == identity.x25519_pub
    assert reloaded.mlkem_pub == identity.mlkem_pub

    # reloaded private key must actually work in the protocol, not just match public bytes
    bob = generate_identity("device-b")
    response, _, _ = respond_to_qr(bob, make_qr_payload(identity))
    complete_pairing(reloaded, response)


def test_encrypted_identity_file_has_no_plaintext_private_key(tmp_path):
    path = tmp_path / "identity.json"
    identity = generate_identity("device-a")
    save_identity(identity, path, passphrase="hunter2")

    on_disk = json.loads(path.read_text())
    assert on_disk["encrypted"] is True
    assert "x25519_priv" not in on_disk
    assert "mlkem_priv" not in on_disk

    x25519_priv_raw = identity.x25519_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    assert x25519_priv_raw.hex() not in path.read_text()


def test_wrong_passphrase_rejected(tmp_path):
    path = tmp_path / "identity.json"
    identity = generate_identity("device-a")
    save_identity(identity, path, passphrase="right-passphrase")

    with pytest.raises(WrongPassphraseError):
        load_identity(path, passphrase="wrong-passphrase")


def test_encrypted_identity_requires_a_passphrase_to_load(tmp_path):
    path = tmp_path / "identity.json"
    save_identity(generate_identity("device-a"), path, passphrase="secret")

    with pytest.raises(WrongPassphraseError):
        load_identity(path)  # no passphrase given


def test_load_or_create_identity_upgrades_plaintext_to_encrypted_in_place(tmp_path):
    path = tmp_path / "identity.json"
    plaintext_identity = load_or_create_identity("device-a", path)  # no passphrase: plaintext
    assert json.loads(path.read_text())["encrypted"] is False

    upgraded = load_or_create_identity("device-a", path, passphrase="now-encrypt-me")
    assert json.loads(path.read_text())["encrypted"] is True
    # same keypair survives the upgrade, just re-wrapped
    assert upgraded.x25519_pub == plaintext_identity.x25519_pub
    assert upgraded.mlkem_pub == plaintext_identity.mlkem_pub

    reloaded = load_or_create_identity("device-a", path, passphrase="now-encrypt-me")
    assert reloaded.x25519_pub == plaintext_identity.x25519_pub
