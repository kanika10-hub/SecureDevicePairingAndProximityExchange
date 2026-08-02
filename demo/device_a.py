#!/usr/bin/env python3
"""Device A demo CLI.

  python -m demo.device_a --pair
      Generates (or loads) device-a's long-term identity, saves a QR code, and waits for
      device-b to scan it and pair back over the network.

  python -m demo.device_a --proximity --transport wifi
      Loads device-a's identity + trust store, discovers nearby devices, and initiates an
      authenticated ephemeral handshake + token exchange with each one that's already paired.

  python -m demo.device_a --proximity --transport wifi --as-stranger
      Same as above but using a fresh, never-paired throwaway identity -- demonstrates that
      the proximity protocol correctly rejects a device it has no trust record for.

In this demo, device_a always plays the pairing/proximity *initiator* role and device_b always
plays the *responder* -- a fixed choice made only to keep the two CLI scripts simple and avoid
both sides trying to initiate at once; the underlying protocol (pairing_protocol.py,
proximity_protocol.py) is symmetric and doesn't care which side calls which function.
"""
import argparse
import socket
import uuid

from demo.common import device_state_dir, log, make_transport, make_trust_manager, recv_framed, resolve_passphrase
from pairing.pairing_protocol import WrongPassphraseError, complete_pairing, load_or_create_identity, make_qr_payload
from pairing.qr_generate import save_qr
from proximity.proximity_protocol import AuthenticationFailedError, UnpairedPeerError, initiate_encounter
from trust.exceptions import DuplicateDeviceError
from trust.integration import ProtocolPeerStore, register_paired_peer

DEVICE_ID = "device-a"


def cmd_pair(port: int, passphrase: str | None):
    state = device_state_dir(DEVICE_ID)
    identity = load_or_create_identity(DEVICE_ID, state / "identity.json", passphrase=passphrase)
    qr_path = state / "qr.png"
    save_qr(make_qr_payload(identity), str(qr_path))
    log(DEVICE_ID, f"identity ready, QR code saved to {qr_path}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    bound_port = server.getsockname()[1]
    log(DEVICE_ID, f"listening on port {bound_port} for device-b's pairing response")
    log(DEVICE_ID, f"run: python -m demo.device_b --pair --qr-image {qr_path} --peer-port {bound_port}")

    conn, addr = server.accept()
    log(DEVICE_ID, f"connection from {addr}, completing handshake")
    with conn:
        response = recv_framed(conn)
    server.close()

    fingerprint, peer = complete_pairing(identity, response)
    manager = make_trust_manager(state)
    try:
        register_paired_peer(manager, peer, fingerprint)
        log(DEVICE_ID, f"paired with {peer['device_id']}")
    except DuplicateDeviceError:
        log(DEVICE_ID, f"{peer['device_id']} is already a trusted peer -- re-pairing does not "
                        "overwrite existing trust (revoke/remove it first via demo.trust_cli to re-register)")

    log(DEVICE_ID, f"SAFETY NUMBER (compare with device-b): {fingerprint}")


def cmd_proximity(transport_name: str, as_stranger: bool, discover_timeout: float, message: str | None,
                   verbose: bool, passphrase: str | None):
    if as_stranger:
        stranger_id = f"stranger-{uuid.uuid4().hex[:8]}"
        state = device_state_dir(stranger_id)
        identity = load_or_create_identity(stranger_id, state / "identity.json", passphrase=passphrase)
        manager = make_trust_manager(state)  # deliberately empty: never paired
        my_id = stranger_id
    else:
        state = device_state_dir(DEVICE_ID)
        identity = load_or_create_identity(DEVICE_ID, state / "identity.json", passphrase=passphrase)
        manager = make_trust_manager(state)
        my_id = DEVICE_ID

    peer_store = ProtocolPeerStore(manager)
    transport = make_transport(transport_name)
    transport.start(my_id)
    log(my_id, f"advertising over {transport_name}, discovering nearby devices...")
    try:
        peers = transport.discover(timeout=discover_timeout)
        log(my_id, f"discovered: {peers}")
        if not peers:
            log(my_id, "no peers found -- is device-b running --proximity too?")

        for peer_id in peers:
            token = message.encode() if message else f"presence-token-from-{my_id}".encode()
            try:
                received = initiate_encounter(transport, identity, peer_store, peer_id, token, verbose=verbose)
                peer_store.note_session_complete(peer_id)
                log(my_id, f"ACCEPTED by {peer_id}: authenticated handshake complete, received token {received!r}")
            except UnpairedPeerError as e:
                log(my_id, f"SKIPPED {peer_id}: {e}")
            except AuthenticationFailedError as e:
                log(my_id, f"REJECTED by {peer_id}: {e}")
            except TimeoutError as e:
                log(my_id, f"TIMEOUT talking to {peer_id}: {e}")
    finally:
        transport.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pair", action="store_true", help="run the QR pairing flow")
    parser.add_argument("--port", type=int, default=0, help="port to listen on during --pair (0 = pick automatically)")
    parser.add_argument("--proximity", action="store_true", help="run the proximity discovery + handshake flow")
    parser.add_argument("--transport", choices=["wifi", "ble"], default="wifi")
    parser.add_argument("--as-stranger", action="store_true", help="use a fresh unpaired identity (demonstrates rejection)")
    parser.add_argument("--discover-timeout", type=float, default=5.0)
    parser.add_argument("--message", default=None, help="custom message to send as the proximity token (default: presence-token-from-device-a)")
    parser.add_argument("--verbose", "-v", action="store_true", help="print session key / nonce / ciphertext / plaintext for the encryption and decryption steps")
    parser.add_argument("--passphrase", default=None,
                         help="encrypt identity.json's private keys at rest with this passphrase "
                              "(or set DEVICE_PASSPHRASE env var); omitted = plaintext, unchanged default behavior")
    args = parser.parse_args()
    passphrase = resolve_passphrase(args.passphrase)

    try:
        if args.pair:
            cmd_pair(args.port, passphrase)
        elif args.proximity:
            cmd_proximity(args.transport, args.as_stranger, args.discover_timeout, args.message, args.verbose, passphrase)
        else:
            parser.print_help()
    except WrongPassphraseError as e:
        log(DEVICE_ID, f"error: {e}")


if __name__ == "__main__":
    main()
