#!/usr/bin/env python3
"""Device B demo CLI.

  python -m demo.device_b --pair --qr-image demo/state/device-a/qr.png --peer-port <printed by device_a>
      Scans the QR code device-a displayed (from a saved image -- see qr_scan.py for the
      webcam-based path if you have one) and completes pairing back over the network.

  python -m demo.device_b --proximity --transport wifi
      Loads device-b's identity + trust store and waits, responding to any authenticated
      proximity encounter from a paired peer (and rejecting anyone else) until --duration
      seconds pass.

See demo/device_a.py for why device_a is always the initiator and device_b the responder here.
"""
import argparse
import socket
import time

from demo.common import device_state_dir, log, make_transport, make_trust_manager, resolve_passphrase, send_framed
from pairing.pairing_protocol import WrongPassphraseError, load_or_create_identity, respond_to_qr
from pairing.qr_scan import scan_image_file, scan_webcam
from proximity.proximity_protocol import AuthenticationFailedError, UnpairedPeerError, respond_to_encounter
from trust.exceptions import DuplicateDeviceError
from trust.integration import ProtocolPeerStore, register_paired_peer

DEVICE_ID = "device-b"


def cmd_pair(qr_image: str | None, peer_host: str, peer_port: int, passphrase: str | None):
    state = device_state_dir(DEVICE_ID)
    identity = load_or_create_identity(DEVICE_ID, state / "identity.json", passphrase=passphrase)

    if qr_image:
        log(DEVICE_ID, f"scanning QR from {qr_image}")
        payload = scan_image_file(qr_image)
    else:
        log(DEVICE_ID, "scanning QR from webcam...")
        payload = scan_webcam()

    response, fingerprint, peer = respond_to_qr(identity, payload)
    log(DEVICE_ID, f"scanned {peer['device_id']}'s public keys, connecting to {peer_host}:{peer_port}")

    with socket.create_connection((peer_host, peer_port), timeout=10) as conn:
        send_framed(conn, response)

    manager = make_trust_manager(state)
    try:
        register_paired_peer(manager, peer, fingerprint)
        log(DEVICE_ID, f"paired with {peer['device_id']}")
    except DuplicateDeviceError:
        log(DEVICE_ID, f"{peer['device_id']} is already a trusted peer -- re-pairing does not "
                        "overwrite existing trust (revoke/remove it first via demo.trust_cli to re-register)")

    log(DEVICE_ID, f"SAFETY NUMBER (compare with device-a): {fingerprint}")


def cmd_proximity(transport_name: str, duration: float, message: str | None, verbose: bool, passphrase: str | None):
    state = device_state_dir(DEVICE_ID)
    identity = load_or_create_identity(DEVICE_ID, state / "identity.json", passphrase=passphrase)
    manager = make_trust_manager(state)
    peer_store = ProtocolPeerStore(manager)

    transport = make_transport(transport_name)
    transport.start(DEVICE_ID)
    log(DEVICE_ID, f"advertising over {transport_name}, waiting up to {duration}s for encounters...")
    try:
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                token = message.encode() if message else f"presence-token-from-{DEVICE_ID}".encode()
                peer_id, received = respond_to_encounter(transport, identity, peer_store, token, timeout=remaining, verbose=verbose)
                peer_store.note_session_complete(peer_id)
                log(DEVICE_ID, f"ACCEPTED {peer_id}: authenticated handshake complete, received token {received!r}")
            except UnpairedPeerError as e:
                log(DEVICE_ID, f"REJECTED an unpaired peer: {e}")
            except AuthenticationFailedError as e:
                log(DEVICE_ID, f"REJECTED an impersonation attempt: {e}")
            except TimeoutError:
                break
    finally:
        transport.stop()
    log(DEVICE_ID, "done")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pair", action="store_true")
    parser.add_argument("--qr-image", default=None, help="path to a saved QR image (omit to use the webcam)")
    parser.add_argument("--peer-host", default="127.0.0.1")
    parser.add_argument("--peer-port", type=int, default=None)
    parser.add_argument("--proximity", action="store_true")
    parser.add_argument("--transport", choices=["wifi", "ble"], default="wifi")
    parser.add_argument("--duration", type=float, default=30.0, help="seconds to wait for proximity encounters")
    parser.add_argument("--message", default=None, help="custom message to send back as the proximity token (default: presence-token-from-device-b)")
    parser.add_argument("--verbose", "-v", action="store_true", help="print session key / nonce / ciphertext / plaintext for the encryption and decryption steps")
    parser.add_argument("--passphrase", default=None,
                         help="encrypt identity.json's private keys at rest with this passphrase "
                              "(or set DEVICE_PASSPHRASE env var); omitted = plaintext, unchanged default behavior")
    args = parser.parse_args()
    passphrase = resolve_passphrase(args.passphrase)

    try:
        if args.pair:
            if args.peer_port is None:
                parser.error("--pair requires --peer-port (printed by device_a --pair)")
            cmd_pair(args.qr_image, args.peer_host, args.peer_port, passphrase)
        elif args.proximity:
            cmd_proximity(args.transport, args.duration, args.message, args.verbose, passphrase)
        else:
            parser.print_help()
    except WrongPassphraseError as e:
        log(DEVICE_ID, f"error: {e}")


if __name__ == "__main__":
    main()
