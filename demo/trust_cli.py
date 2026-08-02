#!/usr/bin/env python3
"""Trust management CLI for a demo device's paired peers.

  python -m demo.trust_cli device-a --list
  python -m demo.trust_cli device-a --revoke device-b --reason "lost phone"
  python -m demo.trust_cli device-a --restore device-b
  python -m demo.trust_cli device-a --remove device-b

Operates on <device_id>'s trust_db.json under demo/state/ (see trust/ and
docs/TRUST_FRAMEWORK.md). After --revoke, re-run e.g.
`python -m demo.device_a --proximity --transport wifi` against the revoked peer: it's rejected
exactly like a device that was never paired -- see trust.integration.ProtocolPeerStore, which
returns None for a revoked peer, indistinguishable on the wire from "unknown".
"""
import argparse

from demo.common import device_state_dir, log, make_trust_manager
from trust.exceptions import DeviceNotFoundError


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("device_id", help="which local device's trust store to manage, e.g. device-a")
    parser.add_argument("--list", action="store_true", help="list all paired peers and their trust status")
    parser.add_argument("--revoke", metavar="PEER_ID", help="revoke trust in a peer (reversible via --restore)")
    parser.add_argument("--reason", default=None, help="optional reason recorded with --revoke")
    parser.add_argument("--restore", metavar="PEER_ID", help="restore a previously revoked peer")
    parser.add_argument("--remove", metavar="PEER_ID", help="forget a peer entirely (irreversible, unlike --revoke)")
    args = parser.parse_args()

    state = device_state_dir(args.device_id)
    manager = make_trust_manager(state)

    try:
        if args.list:
            records = manager.list_devices()
            if not records:
                log(args.device_id, "no paired peers")
            for r in records:
                status = manager.get_status(r.device_id)
                log(args.device_id, f"{r.device_id} (alias={r.alias}) status={status.value} fingerprint={r.fingerprint}")
        elif args.revoke:
            manager.revoke_trust(args.revoke, reason=args.reason)
            suffix = f" ({args.reason})" if args.reason else ""
            log(args.device_id, f"revoked {args.revoke}{suffix}")
        elif args.restore:
            manager.restore_trust(args.restore)
            log(args.device_id, f"restored {args.restore}")
        elif args.remove:
            manager.remove_device(args.remove)
            log(args.device_id, f"removed {args.remove} (irreversible -- use --revoke instead to keep an audit trail)")
        else:
            parser.print_help()
    except DeviceNotFoundError as e:
        log(args.device_id, f"error: {e}")


if __name__ == "__main__":
    main()
