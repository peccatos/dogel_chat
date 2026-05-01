# dogel.bin v0.1 MVP Status

## Done

- Interactive shell parser.
- Local identity creation.
- Password-protected local private keys.
- libp2p LAN P2P connections.
- Encrypted signed messages.
- Rooms and direct rooms.
- Online invites.
- Trust store.
- Strict message policy.
- Crypto hardening:
  - Argon2id room passphrase KDF;
  - replay cache;
  - inbound membership enforcement;
  - KDF caps;
  - identity session lock.
- Minimal TUI mode via `--tui`.
- `/doctor`.
- `/debug on|off`.

## Not done

- Full TUI polish.
- Local encrypted message history.
- X25519 offline invites.
- Relay/bootstrap/NAT traversal.
- Group key rotation.
- Steganography codecs.
- Formal audit.

## Recommended next phase

Phase 12 should either:

1. harden TUI output routing with a real `AppOutput` event bus; or
2. implement encrypted local history v0.1.1.

Do not start relay/NAT traversal before the UI/event boundaries are cleaner.
