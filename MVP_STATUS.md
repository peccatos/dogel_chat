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
- Local encrypted message history.
- Crypto hardening:
  - Argon2id room passphrase KDF;
  - replay cache;
  - strict protocol version checks;
  - creator-signed membership for invite-created rooms;
  - room keys bound to room id, signed membership and protocol version;
  - inbound membership enforcement;
  - KDF caps;
  - identity session lock.
- Ratatui TUI mode via `--tui`:
  - header, session log, input bar and status sidebar;
  - scrollback with `PgUp`/`PgDn`;
  - input cursor movement and history;
  - in-TUI output routing for shell commands;
  - native password input for identity creation and login;
  - background P2P diagnostics routed through events.
- `/doctor`.
- `/debug on|off`.
- Peer discovery and connection routing:
  - `/connect-peer <peer_id|alias>`;
  - `/resolve-peer <peer_id|alias>`;
  - bootstrap directory registration and resolution;
  - direct-first route selection with relay fallback.
- Phase 13 relay/bootstrap readiness:
  - `--bootstrap <multiaddr>` startup dialing;
  - `--relay-server` circuit relay service mode;
  - `--external-addr <multiaddr>` manual public address announcement;
  - relay reservation diagnostics in `/doctor` and `/whoami`.
- AutoNAT/DCUtR external-network hardening:
  - NAT status reporting in `/doctor` and `/whoami`;
  - DCUtR event tracking in diagnostics;
  - relay-assisted direct-upgrade attempts for cross-network peers.

## Not done

- X25519 offline invites.
- Production relay operations and abuse controls.
- Group key rotation.
- Steganography codecs.
- Formal audit.

## Recommended next phase

Next phase should harden production relay operations, bootstrap discovery
freshness/TTL handling and multi-node manual acceptance tests.
