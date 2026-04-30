# dogel.bin v0.1 — MVP Specification

## 1. Назначение проекта

`dogel.bin` — это интерактивный P2P CLI-мессенджер на Rust с локальной identity, зашифрованными сообщениями, подписанными envelope и ручным подключением peers в локальной сети.

Версия `v0.1` deliberately LAN-first: она должна доказать, что базовая P2P-модель, identity, room encryption, signatures и command runtime работают без центрального сервера.

Главная цель `v0.1` — получить рабочий защищённый live-chat между двумя или несколькими машинами в одной локальной сети.

---

## 2. Не цели v0.1

В `v0.1` намеренно не входят:

- bootstrap nodes;
- relay nodes;
- NAT traversal;
- internet discovery;
- offline messages;
- file transfer;
- steganography implementation;
- mobile clients;
- full Signal-like group ratchet;
- server-side history;
- automatic peer discovery;
- public user directory;
- federation;
- moderation system.

Эти вещи не запрещены архитектурно, но откладываются на следующие версии.

---

## 3. Версионная дорожная карта

### v0.1 — LAN P2P MVP

- Manual peer connection via libp2p multiaddr.
- Interactive shell CLI.
- Local identities.
- Password-protected private keys.
- Ed25519 message signing key.
- Encrypted room messages.
- Per-room local member list.
- Optional ephemeral rooms.
- No server.
- No relay.
- No automatic discovery.

### v0.2 — Internet P2P

- Bootstrap nodes.
- Relay nodes.
- NAT traversal / hole punching where possible.
- More reliable peer discovery.
- Better connection diagnostics.

### v0.3+ — Stronger group model

- Invite-based room membership.
- Public-key encrypted room invites.
- Group key rotation.
- Member removal with cryptographic effect.
- Optional steganography codecs.
- TUI polish.

---

## 4. Binary and workspace naming

User-facing binary name:

```text
 dogel.bin
```

Recommended internal workspace codename:

```text
 eve
```

Recommended Rust workspace layout:

```text
eve/
  Cargo.toml

  crates/
    dogel-cli/
      Cargo.toml
      src/main.rs

    eve-core/
      Cargo.toml
      src/lib.rs

    eve-p2p/
      Cargo.toml
      src/lib.rs

    eve-protocol/
      Cargo.toml
      src/lib.rs

    eve-crypto/
      Cargo.toml
      src/lib.rs

    eve-storage/
      Cargo.toml
      src/lib.rs
```

`dogel.bin` is the executable. Internal crates use `eve-*` naming to keep domain modules clean and reusable.

---

## 5. Runtime mode

`dogel.bin v0.1` runs as an interactive shell session.

Example startup:

```bash
dogel.bin --listen /ip4/0.0.0.0/tcp/7777
```

Default listen address if omitted:

```text
/ip4/0.0.0.0/tcp/7777
```

Inside the shell:

```text
dogel> /identity create elliot
dogel> /login elliot
dogel> /whoami
dogel> /connect /ip4/192.168.1.20/tcp/7777/p2p/12D3KooW...
dogel> /join 123 --secret "red wheelbarrow" --ephemeral
dogel> /room add-peer 12D3KooW...
dogel> /msg hello world
dogel> /quit
```

The process owns:

- stdin command loop;
- libp2p swarm event loop;
- application state;
- active identity;
- active room;
- room sessions;
- peer connections;
- message renderer.

Implementation should use an async event loop, likely based on `tokio::select!`.

---

## 6. CLI command format

Commands use shell-like syntax:

```text
/command arg1 arg2 --flag value --bool-flag
```

The parser must support quoted arguments:

```text
/join 123 --secret "red wheelbarrow" --ephemeral
```

Do not use naive `split_whitespace()` because it breaks quoted secrets.

Recommended parsing approach:

- use a shell-like tokenizer such as `shell-words`;
- map tokenized input into a strict `UserCommand` enum;
- return structured, human-readable errors.

`/msg` is special: it should accept the full remaining text as the message body without requiring quotes.

Valid:

```text
/msg hello world
```

---

## 7. Command list v0.1

Required commands:

```text
/identity create <alias>
/login <alias>
/whoami
/connect <multiaddr>
/peers
/join <room_id> --secret <passphrase> [--ephemeral]
/room add-peer <peer_id>
/room peers
/rooms
/msg <text>
/history on
/history off
/help
/quit
```

---

## 8. Command semantics

### `/identity create <alias>`

Creates a new local identity.

Example:

```text
dogel> /identity create elliot
Password: ********
Confirm password: ********
```

Behavior:

1. Validate alias.
2. Fail if identity already exists.
3. Prompt password interactively.
4. Confirm password interactively.
5. Generate libp2p network keypair.
6. Generate Ed25519 signing keypair.
7. Derive local encryption key from password using Argon2id.
8. Encrypt private key material.
9. Write public profile metadata.
10. Print created identity summary.

Expected output:

```text
created identity:
  alias: elliot
  peer_id: 12D3KooW...
  fingerprint: 91:AF:22:C0:7A:...
```

Password must never be accepted as a command-line argument.

---

### `/login <alias>`

Unlocks an existing local identity.

Example:

```text
dogel> /login elliot
Password: ********
```

Behavior:

1. Load public profile metadata.
2. Prompt password interactively.
3. Derive local encryption key with stored KDF params.
4. Decrypt network private key.
5. Decrypt signing private key.
6. Set active identity.
7. Start or reconfigure libp2p swarm with unlocked network identity if not already initialized.

Expected output:

```text
unlocked identity:
  alias: elliot
  peer_id: 12D3KooW...
  fingerprint: 91:AF:22:C0:7A:...
```

---

### `/whoami`

Shows active identity and listen addresses.

Expected output:

```text
alias: elliot
peer_id: 12D3KooW...
fingerprint: 91:AF:22:C0:7A:...
listen:
  /ip4/0.0.0.0/tcp/7777
  /ip4/192.168.1.14/tcp/7777/p2p/12D3KooW...
```

If no identity is unlocked:

```text
error: no active identity

hint:
  /login <alias>
```

---

### `/connect <multiaddr>`

Connects to a peer manually.

Example:

```text
/connect /ip4/192.168.1.20/tcp/7777/p2p/12D3KooW...
```

Behavior:

1. Parse multiaddr.
2. Ensure peer id is present in address.
3. Dial via libp2p.
4. Add peer to connected peer list after connection succeeds.
5. Print connection status.

Errors must clearly distinguish:

- invalid multiaddr;
- missing `/p2p/<peer_id>`;
- dial timeout;
- peer rejected connection;
- unsupported transport.

---

### `/peers`

Lists connected peers.

Example output:

```text
connected peers:
  12D3KooWAlice   connected=true
  12D3KooWBob     connected=true
```

For v0.1, peer aliases are optional because alias-to-key binding is not yet part of the handshake model.

---

### `/join <room_id> --secret <passphrase> [--ephemeral]`

Creates or activates a local room session.

Example:

```text
/join 123 --secret "red wheelbarrow" --ephemeral
```

Behavior:

1. Validate room id.
2. Require `--secret`.
3. Derive room key from `room_id + passphrase`.
4. If room does not exist locally, create it.
5. If room exists with same derived key, activate it.
6. If room exists with different derived key, fail.
7. Set `active_room = room_id`.
8. If `--ephemeral`, do not persist room config or history.

Expected output:

```text
joined room: 123
active room: 123
ephemeral: true
history: false
```

If secret differs from existing room key:

```text
error: room 123 already exists with a different key

hint:
  leave/recreate is not supported in v0.1
```

Important: `/join` acts as both create and switch. There is no separate `/switch` command in v0.1.

---

### `/room add-peer <peer_id>`

Adds a connected peer to the active room's local routing member list.

Example:

```text
/room add-peer 12D3KooWBob
```

Behavior:

1. Require active room.
2. Require peer to be currently connected.
3. Add peer id to active room members if not already present.
4. Do not send room key.
5. Do not perform cryptographic invite flow.

Expected output:

```text
added peer to room 123:
  12D3KooWBob
```

If no active room:

```text
error: no active room

hint:
  /join 123 --secret "shared phrase"
```

If peer is not connected:

```text
error: peer is not connected

hint:
  use /connect <multiaddr> first
```

---

### `/room peers`

Shows peers in the active room.

Example output:

```text
room: 123
members:
  12D3KooWAlice   self=true
  12D3KooWBob     connected=true
```

For v0.1, membership is local routing metadata, not cryptographic membership.

---

### `/rooms`

Lists local room sessions.

Example output:

```text
rooms:
  * 123      ephemeral=true   history=false   members=2
    dev      ephemeral=false  history=false   members=1
```

`*` marks the active room.

---

### `/msg <text>`

Sends a message to the active room.

Example:

```text
/msg hello world
```

Behavior:

1. Require active identity.
2. Require active room.
3. Require at least one connected room peer besides self.
4. Build plaintext message.
5. Encrypt plaintext using room key.
6. Build envelope.
7. Sign envelope with Ed25519 signing key.
8. Send only to active room members that are currently connected.
9. Render local sent message.

If no active room:

```text
error: no active room

hint:
  /join 123 --secret "shared phrase"
```

If room has no connected peers:

```text
error: room has no connected peers

hint:
  /room add-peer <peer_id>
```

---

### `/history on`

Enables local encrypted history for the active room.

Rules:

- Requires active room.
- Fails for ephemeral rooms.
- Writes only encrypted history.
- Never sends history to peers.

If active room is ephemeral:

```text
error: cannot enable history for an ephemeral room
```

---

### `/history off`

Disables local history for the active room.

Rules:

- Does not necessarily delete previous history.
- Deletion should be a future explicit command, not implicit behavior.

---

### `/help`

Prints command usage.

---

### `/quit`

Gracefully exits:

1. Stop accepting input.
2. Close libp2p swarm.
3. Zeroize unlocked private key material where possible.
4. Flush pending storage writes.
5. Exit process.

---

## 9. Identity model

Each identity has:

```text
alias
network keypair
signing keypair
fingerprint
created_at_ms
```

### Alias

Human-readable local name.

Alias is not a security boundary. It is display metadata only.

### Network keypair

Used by libp2p to derive `PeerId` and establish secure P2P connections.

### Signing keypair

Separate Ed25519 keypair used to sign encrypted message envelopes.

### Fingerprint

Derived from signing public key, not alias.

UI should display short fingerprint near alias when possible:

```text
elliot [91:AF:22:C0]: hello world
```

---

## 10. Local storage layout

Logical application config root:

```text
~/.config/dogel/
```

Use a cross-platform directory crate such as `directories` instead of hardcoding this path.

Identity layout:

```text
~/.config/dogel/
  identities/
    elliot/
      profile.toml
      network_key.enc
      signing_key.enc
      rooms.toml
      history/
```

### `profile.toml`

Public metadata, readable without password:

```toml
alias = "elliot"
created_at_ms = 1710000000000

[network]
peer_id = "12D3KooW..."

[signing]
fingerprint = "91:AF:22:C0:7A:..."
public_key = "base64..."
```

### `network_key.enc`

Encrypted libp2p private key.

### `signing_key.enc`

Encrypted Ed25519 signing private key.

### `rooms.toml`

Persistent non-ephemeral room metadata.

Must not contain plaintext room passphrases.

May contain:

```toml
[[rooms]]
room_id = "123"
ephemeral = false
history_enabled = false
members = ["12D3KooW..."]
```

Room keys should not be stored in plaintext.

For v0.1, persistent room key storage can be deferred. If deferred, user must re-enter `--secret` after restart.

### `history/`

Encrypted local room history files.

No plaintext message history should be written to disk.

---

## 11. Encrypted private key file format

Encrypted private key files must be versioned envelopes.

Conceptual structure:

```text
EncryptedPrivateKeyFile {
    version,
    kdf,
    kdf_params,
    salt,
    nonce,
    ciphertext,
}
```

Required KDF:

```text
Argon2id
```

Required AEAD:

```text
XChaCha20Poly1305 or ChaCha20Poly1305
```

Recommendation: prefer `XChaCha20Poly1305` for local file encryption because its larger nonce reduces accidental nonce-reuse risk.

Private key bytes should be zeroized after use where practical.

---

## 12. Room model

Runtime room session:

```text
RoomSession {
    room_id,
    room_key,
    ephemeral,
    history_enabled,
    members,
}
```

### Room key derivation

For v0.1:

```text
room_key = KDF(room_id + shared passphrase)
```

Recommended:

- use a domain-separated KDF input;
- include room id;
- do not store passphrase;
- do not print derived key;
- do not send room key over network.

Example conceptual input:

```text
DOGEL_ROOM_KEY_V1 || room_id || passphrase
```

### Ephemeral rooms

Ephemeral room rules:

- room key is memory-only;
- room config is not persisted;
- history is always disabled;
- `/history on` fails;
- after process exit, room cannot be restored unless user rejoins with same room id and secret.

---

## 13. Messaging model

`v0.1` uses per-room peer routing, not global flooding.

Message sending:

1. User sends `/msg <text>`.
2. App finds active room.
3. App serializes plaintext message.
4. App encrypts plaintext with room key.
5. App creates encrypted envelope.
6. App signs envelope.
7. App sends only to connected peers in active room's member list.

Receiving side:

1. Receive envelope from libp2p.
2. Parse envelope.
3. Verify signature.
4. Check whether local room exists.
5. Attempt decrypt with local room key.
6. If decrypt succeeds, render message.
7. If room unknown or decrypt fails, ignore or show debug event depending on verbosity.

Membership in v0.1 is local routing metadata, not cryptographic membership.

This means:

- adding a peer controls who receives messages from this client;
- it does not securely distribute room keys;
- it does not revoke access if old room secret is known;
- real invite and key rotation are future work.

---

## 14. Protocol envelope

Conceptual message envelope:

```text
SignedEncryptedEnvelope {
    version,
    room_id,
    sender_alias,
    sender_peer_id,
    sender_signing_public_key,
    timestamp_ms,
    nonce,
    ciphertext,
    signature,
}
```

Signature should cover all fields except `signature`.

Important: `sender_alias` is display metadata only. Trust is anchored in `sender_signing_public_key` and fingerprint.

Plaintext message before encryption:

```text
PlainMessage {
    room_id,
    body,
    timestamp_ms,
}
```

The room id is present both outside and inside encryption in v0.1.

Trade-off:

- external `room_id` allows routing and local lookup;
- it leaks room identifier to peers receiving the envelope;
- future versions may use encrypted or hashed room ids.

---

## 15. Networking model

Use libp2p for P2P networking.

v0.1 supports:

- TCP transport;
- local LAN dialing;
- manual multiaddr connection;
- direct peer messaging;
- no relay;
- no discovery;
- no NAT traversal.

Default listen address:

```text
/ip4/0.0.0.0/tcp/7777
```

A connectable address should include peer id:

```text
/ip4/192.168.1.20/tcp/7777/p2p/12D3KooW...
```

---

## 16. App state model

Conceptual runtime state:

```text
AppState {
    active_identity,
    connected_peers,
    rooms,
    active_room,
    history_policy,
}
```

### Active identity

None until `/login <alias>` succeeds.

### Connected peers

Peers connected via `/connect` or inbound libp2p connections.

### Rooms

Map of room id to room session.

### Active room

Set by `/join`.

---

## 17. Error handling principles

Errors should be direct, specific and actionable.

Bad:

```text
error: failed
```

Good:

```text
error: missing required flag --secret

usage:
  /join <room_id> --secret <passphrase> [--ephemeral]
```

Each command should return:

- success message;
- structured error;
- optional hint.

---

## 18. Security principles

### Passwords

- Never send password over network.
- Never accept password via CLI argument.
- Never log password.
- Use interactive prompt only.

### Private keys

- Store encrypted at rest.
- Decrypt only after `/login`.
- Keep in memory only while identity is active.
- Zeroize where practical.

### Message security

- Encrypt plaintext before sending.
- Sign encrypted envelope.
- Verify signature before rendering.
- Treat alias as untrusted display metadata.

### History

- Default off.
- If enabled, encrypted only.
- Ephemeral rooms forbid history.

### Known v0.1 limitations

- No metadata hiding.
- Room id is visible to message recipients.
- Manual shared room secret is not an ideal invite mechanism.
- No group key rotation.
- No cryptographic member removal.
- No protection if users share room secret insecurely.
- LAN-only direct connectivity.

---

## 19. Recommended Rust crates

Core async/runtime:

```text
tokio
futures
```

P2P:

```text
libp2p
```

CLI parsing/input:

```text
shell-words
rpassword
```

Serialization:

```text
serde
serde_json initially, postcard/bincode later
```

Crypto:

```text
argon2
chacha20poly1305
ed25519-dalek
rand
sha2 or blake3
zeroize
base64
```

Storage/config:

```text
directories
toml
```

Errors/logging:

```text
thiserror
anyhow for binary boundary only
tracing
tracing-subscriber
```

---

## 20. Suggested implementation phases

### Phase 1 — workspace and command shell

- Create Rust workspace.
- Add `dogel-cli` binary with binary name `dogel.bin`.
- Implement interactive prompt.
- Implement shell-like parser.
- Implement `UserCommand` enum.
- Implement `/help` and `/quit`.

### Phase 2 — identity storage

- Implement `/identity create`.
- Implement `/login`.
- Store profile metadata.
- Encrypt private keys.
- Show `/whoami` without networking polish.

### Phase 3 — libp2p LAN connect

- Start libp2p swarm after identity unlock.
- Listen on default address.
- Implement `/connect`.
- Implement `/peers`.
- Verify two local clients can connect.

### Phase 4 — rooms

- Implement `/join`.
- Derive room key.
- Manage active room.
- Implement `/rooms`.
- Implement `/room add-peer`.
- Implement `/room peers`.

### Phase 5 — encrypted messaging

- Define protocol envelope.
- Encrypt plaintext messages.
- Sign encrypted envelopes.
- Send to room members only.
- Verify/decrypt/render on receive.

### Phase 6 — history and ephemeral polish

- Implement `/history on/off`.
- Enforce no history for ephemeral rooms.
- Add encrypted history writer if included in v0.1.
- Improve errors and diagnostics.

### Phase 7 — TUI preparation

- Keep core independent from stdin/stdout.
- Ensure future `ratatui` frontend can reuse `eve-core`.

---

## 21. Open decisions before coding

The following should be decided before implementation starts:

1. Should encrypted local history be implemented in v0.1 initial code, or deferred to v0.1.1?
2. Should persistent non-ephemeral room keys be stored encrypted, or should users re-enter room secrets after restart?
3. Which exact AEAD should be used for message encryption: `ChaCha20Poly1305` or `XChaCha20Poly1305`?
4. Which exact hash/fingerprint format should be displayed?
5. Should inbound connections be automatically accepted in v0.1?

Recommended defaults:

1. Defer full history writer to v0.1.1, but keep commands and state model.
2. Re-enter room secrets after restart in v0.1.
3. Use `ChaCha20Poly1305` for messages, `XChaCha20Poly1305` for local files if available.
4. Fingerprint = BLAKE3 or SHA-256 hash of signing public key, displayed as first 8 bytes hex.
5. Accept inbound connections, but do not add them to any room automatically.

