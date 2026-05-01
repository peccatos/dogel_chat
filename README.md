# dogel.bin v0.1 phase 11

Phase 11 keeps the working encrypted P2P messaging core, trust layer, strict message policy, crypto-hardening and online invites, then adds a minimal TUI mode plus stabilization commands.

## Startup

Classic shell mode:

```bash
cargo run -p dogel-cli -- --listen /ip4/0.0.0.0/tcp/7777
```

Minimal TUI mode:

```bash
cargo run -p dogel-cli -- --tui --listen /ip4/0.0.0.0/tcp/7777
```

Build `dogel.bin`:

```bash
make build
./target/debug/dogel.bin --tui --listen /ip4/0.0.0.0/tcp/7777
```

## TUI scope

The TUI is intentionally minimal:

- alternate-screen terminal interface;
- header with identity, room, peer count, trust count, policy and debug status;
- session log panel;
- single-line input panel;
- same command parser as shell mode;
- ordinary text without `/` still sends to active room;
- strict message policy remains active;
- no paste mode;
- no multiline input;
- no file transfer.

The shell mode remains the most stable debugging interface.

## New commands

```text
/doctor
/debug on
/debug off
```

`/doctor` prints a health report for identity, P2P, rooms, invites, trust and policy.

`/debug on|off` toggles runtime debug state. Phase 11 stores the flag and surfaces it in `/doctor`/TUI. Deeper debug routing can be attached later.

## Existing invite flow

Peer A:

```text
/login <alias-a>
/connect /ip4/<host>/tcp/<port>/p2p/<peer-id-b>
/create-room --ephemeral
/invite <peer-id-b>
```

Peer B:

```text
/login <alias-b>
/connect /ip4/<host>/tcp/<port>/p2p/<peer-id-a>
/invites
/accept-invite <invite-id>
hello
```

## Security notes

- Private keys are encrypted locally using password-derived keys.
- Messages are encrypted with room keys and signed.
- Room passphrase derivation uses Argon2id in the dev shortcut paths.
- Online invites use the already-secured libp2p Noise channel and signed invite payloads.
- Strict policy rejects links, multiline input, control characters and bursts before encryption.
- TUI mode does not weaken policy; it keeps single-line input only.

## Known limitations

- TUI is minimal and not yet a full ratatui application architecture.
- Some low-level background diagnostics may still be printed by runtime tasks.
- Online invites are not offline X25519 sealed invites yet.
- No local encrypted history writer yet.
- No relay/bootstrap/NAT traversal yet.
