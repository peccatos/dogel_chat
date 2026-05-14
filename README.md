# dogel.bin v0.1 phase 16

Phase 16 keeps the encrypted P2P messaging core, trust layer, strict message policy, online invites, Phase 12 protocol hardening, Phase 13 relay/bootstrap readiness, Phase 14 ratatui layout and Phase 15 native TUI routing, then adds AutoNAT/DCUtR external-network hardening.

## Startup

Classic shell mode:

```bash
cargo run -p dogel-cli -- --listen /ip4/0.0.0.0/tcp/7777
```

TUI mode:

```bash
cargo run -p dogel-cli -- --tui --listen /ip4/0.0.0.0/tcp/7777
```

Build `dogel.bin`:

```bash
make build
./target/debug/dogel.bin --tui --listen /ip4/0.0.0.0/tcp/7777
```

Public relay/bootstrap node:

```bash
cargo run -p dogel-cli -- \
  --relay-server \
  --listen /ip4/0.0.0.0/tcp/7777 \
  --external-addr /ip4/<public-ip>/tcp/7777
```

External clients using that relay:

```bash
cargo run -p dogel-cli -- \
  --bootstrap /ip4/<relay-host>/tcp/7777/p2p/<relay-peer-id>
```

Run `/login <alias>`, then `/whoami` on each client. When the relay reservation is accepted, `/whoami` prints a `relayed listen` address that can be shared with the other client and used with `/connect`.

## TUI scope

The TUI is now the richer interactive terminal frontend:

- alternate-screen terminal interface;
- header with identity, active room and policy;
- session log with `PgUp`/`PgDn` scrollback;
- status sidebar for network, relay, rooms, invites, trust and debug state;
- single-line input panel with cursor movement, `Home`/`End`, `Delete`, `Backspace`;
- input history with `Up`/`Down`;
- native password prompts for `/identity create` and `/login`;
- command output routed into the session log instead of shell fallback;
- background P2P diagnostics routed into the TUI log;
- same command parser as shell mode;
- ordinary text without `/` still sends to active room;
- strict message policy remains active;
- no paste mode;
- no multiline input;
- no file transfer.

The shell mode remains available for line-oriented debugging, but TUI mode no longer leaves alternate-screen for normal commands.

## New commands

```text
/doctor
/debug on
/debug off
```

`/doctor` prints a health report for identity, P2P, rooms, invites, trust and policy.

`/debug on|off` toggles runtime debug state and surfaces it in `/doctor`/TUI.

## Phase 16 networking

New startup flags:

```text
--bootstrap <multiaddr>     Dial a known dogel peer at startup. Repeatable.
--relay-server              Enable circuit relay service for other peers.
--external-addr <multiaddr> Announce a public relay address manually. Repeatable.
```

The existing LAN/direct `/connect <multiaddr>` flow is unchanged. Bootstrap clients also request a circuit relay reservation by listening on the bootstrap peer's `/p2p-circuit` address.
AutoNAT now reports whether the local node is publicly reachable, and DCUtR attempts a direct upgrade once peers meet through relay.

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
- Online invites use the already-secured libp2p Noise channel, signed invite payloads, and creator-signed membership state.
- Invite-created room keys are derived from the room seed plus signed peer list, room id and protocol version.
- Relay/bootstrap only changes transport reachability. The relay forwards encrypted libp2p traffic and does not receive dogel plaintext.
- When room history is enabled, messages are written to an encrypted local history file and can be replayed from the stored history.
- Strict policy rejects links, multiline input, control characters and bursts before encryption.
- TUI mode does not weaken policy; it keeps single-line input only.

## Known limitations

- Some lower-level runtime diagnostics may still be terse until the event model is expanded.
- Online invites are not offline X25519 sealed invites yet.
- Legacy `/join --secret` rooms remain a dev shortcut and do not use signed membership.
- Relay/bootstrap is in place. Production relay operations, abuse controls and wider manual acceptance coverage are still incomplete.
