# dogel.bin v0.1 phase 1

This is the first implementation slice for `dogel.bin`.

Included:

- Rust workspace skeleton.
- `dogel-cli` binary crate producing `dogel.bin`.
- `eve-core` crate with shell-like command parsing.
- Interactive shell runtime.
- `/help` and `/quit`.
- Parser support for quoted flags.
- `/msg` free text parsing.
- Unit tests for the command parser.

Not included yet:

- libp2p networking.
- identity storage.
- cryptography.
- room runtime state.
- encrypted messaging.

## Run

```bash
cargo run -p dogel-cli
```

The binary target itself is named:

```text
dogel.bin
```

## Test

```bash
cargo test
```

## Example session

```text
dogel> /help
dogel> /identity create elliot
dogel> /login elliot
dogel> /join 123 --secret "red wheelbarrow" --ephemeral
dogel> /room add-peer 12D3KooWBob
dogel> /msg hello world
dogel> /quit
```
