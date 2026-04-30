# dogel.bin v0.1 phase 1

This is the first implementation slice for `dogel.bin`.

Included:

- Rust workspace skeleton.
- `dogel-cli` binary crate.
- Cargo-safe binary target named `dogel`.
- Optional build helper that copies `target/*/dogel` to `target/*/dogel.bin`.
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

## Important naming note

Cargo does **not** allow `.` in a Rust binary target name.

This is invalid:

```toml
[[bin]]
name = "dogel.bin"
```

So the Cargo target is named:

```text
dogel
```

The produced executable can still be copied/installed as:

```text
dogel.bin
```

Use the included `Makefile`:

```bash
make build
```

This builds the valid Cargo binary and then creates:

```text
target/debug/dogel.bin
```

## Run during development

```bash
cargo run -p dogel-cli
```

or:

```bash
cargo run -p dogel-cli --bin dogel
```

## Build `dogel.bin`

Debug:

```bash
make build
./target/debug/dogel.bin
```

Release:

```bash
make release
./target/release/dogel.bin
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
