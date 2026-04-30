# Cargo cannot use `dogel.bin` as the actual binary target name because
# Rust crate/binary target identifiers cannot contain a dot.
#
# Therefore the real Cargo target is `dogel`, and this Makefile copies the
# compiled executable to the user-facing name `dogel.bin`.

.PHONY: build release test run clean

build:
	cargo build -p dogel-cli --bin dogel
	cp target/debug/dogel target/debug/dogel.bin
	@echo "built target/debug/dogel.bin"

release:
	cargo build --release -p dogel-cli --bin dogel
	cp target/release/dogel target/release/dogel.bin
	@echo "built target/release/dogel.bin"

run:
	cargo run -p dogel-cli --bin dogel

test:
	cargo test

clean:
	cargo clean
