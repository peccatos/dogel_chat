.PHONY: build release test run clean

build:
	cargo build -p dogel-cli --bin dogel
	cp target/debug/dogel target/debug/dogel.bin

release:
	cargo build --release -p dogel-cli --bin dogel
	cp target/release/dogel target/release/dogel.bin

test:
	cargo test

run:
	cargo run -p dogel-cli

clean:
	cargo clean
