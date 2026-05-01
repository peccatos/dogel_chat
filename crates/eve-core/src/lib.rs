//! Core command parsing for dogel.bin.
//!
//! This crate intentionally does not know about networking, storage or
//! cryptography. Keeping it small makes it easy to test the CLI grammar before
//! we attach heavy runtime systems such as libp2p.

pub mod command;

pub use command::{parse_command, CommandParseError, PolicyCommand, TrustCommand, UserCommand};
