//! Core domain layer for dogel.bin.
//!
//! This crate intentionally does **not** know about stdin/stdout, libp2p,
//! filesystem storage, cryptography, or terminal rendering.
//!
//! The goal of this first slice is narrow:
//!
//! - define the user-facing command model;
//! - parse shell-like input into typed commands;
//! - return precise errors that the CLI layer can render nicely.
//!
//! Keeping this logic outside the binary matters because later frontends
//! can reuse it:
//!
//! - the current interactive CLI shell;
//! - a future `ratatui` TUI;
//! - integration tests;
//! - possibly a daemon/control socket.
//!
//! This is also where we prevent the classic CLI mistake of scattering
//! string parsing across the application runtime.

pub mod command;

pub use command::{
    parse_user_command, CommandParseError, ParsedLine, UserCommand,
};
