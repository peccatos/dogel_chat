use anyhow::Result;
use eve_core::{parse_user_command, CommandParseError, UserCommand};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

/// dogel.bin phase 1 entry point.
///
/// This binary currently implements only the interactive shell and command
/// parser integration. That is intentional.
///
/// The next implementation phases will add:
///
/// - identity creation/unlock;
/// - libp2p swarm startup;
/// - room state;
/// - encryption/signing;
/// - P2P message send/receive.
///
/// Starting with the shell first prevents a common failure mode:
/// mixing terminal UX bugs, cryptographic bugs and networking bugs in one
/// untestable prototype.
fn main() -> Result<()> {
    print_banner();

    let mut editor = DefaultEditor::new()?;

    loop {
        match editor.readline("dogel> ") {
            Ok(line) => {
                let trimmed = line.trim();

                if trimmed.is_empty() {
                    continue;
                }

                // Storing command history is useful for development, but later
                // we must be careful not to store sensitive command arguments.
                //
                // In v0.1, `/join --secret ...` contains a passphrase, so this
                // is a security smell. For the first parser slice it is kept
                // in memory only; we are not loading/saving history files.
                let _ = editor.add_history_entry(trimmed);

                match parse_user_command(trimmed) {
                    Ok(parsed) => {
                        if handle_command(parsed.command)? {
                            break;
                        }
                    }
                    Err(err) => print_parse_error(err),
                }
            }
            Ok(_) => {
                // `rustyline::readline` currently returns `String`, so this
                // arm is not expected. It is left out intentionally by using
                // the concrete match arms above.
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                println!("hint: use /quit to exit cleanly");
            }
            Err(ReadlineError::Eof) => {
                println!();
                println!("exit");
                break;
            }
            Err(err) => {
                eprintln!("error: failed to read input: {err}");
                break;
            }
        }
    }

    Ok(())
}

/// Handles parsed commands for phase 1.
///
/// Return value:
///
/// - `Ok(true)` means the application should exit.
/// - `Ok(false)` means keep running.
///
/// Most commands are not implemented yet. We still parse and acknowledge them
/// now because this verifies the UX contract before lower-level systems exist.
fn handle_command(command: UserCommand) -> Result<bool> {
    match command {
        UserCommand::Help => {
            print_help();
            Ok(false)
        }
        UserCommand::Quit => {
            println!("bye");
            Ok(true)
        }

        UserCommand::IdentityCreate { alias } => {
            println!("not implemented yet: would create identity '{alias}'");
            println!("next phase: password prompt + encrypted key storage");
            Ok(false)
        }

        UserCommand::Login { alias } => {
            println!("not implemented yet: would unlock identity '{alias}'");
            println!("next phase: password prompt + key decryption");
            Ok(false)
        }

        UserCommand::Whoami => {
            println!("error: no active identity");
            println!();
            println!("hint:");
            println!("  /login <alias>");
            Ok(false)
        }

        UserCommand::Connect { multiaddr } => {
            println!("not implemented yet: would connect to peer at:");
            println!("  {multiaddr}");
            println!("next phase: libp2p transport");
            Ok(false)
        }

        UserCommand::Peers => {
            println!("connected peers:");
            println!("  <none>");
            Ok(false)
        }

        UserCommand::Join {
            room_id,
            secret: _,
            ephemeral,
        } => {
            println!("not implemented yet: would join room '{room_id}'");
            println!("ephemeral: {ephemeral}");
            println!("security: room secret was parsed but is not printed");
            println!("next phase: room key derivation + room state");
            Ok(false)
        }

        UserCommand::RoomAddPeer { peer_id } => {
            println!("not implemented yet: would add peer to active room:");
            println!("  {peer_id}");
            Ok(false)
        }

        UserCommand::RoomPeers => {
            println!("error: no active room");
            println!();
            println!("hint:");
            println!("  /join 123 --secret \"shared phrase\"");
            Ok(false)
        }

        UserCommand::Rooms => {
            println!("rooms:");
            println!("  <none>");
            Ok(false)
        }

        UserCommand::Message { text } => {
            println!("error: no active room");
            println!();
            println!("hint:");
            println!("  /join 123 --secret \"shared phrase\"");
            println!();
            println!("debug: parsed message text: {text}");
            Ok(false)
        }

        UserCommand::History { enabled } => {
            println!("not implemented yet: would set history_enabled={enabled}");
            println!("note: durable encrypted history is deferred to v0.1.1");
            Ok(false)
        }
    }
}

fn print_parse_error(err: CommandParseError) {
    eprintln!("error: {err}");
}

fn print_banner() {
    println!("dogel.bin v0.1 phase 1");
    println!("interactive shell + command parser");
    println!("type /help for commands, /quit to exit");
    println!();
}

fn print_help() {
    println!("commands:");
    println!("  /identity create <alias>");
    println!("  /login <alias>");
    println!("  /whoami");
    println!("  /connect <multiaddr>");
    println!("  /peers");
    println!("  /join <room_id> --secret <passphrase> [--ephemeral]");
    println!("  /room add-peer <peer_id>");
    println!("  /room peers");
    println!("  /rooms");
    println!("  /msg <text>");
    println!("  /history on");
    println!("  /history off");
    println!("  /help");
    println!("  /quit");
    println!();
    println!("examples:");
    println!("  /join 123 --secret \"red wheelbarrow\" --ephemeral");
    println!("  /msg hello world");
}
