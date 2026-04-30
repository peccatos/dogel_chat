use std::fmt;

/// A successfully parsed input line.
///
/// The CLI runtime currently only needs `command`, but wrapping it gives us
/// space for future metadata without changing the public parser shape.
/// Examples of future metadata:
///
/// - original raw line for audit/debug mode;
/// - redacted raw line for logs;
/// - command source: stdin, TUI, script, test harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedLine {
    pub command: UserCommand,
}

/// Typed command model for dogel.bin v0.1.
///
/// This enum is intentionally explicit. A stringly-typed command bus would
/// be faster to hack together, but it would push validation bugs into the
/// runtime and networking layers.
///
/// Trade-off:
///
/// - More enum variants and parser code now.
/// - Much safer application logic later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserCommand {
    /// `/identity create <alias>`
    ///
    /// Creates a local identity. The password is not part of this command:
    /// it must be requested interactively by the binary layer.
    IdentityCreate {
        alias: String,
    },

    /// `/login <alias>`
    ///
    /// Unlocks an existing local identity. Password prompting also belongs
    /// to the binary/storage layer, not the parser.
    Login {
        alias: String,
    },

    /// `/whoami`
    Whoami,

    /// `/connect <multiaddr>`
    ///
    /// In v0.1 this will be a manual libp2p multiaddr.
    Connect {
        multiaddr: String,
    },

    /// `/peers`
    Peers,

    /// `/join <room_id> --secret <passphrase> [--ephemeral]`
    ///
    /// Creates or activates a local room session.
    Join {
        room_id: String,
        secret: String,
        ephemeral: bool,
    },

    /// `/room add-peer <peer_id>`
    RoomAddPeer {
        peer_id: String,
    },

    /// `/room peers`
    RoomPeers,

    /// `/rooms`
    Rooms,

    /// `/msg <text>`
    ///
    /// The message body is the full remaining text, not shell-tokenized.
    /// This is deliberate: users should not need quotes for normal chat.
    Message {
        text: String,
    },

    /// `/history on` or `/history off`
    History {
        enabled: bool,
    },

    /// `/help`
    Help,

    /// `/quit`
    Quit,
}

/// Parser errors that are specific enough for the CLI to print actionable
/// messages.
///
/// Do not collapse these into `anyhow::Error` inside `eve-core`.
/// `anyhow` is fine at the binary boundary, but the domain layer should
/// expose structured errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandParseError {
    EmptyInput,
    MissingLeadingSlash,
    UnknownCommand {
        command: String,
    },
    InvalidSyntax {
        message: String,
        usage: Option<&'static str>,
    },
    TokenizationFailed {
        message: String,
    },
}

impl fmt::Display for CommandParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandParseError::EmptyInput => write!(f, "empty input"),
            CommandParseError::MissingLeadingSlash => {
                write!(f, "commands must start with '/'")
            }
            CommandParseError::UnknownCommand { command } => {
                write!(f, "unknown command: {command}")
            }
            CommandParseError::InvalidSyntax { message, usage } => {
                write!(f, "{message}")?;
                if let Some(usage) = usage {
                    write!(f, "\n\nusage:\n  {usage}")?;
                }
                Ok(())
            }
            CommandParseError::TokenizationFailed { message } => {
                write!(f, "failed to parse command line: {message}")
            }
        }
    }
}

impl std::error::Error for CommandParseError {}

/// Parse one raw user input line into a typed command.
///
/// Important design decisions:
///
/// 1. All commands must start with `/`.
///    This keeps chat text and control commands clearly separated.
///
/// 2. `/msg` is parsed before shell tokenization.
///    `shell_words::split()` would preserve quoted text but still tokenizes
///    everything. For chat messages, the expected UX is:
///
///    `/msg hello world`
///
///    not:
///
///    `/msg "hello world"`
///
/// 3. All non-`/msg` commands use shell-like tokenization.
///    This gives us quoted flags such as:
///
///    `/join 123 --secret "red wheelbarrow" --ephemeral`
pub fn parse_user_command(input: &str) -> Result<ParsedLine, CommandParseError> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(CommandParseError::EmptyInput);
    }

    if !trimmed.starts_with('/') {
        return Err(CommandParseError::MissingLeadingSlash);
    }

    // `/msg` gets special treatment so the whole remainder becomes message
    // text. This is closer to how real chat clients behave.
    if trimmed == "/msg" || trimmed.starts_with("/msg ") {
        return parse_msg_command(trimmed);
    }

    let tokens = shell_words::split(trimmed)
        .map_err(|err| CommandParseError::TokenizationFailed {
            message: err.to_string(),
        })?;

    if tokens.is_empty() {
        return Err(CommandParseError::EmptyInput);
    }

    let command = tokens[0].as_str();

    match command {
        "/identity" => parse_identity(&tokens),
        "/login" => parse_login(&tokens),
        "/whoami" => expect_exact_arity(&tokens, 1, "/whoami").map(|_| UserCommand::Whoami),
        "/connect" => parse_connect(&tokens),
        "/peers" => expect_exact_arity(&tokens, 1, "/peers").map(|_| UserCommand::Peers),
        "/join" => parse_join(&tokens),
        "/room" => parse_room(&tokens),
        "/rooms" => expect_exact_arity(&tokens, 1, "/rooms").map(|_| UserCommand::Rooms),
        "/history" => parse_history(&tokens),
        "/help" => expect_exact_arity(&tokens, 1, "/help").map(|_| UserCommand::Help),
        "/quit" | "/exit" => expect_exact_arity(&tokens, 1, "/quit").map(|_| UserCommand::Quit),
        other => Err(CommandParseError::UnknownCommand {
            command: other.to_string(),
        }),
    }
    .map(|command| ParsedLine { command })
}

fn parse_msg_command(trimmed: &str) -> Result<ParsedLine, CommandParseError> {
    let text = trimmed.strip_prefix("/msg").unwrap_or("").trim();

    if text.is_empty() {
        return Err(CommandParseError::InvalidSyntax {
            message: "missing message text".to_string(),
            usage: Some("/msg <text>"),
        });
    }

    Ok(ParsedLine {
        command: UserCommand::Message {
            text: text.to_string(),
        },
    })
}

fn parse_identity(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    if tokens.len() != 3 || tokens[1] != "create" {
        return Err(CommandParseError::InvalidSyntax {
            message: "invalid identity command".to_string(),
            usage: Some("/identity create <alias>"),
        });
    }

    let alias = validate_non_empty("alias", &tokens[2], "/identity create <alias>")?;

    Ok(UserCommand::IdentityCreate {
        alias: alias.to_string(),
    })
}

fn parse_login(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    expect_exact_arity(tokens, 2, "/login <alias>")?;

    let alias = validate_non_empty("alias", &tokens[1], "/login <alias>")?;

    Ok(UserCommand::Login {
        alias: alias.to_string(),
    })
}

fn parse_connect(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    expect_exact_arity(tokens, 2, "/connect <multiaddr>")?;

    let multiaddr = validate_non_empty("multiaddr", &tokens[1], "/connect <multiaddr>")?;

    Ok(UserCommand::Connect {
        multiaddr: multiaddr.to_string(),
    })
}

fn parse_join(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    if tokens.len() < 4 {
        return Err(CommandParseError::InvalidSyntax {
            message: "missing required room id or --secret".to_string(),
            usage: Some("/join <room_id> --secret <passphrase> [--ephemeral]"),
        });
    }

    let room_id = validate_non_empty(
        "room_id",
        &tokens[1],
        "/join <room_id> --secret <passphrase> [--ephemeral]",
    )?;

    let mut secret: Option<String> = None;
    let mut ephemeral = false;

    let mut idx = 2;
    while idx < tokens.len() {
        match tokens[idx].as_str() {
            "--secret" => {
                let value = tokens.get(idx + 1).ok_or_else(|| {
                    CommandParseError::InvalidSyntax {
                        message: "missing value for --secret".to_string(),
                        usage: Some("/join <room_id> --secret <passphrase> [--ephemeral]"),
                    }
                })?;

                if value.starts_with("--") {
                    return Err(CommandParseError::InvalidSyntax {
                        message: "missing value for --secret".to_string(),
                        usage: Some("/join <room_id> --secret <passphrase> [--ephemeral]"),
                    });
                }

                secret = Some(value.clone());
                idx += 2;
            }
            "--ephemeral" => {
                ephemeral = true;
                idx += 1;
            }
            unknown => {
                return Err(CommandParseError::InvalidSyntax {
                    message: format!("unknown /join flag or argument: {unknown}"),
                    usage: Some("/join <room_id> --secret <passphrase> [--ephemeral]"),
                });
            }
        }
    }

    let secret = secret.ok_or_else(|| CommandParseError::InvalidSyntax {
        message: "missing required flag --secret".to_string(),
        usage: Some("/join <room_id> --secret <passphrase> [--ephemeral]"),
    })?;

    if secret.trim().is_empty() {
        return Err(CommandParseError::InvalidSyntax {
            message: "secret must not be empty".to_string(),
            usage: Some("/join <room_id> --secret <passphrase> [--ephemeral]"),
        });
    }

    Ok(UserCommand::Join {
        room_id: room_id.to_string(),
        secret,
        ephemeral,
    })
}

fn parse_room(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    if tokens.len() < 2 {
        return Err(CommandParseError::InvalidSyntax {
            message: "missing room subcommand".to_string(),
            usage: Some("/room add-peer <peer_id>\n  /room peers"),
        });
    }

    match tokens[1].as_str() {
        "add-peer" => {
            if tokens.len() != 3 {
                return Err(CommandParseError::InvalidSyntax {
                    message: "invalid /room add-peer command".to_string(),
                    usage: Some("/room add-peer <peer_id>"),
                });
            }

            let peer_id = validate_non_empty("peer_id", &tokens[2], "/room add-peer <peer_id>")?;

            Ok(UserCommand::RoomAddPeer {
                peer_id: peer_id.to_string(),
            })
        }
        "peers" => {
            expect_exact_arity(tokens, 2, "/room peers")?;
            Ok(UserCommand::RoomPeers)
        }
        other => Err(CommandParseError::InvalidSyntax {
            message: format!("unknown /room subcommand: {other}"),
            usage: Some("/room add-peer <peer_id>\n  /room peers"),
        }),
    }
}

fn parse_history(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    expect_exact_arity(tokens, 2, "/history on|off")?;

    match tokens[1].as_str() {
        "on" => Ok(UserCommand::History { enabled: true }),
        "off" => Ok(UserCommand::History { enabled: false }),
        other => Err(CommandParseError::InvalidSyntax {
            message: format!("invalid history mode: {other}"),
            usage: Some("/history on|off"),
        }),
    }
}

fn expect_exact_arity(
    tokens: &[String],
    expected: usize,
    usage: &'static str,
) -> Result<(), CommandParseError> {
    if tokens.len() == expected {
        Ok(())
    } else {
        Err(CommandParseError::InvalidSyntax {
            message: format!(
                "invalid number of arguments: expected {}, got {}",
                expected.saturating_sub(1),
                tokens.len().saturating_sub(1)
            ),
            usage: Some(usage),
        })
    }
}

fn validate_non_empty<'a>(
    field: &'static str,
    value: &'a str,
    usage: &'static str,
) -> Result<&'a str, CommandParseError> {
    if value.trim().is_empty() {
        Err(CommandParseError::InvalidSyntax {
            message: format!("{field} must not be empty"),
            usage: Some(usage),
        })
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> UserCommand {
        parse_user_command(input).unwrap().command
    }

    #[test]
    fn parses_identity_create() {
        assert_eq!(
            parse("/identity create elliot"),
            UserCommand::IdentityCreate {
                alias: "elliot".to_string()
            }
        );
    }

    #[test]
    fn rejects_invalid_identity_command() {
        let err = parse_user_command("/identity delete elliot").unwrap_err();

        assert!(matches!(err, CommandParseError::InvalidSyntax { .. }));
    }

    #[test]
    fn parses_login() {
        assert_eq!(
            parse("/login elliot"),
            UserCommand::Login {
                alias: "elliot".to_string()
            }
        );
    }

    #[test]
    fn parses_whoami() {
        assert_eq!(parse("/whoami"), UserCommand::Whoami);
    }

    #[test]
    fn parses_connect() {
        assert_eq!(
            parse("/connect /ip4/192.168.1.20/tcp/7777/p2p/12D3KooW"),
            UserCommand::Connect {
                multiaddr: "/ip4/192.168.1.20/tcp/7777/p2p/12D3KooW".to_string()
            }
        );
    }

    #[test]
    fn parses_peers() {
        assert_eq!(parse("/peers"), UserCommand::Peers);
    }

    #[test]
    fn parses_join_with_quoted_secret_and_ephemeral() {
        assert_eq!(
            parse(r#"/join 123 --secret "red wheelbarrow" --ephemeral"#),
            UserCommand::Join {
                room_id: "123".to_string(),
                secret: "red wheelbarrow".to_string(),
                ephemeral: true,
            }
        );
    }

    #[test]
    fn parses_join_when_ephemeral_comes_before_secret() {
        assert_eq!(
            parse(r#"/join 123 --ephemeral --secret "red wheelbarrow""#),
            UserCommand::Join {
                room_id: "123".to_string(),
                secret: "red wheelbarrow".to_string(),
                ephemeral: true,
            }
        );
    }

    #[test]
    fn rejects_join_without_secret() {
        let err = parse_user_command("/join 123 --ephemeral").unwrap_err();

        assert!(matches!(
            err,
            CommandParseError::InvalidSyntax { message, .. }
            if message.contains("--secret")
        ));
    }

    #[test]
    fn parses_room_add_peer() {
        assert_eq!(
            parse("/room add-peer 12D3KooWBob"),
            UserCommand::RoomAddPeer {
                peer_id: "12D3KooWBob".to_string()
            }
        );
    }

    #[test]
    fn parses_room_peers() {
        assert_eq!(parse("/room peers"), UserCommand::RoomPeers);
    }

    #[test]
    fn parses_rooms() {
        assert_eq!(parse("/rooms"), UserCommand::Rooms);
    }

    #[test]
    fn parses_msg_free_text_without_quotes() {
        assert_eq!(
            parse("/msg hello world from dogel"),
            UserCommand::Message {
                text: "hello world from dogel".to_string()
            }
        );
    }

    #[test]
    fn preserves_quotes_inside_msg_text() {
        assert_eq!(
            parse(r#"/msg say "hello" to bob"#),
            UserCommand::Message {
                text: r#"say "hello" to bob"#.to_string()
            }
        );
    }

    #[test]
    fn rejects_empty_msg() {
        let err = parse_user_command("/msg").unwrap_err();

        assert!(matches!(err, CommandParseError::InvalidSyntax { .. }));
    }

    #[test]
    fn parses_history_on_off() {
        assert_eq!(parse("/history on"), UserCommand::History { enabled: true });
        assert_eq!(parse("/history off"), UserCommand::History { enabled: false });
    }

    #[test]
    fn parses_help() {
        assert_eq!(parse("/help"), UserCommand::Help);
    }

    #[test]
    fn parses_quit_and_exit() {
        assert_eq!(parse("/quit"), UserCommand::Quit);
        assert_eq!(parse("/exit"), UserCommand::Quit);
    }

    #[test]
    fn rejects_unknown_command() {
        let err = parse_user_command("/unknown").unwrap_err();

        assert!(matches!(err, CommandParseError::UnknownCommand { .. }));
    }

    #[test]
    fn rejects_missing_leading_slash() {
        let err = parse_user_command("msg hello").unwrap_err();

        assert_eq!(err, CommandParseError::MissingLeadingSlash);
    }

    #[test]
    fn rejects_unclosed_quote() {
        let err = parse_user_command(r#"/join 123 --secret "unterminated"#).unwrap_err();

        assert!(matches!(err, CommandParseError::TokenizationFailed { .. }));
    }
}
