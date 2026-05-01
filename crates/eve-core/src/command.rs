use thiserror::Error;

/// A typed representation of every user command supported by the v0.1 shell.
///
/// This enum is the boundary between "text typed by a human" and the rest of
/// the application. Every later subsystem should receive this enum, not raw
/// strings, so parsing bugs do not leak into storage, crypto or networking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserCommand {
    IdentityCreate { alias: String },
    Login { alias: String },
    Whoami,
    Connect { multiaddr: String },
    Peers,
    Join {
        room_id: String,
        secret: String,
        ephemeral: bool,
    },
    DirectMessage {
        peer_id: String,
        secret: String,
        ephemeral: bool,
    },
    CreateRoom {
        room_id: Option<String>,
        ephemeral: bool,
    },
    Invite {
        peer_id: String,
    },
    Invites,
    AcceptInvite {
        invite_id: String,
    },
    RejectInvite {
        invite_id: String,
    },
    RoomAddPeer { peer_id: String },
    RoomPeers,
    Rooms,
    Message { text: String },
    History { enabled: bool },
    Trust { action: TrustCommand },
    Policy { action: PolicyCommand },
    Status,
    Doctor,
    Debug { enabled: bool },
    Clear,
    Help,
    Quit,
}

/// Subcommands for the local trust store.
///
/// Trust is intentionally explicit. A peer becomes trusted only after the user
/// has seen its signing fingerprint and runs `/trust <peer_id>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustCommand {
    Add { peer_id: String },
    List,
    Remove { peer_id: String },
}

/// Subcommands for the local message policy.
///
/// The policy is intentionally local-first: messages are rejected before
/// encryption and before network transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyCommand {
    Show,
    Strict,
    Relaxed,
}

/// Human-readable parser errors.
///
/// The shell should print these directly. They are intentionally explicit:
/// secure CLI tools should fail loudly and explain the next correct action.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommandParseError {
    #[error("empty command")]
    Empty,

    #[error("commands must start with '/'")]
    MissingSlash,

    #[error("failed to parse shell-like input: {0}")]
    ShellWords(String),

    #[error("unknown command: {0}")]
    UnknownCommand(String),

    #[error("missing argument: {0}")]
    MissingArgument(&'static str),

    #[error("unexpected argument: {0}")]
    UnexpectedArgument(String),

    #[error("missing required flag {0}")]
    MissingFlag(&'static str),

    #[error("invalid value for {field}: {value}")]
    InvalidValue {
        field: &'static str,
        value: String,
    },
}

/// Parse a single interactive shell line into a typed command.
///
/// `/msg` is handled before shell tokenization because message text should be
/// allowed to contain spaces without requiring quotes.
pub fn parse_command(input: &str) -> Result<UserCommand, CommandParseError> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err(CommandParseError::Empty);
    }

    if !trimmed.starts_with('/') {
        return Err(CommandParseError::MissingSlash);
    }

    if trimmed == "/help" {
        return Ok(UserCommand::Help);
    }

    if trimmed == "/quit" || trimmed == "/exit" {
        return Ok(UserCommand::Quit);
    }

    // `/msg hello world` should preserve `hello world` as one text payload.
    if let Some(rest) = trimmed.strip_prefix("/msg") {
        let text = rest.trim();
        if text.is_empty() {
            return Err(CommandParseError::MissingArgument("text"));
        }
        return Ok(UserCommand::Message {
            text: text.to_string(),
        });
    }

    let tokens = shell_words::split(trimmed)
        .map_err(|err| CommandParseError::ShellWords(err.to_string()))?;

    parse_tokens(&tokens)
}

fn parse_tokens(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    let Some(command) = tokens.first() else {
        return Err(CommandParseError::Empty);
    };

    match command.as_str() {
        "/identity" => parse_identity(tokens),
        "/login" => parse_login(tokens),
        "/whoami" => expect_no_args(tokens, UserCommand::Whoami),
        "/connect" => parse_connect(tokens),
        "/peers" => expect_no_args(tokens, UserCommand::Peers),
        "/join" => parse_join(tokens),
        "/dm" => parse_dm(tokens),
        "/create-room" => parse_create_room(tokens),
        "/invite" => parse_invite(tokens),
        "/invites" => expect_no_args(tokens, UserCommand::Invites),
        "/accept-invite" => parse_accept_invite(tokens),
        "/reject-invite" => parse_reject_invite(tokens),
        "/room" => parse_room(tokens),
        "/rooms" => expect_no_args(tokens, UserCommand::Rooms),
        "/history" => parse_history(tokens),
        "/trust" => parse_trust(tokens),
        "/policy" => parse_policy(tokens),
        "/status" => expect_no_args(tokens, UserCommand::Status),
        "/doctor" => expect_no_args(tokens, UserCommand::Doctor),
        "/debug" => parse_debug(tokens),
        "/clear" => expect_no_args(tokens, UserCommand::Clear),
        "/help" => expect_no_args(tokens, UserCommand::Help),
        "/quit" | "/exit" => expect_no_args(tokens, UserCommand::Quit),
        other => Err(CommandParseError::UnknownCommand(other.to_string())),
    }
}

fn expect_no_args(
    tokens: &[String],
    command: UserCommand,
) -> Result<UserCommand, CommandParseError> {
    if tokens.len() == 1 {
        Ok(command)
    } else {
        Err(CommandParseError::UnexpectedArgument(tokens[1].clone()))
    }
}

fn parse_identity(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    match tokens {
        [_, subcommand, alias] if subcommand == "create" => Ok(UserCommand::IdentityCreate {
            alias: alias.clone(),
        }),
        [_, subcommand, _, extra, ..] if subcommand == "create" => {
            Err(CommandParseError::UnexpectedArgument(extra.clone()))
        }
        [_, subcommand, ..] => Err(CommandParseError::InvalidValue {
            field: "identity subcommand",
            value: subcommand.clone(),
        }),
        [_] => Err(CommandParseError::MissingArgument("create <alias>")),
        [] => Err(CommandParseError::Empty),
    }
}

fn parse_login(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    match tokens {
        [_, alias] => Ok(UserCommand::Login {
            alias: alias.clone(),
        }),
        [_] => Err(CommandParseError::MissingArgument("alias")),
        [_, _, extra, ..] => Err(CommandParseError::UnexpectedArgument(extra.clone())),
        [] => Err(CommandParseError::Empty),
    }
}

fn parse_connect(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    match tokens {
        [_, multiaddr] => Ok(UserCommand::Connect {
            multiaddr: multiaddr.clone(),
        }),
        [_] => Err(CommandParseError::MissingArgument("multiaddr")),
        [_, _, extra, ..] => Err(CommandParseError::UnexpectedArgument(extra.clone())),
        [] => Err(CommandParseError::Empty),
    }
}

fn parse_join(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    if tokens.len() < 2 {
        return Err(CommandParseError::MissingArgument("room_id"));
    }

    let room_id = tokens[1].clone();
    let mut secret: Option<String> = None;
    let mut ephemeral = false;

    let mut i = 2;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "--secret" => {
                let Some(value) = tokens.get(i + 1) else {
                    return Err(CommandParseError::MissingArgument("secret value"));
                };
                secret = Some(value.clone());
                i += 2;
            }
            "--ephemeral" => {
                ephemeral = true;
                i += 1;
            }
            other => return Err(CommandParseError::UnexpectedArgument(other.to_string())),
        }
    }

    let Some(secret) = secret else {
        return Err(CommandParseError::MissingFlag("--secret"));
    };

    Ok(UserCommand::Join {
        room_id,
        secret,
        ephemeral,
    })
}

fn parse_dm(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    if tokens.len() < 2 {
        return Err(CommandParseError::MissingArgument("peer_id"));
    }

    let peer_id = tokens[1].clone();
    let mut secret: Option<String> = None;
    let mut ephemeral = false;

    let mut i = 2;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "--secret" => {
                let Some(value) = tokens.get(i + 1) else {
                    return Err(CommandParseError::MissingArgument("secret value"));
                };
                secret = Some(value.clone());
                i += 2;
            }
            "--ephemeral" => {
                ephemeral = true;
                i += 1;
            }
            other => return Err(CommandParseError::UnexpectedArgument(other.to_string())),
        }
    }

    let Some(secret) = secret else {
        return Err(CommandParseError::MissingFlag("--secret"));
    };

    Ok(UserCommand::DirectMessage {
        peer_id,
        secret,
        ephemeral,
    })
}


fn parse_create_room(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    let mut room_id: Option<String> = None;
    let mut ephemeral = false;

    let mut i = 1;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "--ephemeral" => {
                ephemeral = true;
                i += 1;
            }
            value if !value.starts_with("--") && room_id.is_none() => {
                room_id = Some(value.to_string());
                i += 1;
            }
            other => return Err(CommandParseError::UnexpectedArgument(other.to_string())),
        }
    }

    Ok(UserCommand::CreateRoom { room_id, ephemeral })
}

fn parse_invite(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    match tokens {
        [_, peer_id] => Ok(UserCommand::Invite {
            peer_id: peer_id.clone(),
        }),
        [_] => Err(CommandParseError::MissingArgument("peer_id")),
        [_, _, extra, ..] => Err(CommandParseError::UnexpectedArgument(extra.clone())),
        [] => Err(CommandParseError::Empty),
    }
}

fn parse_accept_invite(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    match tokens {
        [_, invite_id] => Ok(UserCommand::AcceptInvite {
            invite_id: invite_id.clone(),
        }),
        [_] => Err(CommandParseError::MissingArgument("invite_id")),
        [_, _, extra, ..] => Err(CommandParseError::UnexpectedArgument(extra.clone())),
        [] => Err(CommandParseError::Empty),
    }
}

fn parse_reject_invite(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    match tokens {
        [_, invite_id] => Ok(UserCommand::RejectInvite {
            invite_id: invite_id.clone(),
        }),
        [_] => Err(CommandParseError::MissingArgument("invite_id")),
        [_, _, extra, ..] => Err(CommandParseError::UnexpectedArgument(extra.clone())),
        [] => Err(CommandParseError::Empty),
    }
}

fn parse_room(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    match tokens {
        [_, subcommand, peer_id] if subcommand == "add-peer" => Ok(UserCommand::RoomAddPeer {
            peer_id: peer_id.clone(),
        }),
        [_, subcommand, _, extra, ..] if subcommand == "add-peer" => {
            Err(CommandParseError::UnexpectedArgument(extra.clone()))
        }
        [_, subcommand] if subcommand == "peers" => Ok(UserCommand::RoomPeers),
        [_, subcommand, extra, ..] if subcommand == "peers" => {
            Err(CommandParseError::UnexpectedArgument(extra.clone()))
        }
        [_, subcommand, ..] => Err(CommandParseError::InvalidValue {
            field: "room subcommand",
            value: subcommand.clone(),
        }),
        [_] => Err(CommandParseError::MissingArgument("room subcommand")),
        [] => Err(CommandParseError::Empty),
    }
}

fn parse_history(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    match tokens {
        [_, value] if value == "on" => Ok(UserCommand::History { enabled: true }),
        [_, value] if value == "off" => Ok(UserCommand::History { enabled: false }),
        [_, value] => Err(CommandParseError::InvalidValue {
            field: "history",
            value: value.clone(),
        }),
        [_, _, extra, ..] => Err(CommandParseError::UnexpectedArgument(extra.clone())),
        [_] => Err(CommandParseError::MissingArgument("on|off")),
        [] => Err(CommandParseError::Empty),
    }
}

fn parse_trust(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    match tokens {
        [_, value] if value == "list" => Ok(UserCommand::Trust {
            action: TrustCommand::List,
        }),
        [_, value, extra, ..] if value == "list" => {
            Err(CommandParseError::UnexpectedArgument(extra.clone()))
        }
        [_, value, peer_id] if value == "remove" => Ok(UserCommand::Trust {
            action: TrustCommand::Remove {
                peer_id: peer_id.clone(),
            },
        }),
        [_, value, _, extra, ..] if value == "remove" => {
            Err(CommandParseError::UnexpectedArgument(extra.clone()))
        }
        [_, value] if value == "remove" => Err(CommandParseError::MissingArgument("peer_id")),
        [_, peer_id] => Ok(UserCommand::Trust {
            action: TrustCommand::Add {
                peer_id: peer_id.clone(),
            },
        }),
        [_, peer_id, extra, ..] => Err(CommandParseError::UnexpectedArgument(extra.clone())),
        [_] => Err(CommandParseError::MissingArgument("peer_id|list|remove <peer_id>")),
        [] => Err(CommandParseError::Empty),
    }
}



fn parse_debug(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    match tokens {
        [_, value] if value == "on" => Ok(UserCommand::Debug { enabled: true }),
        [_, value] if value == "off" => Ok(UserCommand::Debug { enabled: false }),
        [_, value] => Err(CommandParseError::InvalidValue {
            field: "debug",
            value: value.clone(),
        }),
        [_, _, extra, ..] => Err(CommandParseError::UnexpectedArgument(extra.clone())),
        [_] => Err(CommandParseError::MissingArgument("on|off")),
        [] => Err(CommandParseError::Empty),
    }
}

fn parse_policy(tokens: &[String]) -> Result<UserCommand, CommandParseError> {
    match tokens {
        [_] => Ok(UserCommand::Policy {
            action: PolicyCommand::Show,
        }),
        [_, value] if value == "strict" => Ok(UserCommand::Policy {
            action: PolicyCommand::Strict,
        }),
        [_, value] if value == "relaxed" => Ok(UserCommand::Policy {
            action: PolicyCommand::Relaxed,
        }),
        [_, value] => Err(CommandParseError::InvalidValue {
            field: "policy",
            value: value.clone(),
        }),
        [_, _, extra, ..] => Err(CommandParseError::UnexpectedArgument(extra.clone())),
        [] => Err(CommandParseError::Empty),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_identity_create() {
        assert_eq!(
            parse_command("/identity create Alice").unwrap(),
            UserCommand::IdentityCreate {
                alias: "Alice".to_string()
            }
        );
    }

    #[test]
    fn parses_join_with_quoted_secret_and_ephemeral_flag() {
        assert_eq!(
            parse_command(r#"/join 123 --secret "red wheelbarrow" --ephemeral"#).unwrap(),
            UserCommand::Join {
                room_id: "123".to_string(),
                secret: "red wheelbarrow".to_string(),
                ephemeral: true,
            }
        );
    }

    #[test]
    fn parses_msg_as_free_text() {
        assert_eq!(
            parse_command("/msg hello world from terminal").unwrap(),
            UserCommand::Message {
                text: "hello world from terminal".to_string(),
            }
        );
    }

    #[test]
    fn rejects_missing_slash() {
        assert_eq!(
            parse_command("EVE_os-1112").unwrap_err(),
            CommandParseError::MissingSlash
        );
    }

    #[test]
    fn rejects_join_without_secret() {
        assert_eq!(
            parse_command("/join 123").unwrap_err(),
            CommandParseError::MissingFlag("--secret")
        );
    }

    #[test]
    fn rejects_history_extra_args() {
        assert_eq!(
            parse_command("/history on now").unwrap_err(),
            CommandParseError::UnexpectedArgument("now".to_string())
        );
    }

    #[test]
    fn parses_status() {
        assert_eq!(parse_command("/status").unwrap(), UserCommand::Status);
    }

    #[test]
    fn parses_clear() {
        assert_eq!(parse_command("/clear").unwrap(), UserCommand::Clear);
    }

    #[test]
    fn parses_trust_add() {
        assert_eq!(
            parse_command("/trust 12D3KooWPeer").unwrap(),
            UserCommand::Trust {
                action: TrustCommand::Add {
                    peer_id: "12D3KooWPeer".to_string(),
                }
            }
        );
    }

    #[test]
    fn parses_trust_list() {
        assert_eq!(
            parse_command("/trust list").unwrap(),
            UserCommand::Trust {
                action: TrustCommand::List,
            }
        );
    }

    #[test]
    fn parses_trust_remove() {
        assert_eq!(
            parse_command("/trust remove 12D3KooWPeer").unwrap(),
            UserCommand::Trust {
                action: TrustCommand::Remove {
                    peer_id: "12D3KooWPeer".to_string(),
                }
            }
        );
    }


    #[test]
    fn parses_dm_with_secret_and_ephemeral_flag() {
        assert_eq!(
            parse_command(r#"/dm 12D3KooWPeer --secret "red wheelbarrow" --ephemeral"#).unwrap(),
            UserCommand::DirectMessage {
                peer_id: "12D3KooWPeer".to_string(),
                secret: "red wheelbarrow".to_string(),
                ephemeral: true,
            }
        );
    }

    #[test]
    fn rejects_room_extra_args() {
        assert_eq!(
            parse_command("/room peers extra").unwrap_err(),
            CommandParseError::UnexpectedArgument("extra".to_string())
        );
    }


    #[test]
    fn parses_policy_show() {
        assert_eq!(
            parse_command("/policy").unwrap(),
            UserCommand::Policy {
                action: PolicyCommand::Show,
            }
        );
    }

    #[test]
    fn parses_policy_strict() {
        assert_eq!(
            parse_command("/policy strict").unwrap(),
            UserCommand::Policy {
                action: PolicyCommand::Strict,
            }
        );
    }

    #[test]
    fn parses_policy_relaxed() {
        assert_eq!(
            parse_command("/policy relaxed").unwrap(),
            UserCommand::Policy {
                action: PolicyCommand::Relaxed,
            }
        );
    }


}
