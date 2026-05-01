use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event as CrosstermEvent, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use eve_core::{parse_command, PolicyCommand, TrustCommand, UserCommand};
use eve_crypto::{
    decrypt_room_message, derive_room_key, encrypt_room_message, fingerprint_from_public_key,
    generate_message_id, generate_random_room_key, room_key_fingerprint, sign_bytes,
    verify_signature,
};
use eve_p2p::{P2pEvent, P2pHandle};
use eve_protocol::{PlainMessage, RoomInvite, SignedEncryptedEnvelope};
use eve_storage::{IdentityStore, TrustedPeerRecord, UnlockedIdentity};
use libp2p::{Multiaddr, PeerId};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};
use rustyline::{error::ReadlineError, DefaultEditor};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{self, Write},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

/// Default v0.1 LAN listen address.
///
/// Can be overridden at process startup with:
///
/// `dogel.bin --listen /ip4/0.0.0.0/tcp/7778`
const DEFAULT_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/7777";

/// Runtime state owned by the interactive process.
///
/// This is intentionally still small. The P2P swarm lives in `eve-p2p`, while
/// room keys and membership live here because they are application security
/// state, not transport state.
struct AppState {
    active_identity: Option<UnlockedIdentity>,
    p2p: Option<P2pHandle>,
    listen_addr: Multiaddr,
    rooms: SharedRoomBook,
    invites: SharedInviteBook,
    trust: SharedTrustBook,
    message_policy: MessagePolicy,
    debug_enabled: bool,
    session_lock_alias: Option<String>,
}

type SharedRoomBook = Arc<Mutex<RoomBook>>;
type SharedInviteBook = Arc<Mutex<InviteBook>>;
type SharedTrustBook = Arc<Mutex<TrustBook>>;

/// Runtime trust/observation state shared between the command loop and inbound
/// P2P event task.
///
/// `observed` is intentionally memory-only. It stores the latest signing key
/// seen in a valid signed envelope. `/trust <peer_id>` then pins that key to
/// disk after the user decides the fingerprint is acceptable.
#[derive(Debug, Default)]
struct TrustBook {
    identity_alias: Option<String>,
    observed: HashMap<String, ObservedPeer>,
}

/// Last signing identity observed for a remote peer during the current process.
#[derive(Debug, Clone)]
struct ObservedPeer {
    peer_id: String,
    alias: String,
    signing_public_key_b64: String,
    fingerprint: String,
    last_seen_at_ms: u64,
}

/// Trust status assigned to an inbound message after signature verification.
#[derive(Debug, Clone)]
enum InboundTrustStatus {
    Trusted,
    Untrusted,
    KeyChanged {
        old_fingerprint: String,
        new_fingerprint: String,
    },

}

/// Message policy enforced locally before encryption and network transmission.
///
/// This is intentionally not part of the wire protocol. A modified client can
/// bypass it, but the official `dogel.bin` client should make unsafe behavior
/// inconvenient by default.
#[derive(Debug, Clone)]
struct MessagePolicy {
    mode: PolicyMode,
    max_chars: usize,
    reject_multiline: bool,
    reject_control_chars: bool,
    reject_links: bool,
    max_messages_per_window: usize,
    window: Duration,
    sent_timestamps_ms: VecDeque<u64>,
}

/// Human-readable policy mode.
///
/// `Relaxed` is still not an unrestricted mode. Links, multiline content and
/// control characters remain rejected because dogel.bin is not a paste/file
/// transfer tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyMode {
    Strict,
    Relaxed,
}

impl MessagePolicy {
    fn strict() -> Self {
        Self {
            mode: PolicyMode::Strict,
            max_chars: 512,
            reject_multiline: true,
            reject_control_chars: true,
            reject_links: true,
            max_messages_per_window: 8,
            window: Duration::from_secs(10),
            sent_timestamps_ms: VecDeque::new(),
        }
    }

    fn relaxed() -> Self {
        Self {
            mode: PolicyMode::Relaxed,
            max_chars: 1024,
            reject_multiline: true,
            reject_control_chars: true,
            reject_links: true,
            max_messages_per_window: 16,
            window: Duration::from_secs(10),
            sent_timestamps_ms: VecDeque::new(),
        }
    }

    fn mode_name(&self) -> &'static str {
        match self.mode {
            PolicyMode::Strict => "strict",
            PolicyMode::Relaxed => "relaxed",
        }
    }
}


/// Mutable room state shared between the command loop and the inbound P2P event
/// task.
///
/// The event task needs read access to room keys so it can decrypt inbound
/// envelopes while the user is sitting at the blocking `rustyline` prompt.
#[derive(Debug, Default)]
struct RoomBook {
    rooms: HashMap<String, RoomSession>,
    active_room: Option<String>,
}

/// Local room session.
///
/// `members` is local routing metadata in v0.1. It controls who this client
/// sends messages to. It is not cryptographic membership and does not revoke
/// anyone who already knows the room secret.
#[derive(Debug, Clone)]
struct RoomSession {
    room_id: String,
    room_key: [u8; 32],
    key_fingerprint: String,
    ephemeral: bool,
    history_enabled: bool,
    members: HashSet<PeerId>,

    /// In-memory replay cache for this room.
    ///
    /// Each entry is `sender_peer_id:message_id`. This is intentionally
    /// memory-only for v0.1 because durable history is not implemented yet.
    /// Ephemeral rooms still benefit from rejecting repeated envelopes during a
    /// live session.
    seen_message_ids: HashSet<String>,
}


/// Pending online invites received during this process.
///
/// Phase 10 invites are online-only. They are intentionally memory-only because
/// offline durable invites require a stronger application-level encryption
/// format and persistence model.
#[derive(Debug, Default)]
struct InviteBook {
    pending: HashMap<String, PendingInvite>,
}

/// Invite waiting for user acceptance.
///
/// `room_key` is already decoded and kept only in memory. If the client exits,
/// the invite disappears. That matches the current ephemeral-first security
/// posture and avoids writing room keys to disk.
#[derive(Debug, Clone)]
struct PendingInvite {
    invite_id: String,
    room_id: String,
    room_key: [u8; 32],
    key_fingerprint: String,
    ephemeral: bool,
    sender_alias: String,
    sender_peer_id: PeerId,
    sender_fingerprint: String,
    received_at_ms: u64,
}

impl AppState {
    fn new(listen_addr: Multiaddr) -> Self {
        Self {
            active_identity: None,
            p2p: None,
            listen_addr,
            rooms: Arc::new(Mutex::new(RoomBook::default())),
            invites: Arc::new(Mutex::new(InviteBook::default())),
            trust: Arc::new(Mutex::new(TrustBook::default())),
            message_policy: MessagePolicy::strict(),
            debug_enabled: false,
            session_lock_alias: None,
        }
    }
}

/// Build the interactive prompt from current identity and room state.
///
/// Phase 6 intentionally keeps this prompt simple and stable:
///
/// - before login: `dogel>`
/// - after login: `dogel:<alias>>`
/// - inside persistent room: `dogel:<alias>[123]>`
/// - inside ephemeral room: `dogel:<alias>[123*]>`
///
/// The `*` marker is deliberately compact: it makes ephemeral state visible
/// without stealing horizontal space from chat messages.
async fn build_prompt(state: &AppState) -> String {
    let alias = state
        .active_identity
        .as_ref()
        .map(|identity| identity.alias.as_str());

    let active_room = {
        let rooms = state.rooms.lock().await;

        rooms
            .active_room
            .as_ref()
            .and_then(|room_id| rooms.rooms.get(room_id))
            .map(|room| {
                let suffix = if room.ephemeral { "*" } else { "" };
                format!("{}{}", room.room_id, suffix)
            })
    };

    match (alias, active_room) {
        (Some(alias), Some(room)) => format!("dogel:{alias}[{room}]> "),
        (Some(alias), None) => format!("dogel:{alias}> "),
        (None, Some(room)) => format!("dogel[{room}]> "),
        (None, None) => "dogel> ".to_string(),
    }
}

#[derive(Debug, Clone)]
struct StartupConfig {
    listen_addr: Multiaddr,
    tui: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = parse_startup_config()?;
    let store = IdentityStore::default().context("failed to initialize local identity store")?;
    let mut state = AppState::new(config.listen_addr.clone());

    if config.tui {
        run_tui_loop(&store, &mut state).await?;
    } else {
        run_shell_loop(&store, &mut state).await?;
    }

    release_session_lock_if_needed(&store, &mut state);
    Ok(())
}

/// Classic line-oriented shell mode.
///
/// This remains the primary debugging mode. Phase 11 adds TUI as an additional
/// frontend, not as a replacement for the stable shell.
async fn run_shell_loop(store: &IdentityStore, state: &mut AppState) -> Result<()> {
    println!("dogel.bin v0.1 phase 11");
    println!("interactive shell + encrypted P2P messages + trust + online invites");
    println!("config root: {}", store.root().display());
    println!("listen: {}", state.listen_addr);
    println!("type /help for commands, /quit to exit");
    println!();

    let mut rl = DefaultEditor::new().context("failed to initialize line editor")?;

    loop {
        let prompt = build_prompt(state).await;

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                if !line.starts_with('/') {
                    if let Err(err) = send_room_message(line, state).await {
                        println!("error: {err}");
                    }
                    continue;
                }

                match parse_command(line) {
                    Ok(UserCommand::Quit) => {
                        println!("bye");
                        break;
                    }
                    Ok(command) => {
                        if !matches!(&command, UserCommand::Message { .. }) {
                            let _ = rl.add_history_entry(line);
                        }

                        if let Err(err) = handle_command(command, store, state).await {
                            println!("error: {err}");
                        }
                    }
                    Err(err) => {
                        let _ = rl.add_history_entry(line);
                        print_parse_error(&err);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                println!("use /quit to exit");
            }
            Err(ReadlineError::Eof) => {
                println!("bye");
                break;
            }
            Err(err) => {
                println!("error: failed to read line: {err}");
                break;
            }
        }
    }

    Ok(())
}

/// Minimal TUI frontend.
///
/// This is deliberately conservative: it reuses the same command parser and
/// command handlers as shell mode. It does not yet have a full output-router
/// abstraction, so some low-level network diagnostics can still be printed by
/// background tasks. That is acceptable for Phase 11; the important part is
/// establishing a working alternate-screen UI without touching crypto or P2P.
async fn run_tui_loop(store: &IdentityStore, state: &mut AppState) -> Result<()> {
    enable_raw_mode().context("failed to enable raw mode")?;

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to initialize terminal")?;

    let result = run_tui_loop_inner(store, state, &mut terminal).await;

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    result
}

async fn run_tui_loop_inner(
    store: &IdentityStore,
    state: &mut AppState,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    let mut input = String::new();
    let mut log: VecDeque<String> = VecDeque::new();

    log.push_back("dogel.bin v0.1 phase 11 minimal TUI".to_string());
    log.push_back("type /help, /doctor, /quit; ordinary text sends to active room".to_string());
    log.push_back("links, multiline paste and bursts remain blocked by local policy".to_string());

    loop {
        let prompt = build_prompt(state).await;
        let title = build_tui_title(state).await;

        terminal
            .draw(|frame| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(3),
                        Constraint::Length(3),
                    ])
                    .split(frame.size());

                let header = Paragraph::new(title.clone())
                    .block(Block::default().title(" dogel.bin ").borders(Borders::ALL))
                    .wrap(Wrap { trim: true });
                frame.render_widget(header, chunks[0]);

                let lines = log
                    .iter()
                    .rev()
                    .take(chunks[1].height.saturating_sub(2) as usize)
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n");

                let messages = Paragraph::new(lines)
                    .block(Block::default().title(" session ").borders(Borders::ALL))
                    .wrap(Wrap { trim: false });
                frame.render_widget(messages, chunks[1]);

                let input_line = format!("{prompt}{input}");
                let input_widget = Paragraph::new(input_line)
                    .block(Block::default().title(" input ").borders(Borders::ALL))
                    .wrap(Wrap { trim: false });
                frame.render_widget(input_widget, chunks[2]);
            })
            .context("failed to draw TUI frame")?;

        if !event::poll(Duration::from_millis(80)).context("failed to poll terminal events")? {
            continue;
        }

        let CrosstermEvent::Key(key) = event::read().context("failed to read terminal event")?
        else {
            continue;
        };

        if key.kind != KeyEventKind::Press {
            continue;
        }

        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                log.push_back("^C ignored; use /quit".to_string());
            }
            KeyCode::Esc => {
                log.push_back("ESC ignored; use /quit".to_string());
            }
            KeyCode::Backspace => {
                input.pop();
            }
            KeyCode::Enter => {
                let line = input.trim().to_string();
                input.clear();

                if line.is_empty() {
                    continue;
                }

                push_tui_log(&mut log, format!("> {line}"));

                if !line.starts_with('/') {
                    match send_room_message(&line, state).await {
                        Ok(()) => push_tui_log(&mut log, "message submitted".to_string()),
                        Err(err) => push_tui_log(&mut log, format!("error: {err}")),
                    }
                    continue;
                }

                match parse_command(&line) {
                    Ok(UserCommand::Quit) => {
                        push_tui_log(&mut log, "bye".to_string());
                        break;
                    }
                    Ok(UserCommand::Clear) => {
                        log.clear();
                    }
                    Ok(UserCommand::Doctor) => {
                        let report = build_doctor_report(state, store).await?;
                        for line in report {
                            push_tui_log(&mut log, line);
                        }
                    }
                    Ok(command) => match handle_command(command, store, state).await {
                        Ok(()) => push_tui_log(&mut log, "ok".to_string()),
                        Err(err) => push_tui_log(&mut log, format!("error: {err}")),
                    },
                    Err(err) => push_tui_log(&mut log, format!("parse error: {err}")),
                }
            }
            KeyCode::Char(ch) => {
                // Phase 8 policy forbids multiline and bulk paste. TUI input is
                // single-line only by construction; we additionally avoid
                // accepting control-modified characters as text.
                if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT {
                    input.push(ch);
                }
            }
            _ => {}
        }
    }

    Ok(())
}

fn push_tui_log(log: &mut VecDeque<String>, line: String) {
    log.push_back(line);
    while log.len() > 500 {
        log.pop_front();
    }
}

async fn build_tui_title(state: &AppState) -> String {
    let alias = state
        .active_identity
        .as_ref()
        .map(|identity| identity.alias.as_str())
        .unwrap_or("no-identity");

    let room = {
        let rooms = state.rooms.lock().await;
        rooms
            .active_room
            .as_ref()
            .and_then(|room_id| rooms.rooms.get(room_id))
            .map(|room| {
                if room.ephemeral {
                    format!("{}*", room.room_id)
                } else {
                    room.room_id.clone()
                }
            })
            .unwrap_or_else(|| "no-room".to_string())
    };

    let peer_count = match state.p2p.as_ref() {
        Some(p2p) => p2p.connected_peers().await.map(|peers| peers.len()).unwrap_or(0),
        None => 0,
    };

    let trust_count = {
        let trust = state.trust.lock().await;
        trust.observed.len()
    };

    format!(
        "identity: {alias} | room: {room} | peers: {peer_count} | trust: {trust_count} | policy: {} | debug: {}",
        state.message_policy.mode_name(),
        if state.debug_enabled { "on" } else { "off" }
    )
}

fn release_session_lock_if_needed(store: &IdentityStore, state: &mut AppState) {
    if let Some(alias) = state.session_lock_alias.take() {
        if let Err(err) = store.release_identity_lock(&alias) {
            eprintln!("warning: failed to release identity session lock for {alias}: {err}");
        }
    }
}

async fn handle_command(
    command: UserCommand,
    store: &IdentityStore,
    state: &mut AppState,
) -> Result<()> {
    match command {
        UserCommand::IdentityCreate { alias } => {
            let password = prompt_new_password()?;

            let created = store
                .create_identity(&alias, &password)
                .with_context(|| format!("failed to create identity '{alias}'"))?;

            println!("created identity:");
            println!("  alias: {}", created.alias);
            println!("  peer_id: {}", created.peer_id);
            println!("  fingerprint: {}", created.fingerprint);
            println!("  path: {}", created.identity_dir.display());
        }

        UserCommand::Login { alias } => {
            if state.active_identity.is_some() {
                anyhow::bail!("an identity is already unlocked in this process");
            }

            let password = rpassword::prompt_password("Password: ")
                .context("failed to read password")?;

            let unlocked = store
                .unlock_identity(&alias, &password)
                .with_context(|| format!("failed to unlock identity '{alias}'"))?;

            // Phase 9 hardening: prevent accidental duplicate use of the same
            // libp2p identity in two local dogel.bin processes. Two live
            // processes with the same PeerId produce confusing handshakes and
            // weaken the operational security model.
            store
                .acquire_identity_lock(&unlocked.alias)
                .with_context(|| format!("failed to acquire session lock for identity '{}'", unlocked.alias))?;

            println!("unlocked identity:");
            println!("  alias: {}", unlocked.alias);
            println!("  peer_id: {}", unlocked.peer_id);
            println!("  fingerprint: {}", unlocked.fingerprint);

            // Start libp2p only after successful identity unlock. This is
            // important: the network PeerId must be derived from the encrypted
            // identity, not generated freshly every process start.
            let start_result =
                P2pHandle::start(unlocked.network_keypair.clone(), state.listen_addr.clone())
                    .await;

            let (p2p, p2p_events) = match start_result {
                Ok(value) => value,
                Err(err) => {
                    let _ = store.release_identity_lock(&unlocked.alias);
                    return Err(err).context("failed to start libp2p runtime");
                }
            };

            {
                let mut trust = state.trust.lock().await;
                trust.identity_alias = Some(unlocked.alias.clone());
                trust.observed.clear();
            }

            spawn_p2p_event_task(
                p2p_events,
                Arc::clone(&state.rooms),
                Arc::clone(&state.invites),
                Arc::clone(&state.trust),
                store.clone(),
            );

            println!("p2p runtime started:");
            println!("  local_peer_id: {}", p2p.local_peer_id());
            println!("  listen: {}", state.listen_addr);
            println!("  use /whoami after [p2p] listening appears to copy full multiaddr");

            state.session_lock_alias = Some(unlocked.alias.clone());
            state.p2p = Some(p2p);
            state.active_identity = Some(unlocked);
        }

        UserCommand::Whoami => {
            let Some(identity) = state.active_identity.as_ref() else {
                println!("error: no active identity");
                println!();
                println!("hint:");
                println!("  /login <alias>");
                return Ok(());
            };

            println!("alias: {}", identity.alias);
            println!("peer_id: {}", identity.peer_id);
            println!("fingerprint: {}", identity.fingerprint);
            println!("listen:");

            if let Some(p2p) = state.p2p.as_ref() {
                let addrs = p2p.listen_addrs().await?;
                if addrs.is_empty() {
                    println!("  swarm started, but no listen address is confirmed yet");
                } else {
                    for addr in addrs {
                        println!(
                            "  {}",
                            addr.with(libp2p::multiaddr::Protocol::P2p(p2p.local_peer_id()))
                        );
                    }
                }
            } else {
                println!("  p2p runtime is not started");
            }
        }

        UserCommand::Connect { multiaddr } => {
            let Some(p2p) = state.p2p.as_ref() else {
                println!("error: p2p runtime is not started");
                println!();
                println!("hint:");
                println!("  /login <alias>");
                return Ok(());
            };

            let addr: Multiaddr = multiaddr
                .parse()
                .with_context(|| format!("invalid multiaddr: {multiaddr}"))?;

            p2p.dial(addr.clone()).await?;
            println!("dial started:");
            println!("  {addr}");
            println!("connection result will appear as [p2p] event");
        }

        UserCommand::Peers => {
            let Some(p2p) = state.p2p.as_ref() else {
                println!("error: p2p runtime is not started");
                println!();
                println!("hint:");
                println!("  /login <alias>");
                return Ok(());
            };

            let peers = p2p.connected_peers().await?;
            if peers.is_empty() {
                println!("connected peers:");
                println!("  none");
            } else {
                println!("connected peers:");
                for peer in peers {
                    println!("  {peer}");
                }
            }
        }

        UserCommand::Join {
            room_id,
            secret,
            ephemeral,
        } => {
            let Some(p2p) = state.p2p.as_ref() else {
                println!("error: p2p runtime is not started");
                println!();
                println!("hint:");
                println!("  /login <alias>");
                return Ok(());
            };

            validate_room_id(&room_id)?;
            let room_key = derive_room_key(&room_id, &secret)
                .context("failed to derive Argon2id room key")?;
            let key_fingerprint = room_key_fingerprint(&room_key);
            let self_peer_id = p2p.local_peer_id();

            let mut rooms = state.rooms.lock().await;

            if let Some(existing) = rooms.rooms.get_mut(&room_id) {
                if existing.room_key != room_key {
                    anyhow::bail!(
                        "room {room_id} already exists with a different key; leave/recreate is not supported in v0.1"
                    );
                }

                // We need to read display data while the room entry is mutably
                // borrowed, then release that borrow before mutating
                // `rooms.active_room`. Rust correctly rejects holding two
                // overlapping mutable borrows into the same `rooms` object.
                existing.members.insert(self_peer_id);
                let existing_ephemeral = existing.ephemeral;
                let existing_history_enabled = existing.history_enabled;
                let existing_key_fingerprint = existing.key_fingerprint.clone();

                rooms.active_room = Some(room_id.clone());

                println!("active room: {room_id}");
                println!("ephemeral: {}", existing_ephemeral);
                println!("history: {}", existing_history_enabled);
                println!("room key fingerprint: {}", existing_key_fingerprint);
                return Ok(());
            }

            let mut members = HashSet::new();
            members.insert(self_peer_id);

            let session = RoomSession {
                room_id: room_id.clone(),
                room_key,
                key_fingerprint: key_fingerprint.clone(),
                ephemeral,
                history_enabled: false,
                members,
                seen_message_ids: HashSet::new(),
            };

            rooms.rooms.insert(room_id.clone(), session);
            rooms.active_room = Some(room_id.clone());

            println!("joined room: {room_id}");
            println!("active room: {room_id}");
            println!("ephemeral: {ephemeral}");
            println!("history: false");
            println!("room key fingerprint: {key_fingerprint}");
        }

        UserCommand::DirectMessage {
            peer_id,
            secret,
            ephemeral,
        } => {
            let Some(p2p) = state.p2p.as_ref() else {
                println!("error: p2p runtime is not started");
                println!();
                println!("hint:");
                println!("  /login <alias>");
                return Ok(());
            };

            let remote_peer: PeerId = peer_id
                .parse()
                .with_context(|| format!("invalid peer id: {peer_id}"))?;

            let self_peer = p2p.local_peer_id();
            if remote_peer == self_peer {
                anyhow::bail!("cannot create a direct room with self");
            }

            let connected = p2p.connected_peers().await?;
            if !connected.contains(&remote_peer) {
                println!("error: peer is not connected");
                println!();
                println!("hint:");
                println!("  use /connect <multiaddr> first");
                return Ok(());
            }

            let room_id = deterministic_dm_room_id(self_peer, remote_peer);
            let room_key = derive_room_key(&room_id, &secret)
                .context("failed to derive Argon2id room key")?;
            let key_fingerprint = room_key_fingerprint(&room_key);

            let mut rooms = state.rooms.lock().await;

            if rooms.rooms.contains_key(&room_id) {
                let (existing_ephemeral, existing_history_enabled, existing_key_fingerprint, member_count) = {
                    let existing = rooms
                        .rooms
                        .get_mut(&room_id)
                        .expect("room exists because contains_key returned true");

                    if existing.room_key != room_key {
                        anyhow::bail!(
                            "direct room {room_id} already exists with a different key; use the same --secret on both peers"
                        );
                    }

                    existing.members.insert(self_peer);
                    existing.members.insert(remote_peer);

                    (
                        existing.ephemeral,
                        existing.history_enabled,
                        existing.key_fingerprint.clone(),
                        existing.members.len(),
                    )
                };

                rooms.active_room = Some(room_id.clone());

                println!("direct room active: {room_id}");
                println!("peer: {remote_peer}");
                println!("ephemeral: {}", existing_ephemeral);
                println!("history: {}", existing_history_enabled);
                println!("members: {}", member_count);
                println!("room key fingerprint: {}", existing_key_fingerprint);
                return Ok(());
            }

            let mut members = HashSet::new();
            members.insert(self_peer);
            members.insert(remote_peer);

            let session = RoomSession {
                room_id: room_id.clone(),
                room_key,
                key_fingerprint: key_fingerprint.clone(),
                ephemeral,
                history_enabled: false,
                members,
                seen_message_ids: HashSet::new(),
            };

            rooms.rooms.insert(room_id.clone(), session);
            rooms.active_room = Some(room_id.clone());

            println!("direct room ready: {room_id}");
            println!("peer: {remote_peer}");
            println!("active room: {room_id}");
            println!("ephemeral: {ephemeral}");
            println!("history: false");
            println!("members: 2");
            println!("room key fingerprint: {key_fingerprint}");
        }


        UserCommand::CreateRoom { room_id, ephemeral } => {
            let Some(p2p) = state.p2p.as_ref() else {
                println!("error: p2p runtime is not started");
                println!();
                println!("hint:");
                println!("  /login <alias>");
                return Ok(());
            };

            let room_id = room_id.unwrap_or_else(generate_invite_room_id);
            validate_room_id(&room_id)?;

            let room_key = generate_random_room_key();
            let key_fingerprint = room_key_fingerprint(&room_key);
            let self_peer = p2p.local_peer_id();

            let mut members = HashSet::new();
            members.insert(self_peer);

            let mut rooms = state.rooms.lock().await;
            if rooms.rooms.contains_key(&room_id) {
                anyhow::bail!("room {room_id} already exists");
            }

            let session = RoomSession {
                room_id: room_id.clone(),
                room_key,
                key_fingerprint: key_fingerprint.clone(),
                ephemeral,
                history_enabled: false,
                members,
                seen_message_ids: HashSet::new(),
            };

            rooms.rooms.insert(room_id.clone(), session);
            rooms.active_room = Some(room_id.clone());

            println!("created room: {room_id}");
            println!("active room: {room_id}");
            println!("ephemeral: {ephemeral}");
            println!("history: false");
            println!("members: 1");
            println!("room key fingerprint: {key_fingerprint}");
            println!();
            println!("hint:");
            println!("  /invite <peer_id>");
        }

        UserCommand::Invite { peer_id } => {
            send_room_invite(&peer_id, state).await?;
        }

        UserCommand::Invites => {
            print_pending_invites(state).await?;
        }

        UserCommand::AcceptInvite { invite_id } => {
            accept_invite(&invite_id, state).await?;
        }

        UserCommand::RejectInvite { invite_id } => {
            reject_invite(&invite_id, state).await?;
        }

        UserCommand::RoomAddPeer { peer_id } => {
            let Some(p2p) = state.p2p.as_ref() else {
                println!("error: p2p runtime is not started");
                println!();
                println!("hint:");
                println!("  /login <alias>");
                return Ok(());
            };

            let peer: PeerId = peer_id
                .parse()
                .with_context(|| format!("invalid peer id: {peer_id}"))?;

            let connected = p2p.connected_peers().await?;
            if !connected.contains(&peer) {
                println!("error: peer is not connected");
                println!();
                println!("hint:");
                println!("  use /connect <multiaddr> first");
                return Ok(());
            }

            let mut rooms = state.rooms.lock().await;
            let Some(active_room) = rooms.active_room.clone() else {
                println!("error: no active room");
                println!();
                println!("hint:");
                println!("  /join 123 --secret \"shared phrase\"");
                return Ok(());
            };

            let Some(room) = rooms.rooms.get_mut(&active_room) else {
                anyhow::bail!("active room points to missing room state: {active_room}");
            };

            let inserted = room.members.insert(peer);
            if inserted {
                println!("added peer to room {active_room}:");
                println!("  {peer}");
            } else {
                println!("peer is already in room {active_room}:");
                println!("  {peer}");
            }
        }

        UserCommand::RoomPeers => {
            let Some(p2p) = state.p2p.as_ref() else {
                println!("error: p2p runtime is not started");
                println!();
                println!("hint:");
                println!("  /login <alias>");
                return Ok(());
            };

            let connected: HashSet<_> = p2p.connected_peers().await?.into_iter().collect();
            let self_peer = p2p.local_peer_id();
            let rooms = state.rooms.lock().await;

            let Some(active_room) = rooms.active_room.as_ref() else {
                println!("error: no active room");
                println!();
                println!("hint:");
                println!("  /join 123 --secret \"shared phrase\"");
                return Ok(());
            };

            let Some(room) = rooms.rooms.get(active_room) else {
                anyhow::bail!("active room points to missing room state: {active_room}");
            };

            println!("room: {}", room.room_id);
            println!("members:");
            for peer in sorted_peers(&room.members) {
                if peer == self_peer {
                    println!("  {peer}   self=true");
                } else {
                    println!("  {peer}   connected={}", connected.contains(&peer));
                }
            }
        }

        UserCommand::Rooms => {
            let rooms = state.rooms.lock().await;

            if rooms.rooms.is_empty() {
                println!("rooms:");
                println!("  none");
                return Ok(());
            }

            println!("rooms:");
            let active = rooms.active_room.as_deref();

            let mut sessions: Vec<_> = rooms.rooms.values().collect();
            sessions.sort_by_key(|room| room.room_id.as_str());

            for room in sessions {
                let marker = if Some(room.room_id.as_str()) == active {
                    "*"
                } else {
                    " "
                };
                println!(
                    "  {marker} {:<12} ephemeral={:<5} history={:<5} members={} key={}",
                    room.room_id,
                    room.ephemeral,
                    room.history_enabled,
                    room.members.len(),
                    room.key_fingerprint
                );
            }
        }

        UserCommand::Message { text } => {
            send_room_message(&text, state).await?;
        }

        UserCommand::History { enabled } => {
            let mut rooms = state.rooms.lock().await;

            let Some(active_room) = rooms.active_room.clone() else {
                println!("error: no active room");
                println!();
                println!("hint:");
                println!("  /join 123 --secret \"shared phrase\"");
                return Ok(());
            };

            let Some(room) = rooms.rooms.get_mut(&active_room) else {
                anyhow::bail!("active room points to missing room state: {active_room}");
            };

            if enabled && room.ephemeral {
                println!("error: cannot enable history for an ephemeral room");
                return Ok(());
            }

            room.history_enabled = enabled;
            println!("room {active_room} history_enabled={enabled}");
            if enabled {
                println!("note: durable encrypted history writer is deferred to v0.1.1");
            }
        }

        UserCommand::Trust { action } => {
            handle_trust_command(action, store, state).await?;
        }

        UserCommand::Policy { action } => {
            handle_policy_command(action, state)?;
        }

        UserCommand::Status => {
            print_status(state, store).await?;
        }

        UserCommand::Doctor => {
            print_doctor(state, store).await?;
        }

        UserCommand::Debug { enabled } => {
            state.debug_enabled = enabled;
            println!("debug={enabled}");
        }

        UserCommand::Clear => {
            clear_screen()?;
        }

        UserCommand::Help => print_help(),

        UserCommand::Quit => unreachable!("quit is handled before dispatch"),
    }

    Ok(())
}

/// Build, encrypt, sign and send a message to connected members of the active room.
async fn send_room_message(text: &str, state: &mut AppState) -> Result<()> {
    let Some(identity) = state.active_identity.as_ref() else {
        println!("error: no active identity");
        println!();
        println!("hint:");
        println!("  /login <alias>");
        return Ok(());
    };

    let Some(p2p) = state.p2p.as_ref() else {
        println!("error: p2p runtime is not started");
        println!();
        println!("hint:");
        println!("  /login <alias>");
        return Ok(());
    };

    let connected: HashSet<_> = p2p.connected_peers().await?.into_iter().collect();
    let self_peer = p2p.local_peer_id();

    let room = {
        let rooms = state.rooms.lock().await;

        let Some(active_room) = rooms.active_room.as_ref() else {
            println!("error: no active room");
            println!();
            println!("hint:");
            println!("  /join 123 --secret \"shared phrase\"");
            return Ok(());
        };

        let Some(room) = rooms.rooms.get(active_room) else {
            anyhow::bail!("active room points to missing room state: {active_room}");
        };

        room.clone()
    };

    let targets: Vec<_> = sorted_peers(&room.members)
        .into_iter()
        .filter(|peer| *peer != self_peer)
        .filter(|peer| connected.contains(peer))
        .collect();

    if targets.is_empty() {
        println!("error: room has no connected peers");
        println!();
        println!("hint:");
        println!("  /room add-peer <peer_id>");
        return Ok(());
    }

    enforce_message_policy(text, &mut state.message_policy)?;

    let envelope = build_signed_envelope(identity, &room, text)?;

    for peer in &targets {
        p2p.send_envelope(*peer, envelope.clone()).await?;
    }

    println!(
        "[{}] you -> {} peer(s): {}",
        room.room_id,
        targets.len(),
        text
    );

    Ok(())
}

/// Construct the signed encrypted wire envelope for a chat message.
fn build_signed_envelope(
    identity: &UnlockedIdentity,
    room: &RoomSession,
    body: &str,
) -> Result<SignedEncryptedEnvelope> {
    let timestamp_ms = now_ms();

    let plain = PlainMessage {
        message_id: generate_message_id(),
        room_id: room.room_id.clone(),
        body: body.to_string(),
        timestamp_ms,
    };

    let plaintext = serde_json::to_vec(&plain).context("failed to serialize plaintext message")?;
    let (nonce, ciphertext) =
        encrypt_room_message(&room.room_key, &plaintext).context("failed to encrypt message")?;

    let signing_public_key = identity.signing_key.verifying_key().to_bytes();

    let mut envelope = SignedEncryptedEnvelope {
        version: 1,
        room_id: room.room_id.clone(),
        sender_alias: identity.alias.clone(),
        sender_peer_id: identity.peer_id.clone(),
        sender_signing_public_key_b64: BASE64.encode(signing_public_key),
        timestamp_ms,
        nonce_b64: BASE64.encode(nonce),
        ciphertext_b64: BASE64.encode(ciphertext),
        signature_b64: String::new(),
    };

    let signing_payload = envelope
        .signing_payload()
        .context("failed to build envelope signing payload")?;
    let signature = sign_bytes(&identity.signing_key, &signing_payload);
    envelope.signature_b64 = BASE64.encode(signature);

    Ok(envelope)
}

/// Build a signed online room invite for one connected peer.
///
/// Phase 10 invites are not persisted and not offline-deliverable. They carry a
/// random room key over the existing libp2p secure channel, signed by the
/// sender's Ed25519 message identity.
fn build_room_invite(
    identity: &UnlockedIdentity,
    room: &RoomSession,
) -> Result<RoomInvite> {
    let timestamp_ms = now_ms();
    let signing_public_key = identity.signing_key.verifying_key().to_bytes();

    let mut invite = RoomInvite {
        version: 1,
        invite_id: generate_message_id(),
        room_id: room.room_id.clone(),
        room_key_b64: BASE64.encode(room.room_key),
        ephemeral: room.ephemeral,
        sender_alias: identity.alias.clone(),
        sender_peer_id: identity.peer_id.clone(),
        sender_signing_public_key_b64: BASE64.encode(signing_public_key),
        timestamp_ms,
        signature_b64: String::new(),
    };

    let signing_payload = invite
        .signing_payload()
        .context("failed to build invite signing payload")?;
    let signature = sign_bytes(&identity.signing_key, &signing_payload);
    invite.signature_b64 = BASE64.encode(signature);

    Ok(invite)
}

/// Send an invite for the active room to a connected peer.
async fn send_room_invite(peer_id: &str, state: &mut AppState) -> Result<()> {
    let Some(identity) = state.active_identity.as_ref() else {
        println!("error: no active identity");
        println!();
        println!("hint:");
        println!("  /login <alias>");
        return Ok(());
    };

    let Some(p2p) = state.p2p.as_ref() else {
        println!("error: p2p runtime is not started");
        println!();
        println!("hint:");
        println!("  /login <alias>");
        return Ok(());
    };

    let peer: PeerId = peer_id
        .parse()
        .with_context(|| format!("invalid peer id: {peer_id}"))?;

    if peer == p2p.local_peer_id() {
        anyhow::bail!("cannot invite self");
    }

    let connected = p2p.connected_peers().await?;
    if !connected.contains(&peer) {
        println!("error: peer is not connected");
        println!();
        println!("hint:");
        println!("  use /connect <multiaddr> first");
        return Ok(());
    }

    let room = {
        let mut rooms = state.rooms.lock().await;
        let Some(active_room) = rooms.active_room.clone() else {
            println!("error: no active room");
            println!();
            println!("hint:");
            println!("  /create-room --ephemeral");
            return Ok(());
        };

        let Some(room) = rooms.rooms.get_mut(&active_room) else {
            anyhow::bail!("active room points to missing room state: {active_room}");
        };

        room.members.insert(peer);
        room.clone()
    };

    let invite = build_room_invite(identity, &room)?;
    let invite_id = invite.invite_id.clone();
    let room_id = invite.room_id.clone();

    p2p.send_invite(peer, invite).await?;

    println!("invite sent:");
    println!("  invite_id: {invite_id}");
    println!("  room_id: {room_id}");
    println!("  peer: {peer}");
    println!("  room key fingerprint: {}", room.key_fingerprint);

    Ok(())
}

/// Print pending online invites.
async fn print_pending_invites(state: &AppState) -> Result<()> {
    let invites = state.invites.lock().await;

    println!("pending invites:");
    if invites.pending.is_empty() {
        println!("  none");
        return Ok(());
    }

    let mut pending: Vec<_> = invites.pending.values().collect();
    pending.sort_by_key(|invite| invite.invite_id.as_str());

    for invite in pending {
        println!("  {}", invite.invite_id);
        println!("    room_id: {}", invite.room_id);
        println!("    from: {} [{}]", invite.sender_alias, invite.sender_fingerprint);
        println!("    peer_id: {}", invite.sender_peer_id);
        println!("    ephemeral: {}", invite.ephemeral);
        println!("    room key fingerprint: {}", invite.key_fingerprint);
    }

    Ok(())
}

/// Accept a pending online invite and create/activate the invited room.
async fn accept_invite(invite_id: &str, state: &mut AppState) -> Result<()> {
    let Some(p2p) = state.p2p.as_ref() else {
        println!("error: p2p runtime is not started");
        println!();
        println!("hint:");
        println!("  /login <alias>");
        return Ok(());
    };

    let invite = {
        let mut invites = state.invites.lock().await;
        invites.pending.remove(invite_id)
    };

    let Some(invite) = invite else {
        println!("error: invite not found: {invite_id}");
        println!();
        println!("hint:");
        println!("  /invites");
        return Ok(());
    };

    let self_peer = p2p.local_peer_id();
    let mut members = HashSet::new();
    members.insert(self_peer);
    members.insert(invite.sender_peer_id);

    let mut rooms = state.rooms.lock().await;

    if rooms.rooms.contains_key(&invite.room_id) {
        let member_count = {
            let existing = rooms
                .rooms
                .get_mut(&invite.room_id)
                .expect("room exists because contains_key returned true");

            if existing.room_key != invite.room_key {
                anyhow::bail!(
                    "room {} already exists with a different key; refusing invite",
                    invite.room_id
                );
            }

            existing.members.insert(self_peer);
            existing.members.insert(invite.sender_peer_id);
            existing.members.len()
        };

        rooms.active_room = Some(invite.room_id.clone());

        println!("accepted invite: {}", invite.invite_id);
        println!("active room: {}", invite.room_id);
        println!("from: {} [{}]", invite.sender_alias, invite.sender_fingerprint);
        println!("members: {}", member_count);
        return Ok(());
    }

    let session = RoomSession {
        room_id: invite.room_id.clone(),
        room_key: invite.room_key,
        key_fingerprint: invite.key_fingerprint.clone(),
        ephemeral: invite.ephemeral,
        history_enabled: false,
        members,
        seen_message_ids: HashSet::new(),
    };

    rooms.rooms.insert(invite.room_id.clone(), session);
    rooms.active_room = Some(invite.room_id.clone());

    println!("accepted invite: {}", invite.invite_id);
    println!("active room: {}", invite.room_id);
    println!("from: {} [{}]", invite.sender_alias, invite.sender_fingerprint);
    println!("ephemeral: {}", invite.ephemeral);
    println!("history: false");
    println!("members: 2");
    println!("room key fingerprint: {}", invite.key_fingerprint);

    Ok(())
}

/// Reject and forget a pending invite.
async fn reject_invite(invite_id: &str, state: &mut AppState) -> Result<()> {
    let removed = {
        let mut invites = state.invites.lock().await;
        invites.pending.remove(invite_id).is_some()
    };

    if removed {
        println!("rejected invite: {invite_id}");
    } else {
        println!("invite not found: {invite_id}");
    }

    Ok(())
}

/// Spawn a task that receives encrypted envelopes from libp2p and decrypts them
/// using local room keys.
fn spawn_p2p_event_task(
    mut p2p_events: tokio::sync::mpsc::Receiver<P2pEvent>,
    rooms: SharedRoomBook,
    invites: SharedInviteBook,
    trust: SharedTrustBook,
    store: IdentityStore,
) {
    tokio::spawn(async move {
        while let Some(event) = p2p_events.recv().await {
            match event {
                P2pEvent::PeerConnected { peer_id } => {
                    let _ = peer_id;
                }
                P2pEvent::PeerDisconnected { peer_id } => {
                    let _ = peer_id;
                }
                P2pEvent::InboundEnvelope { peer_id, envelope } => {
                    if let Err(err) =
                        handle_inbound_envelope(peer_id, envelope, &rooms, &trust, &store).await
                    {
                        println!();
                        println!("[msg] rejected inbound envelope: {err}");
                    }
                }
                P2pEvent::InboundInvite { peer_id, invite } => {
                    if let Err(err) =
                        handle_inbound_invite(peer_id, invite, &invites, &trust, &store).await
                    {
                        println!();
                        println!("[invite] rejected inbound invite: {err}");
                    }
                }
            }
        }
    });
}

/// Verify, classify and store an inbound online invite.
///
/// The room key is intentionally not written to disk. The user must explicitly
/// run `/accept-invite <id>` before the room becomes active.
async fn handle_inbound_invite(
    peer_id: PeerId,
    invite: RoomInvite,
    invites: &SharedInviteBook,
    trust: &SharedTrustBook,
    store: &IdentityStore,
) -> Result<()> {
    if invite.sender_peer_id != peer_id.to_string() {
        anyhow::bail!(
            "sender peer mismatch: connection peer is {}, invite claims {}",
            peer_id,
            invite.sender_peer_id
        );
    }

    if invite.invite_id.is_empty() || invite.invite_id.len() > 64 {
        anyhow::bail!("invalid invite id");
    }

    validate_room_id(&invite.room_id)?;

    let signing_public_key = BASE64
        .decode(&invite.sender_signing_public_key_b64)
        .context("invalid invite signing public key base64")?;
    let signature = BASE64
        .decode(&invite.signature_b64)
        .context("invalid invite signature base64")?;
    let signing_payload = invite
        .signing_payload()
        .context("failed to build invite signing payload")?;

    verify_signature(&signing_public_key, &signing_payload, &signature)
        .context("invalid invite signature")?;

    let room_key_bytes = BASE64
        .decode(&invite.room_key_b64)
        .context("invalid invite room key base64")?;

    if room_key_bytes.len() != 32 {
        anyhow::bail!("invalid invite room key length: expected 32 bytes, got {}", room_key_bytes.len());
    }

    let mut room_key = [0u8; 32];
    room_key.copy_from_slice(&room_key_bytes);

    let fingerprint = fingerprint_from_public_key(&signing_public_key);
    let trust_status =
        observe_and_classify_invite_peer(peer_id, &invite, &fingerprint, trust, store).await?;

    let pending = PendingInvite {
        invite_id: invite.invite_id.clone(),
        room_id: invite.room_id.clone(),
        room_key,
        key_fingerprint: room_key_fingerprint(&room_key),
        ephemeral: invite.ephemeral,
        sender_alias: invite.sender_alias.clone(),
        sender_peer_id: peer_id,
        sender_fingerprint: fingerprint.clone(),
        received_at_ms: now_ms(),
    };

    {
        let mut invites = invites.lock().await;
        invites.pending.insert(pending.invite_id.clone(), pending.clone());
    }

    println!();

    match trust_status {
        InboundTrustStatus::Trusted => {
            println!(
                "[invite] {} [{}] invites you to room {}",
                invite.sender_alias, fingerprint, invite.room_id
            );
        }
        InboundTrustStatus::Untrusted => {
            println!(
                "[invite] [untrusted] {} [{}] invites you to room {}",
                invite.sender_alias, fingerprint, invite.room_id
            );
            println!("hint: verify fingerprint out-of-band, then run /trust {}", peer_id);
        }
        InboundTrustStatus::KeyChanged {
            old_fingerprint,
            new_fingerprint,
        } => {
            println!("SECURITY WARNING: signing key changed for peer {peer_id}");
            println!("  old fingerprint: {old_fingerprint}");
            println!("  new fingerprint: {new_fingerprint}");
            println!(
                "[invite] [key-changed] {} [{}] invites you to room {}",
                invite.sender_alias, fingerprint, invite.room_id
            );
        }
    }

    println!("  invite_id: {}", invite.invite_id);
    println!("  ephemeral: {}", invite.ephemeral);
    println!("  room key fingerprint: {}", pending.key_fingerprint);
    println!("hint:");
    println!("  /accept-invite {}", invite.invite_id);
    println!("  /reject-invite {}", invite.invite_id);

    Ok(())
}

/// Verify, decrypt, classify trust status and render an inbound message.
async fn handle_inbound_envelope(
    peer_id: PeerId,
    envelope: SignedEncryptedEnvelope,
    rooms: &SharedRoomBook,
    trust: &SharedTrustBook,
    store: &IdentityStore,
) -> Result<()> {
    let room_key = {
        let rooms = rooms.lock().await;
        let Some(room) = rooms.rooms.get(&envelope.room_id) else {
            anyhow::bail!(
                "unknown room '{}' from peer {}; join the room first",
                envelope.room_id,
                peer_id
            );
        };

        // Phase 9 hardening: local room membership is enforced on inbound
        // messages too. Before this, membership only controlled outbound
        // routing; a connected peer that knew the room id and secret could still
        // inject messages into the local room.
        if !room.members.contains(&peer_id) {
            anyhow::bail!(
                "peer {} is not a local member of room '{}'; use /room add-peer before accepting messages",
                peer_id,
                envelope.room_id
            );
        }

        room.room_key
    };

    if envelope.sender_peer_id != peer_id.to_string() {
        anyhow::bail!(
            "sender peer mismatch: connection peer is {}, envelope claims {}",
            peer_id,
            envelope.sender_peer_id
        );
    }

    let signing_public_key = BASE64
        .decode(&envelope.sender_signing_public_key_b64)
        .context("invalid sender signing public key base64")?;
    let signature = BASE64
        .decode(&envelope.signature_b64)
        .context("invalid signature base64")?;
    let signing_payload = envelope
        .signing_payload()
        .context("failed to build signing payload")?;

    verify_signature(&signing_public_key, &signing_payload, &signature)
        .context("invalid message signature")?;

    let nonce = BASE64
        .decode(&envelope.nonce_b64)
        .context("invalid nonce base64")?;
    let ciphertext = BASE64
        .decode(&envelope.ciphertext_b64)
        .context("invalid ciphertext base64")?;

    let plaintext =
        decrypt_room_message(&room_key, &nonce, &ciphertext).context("message decryption failed")?;
    let plain: PlainMessage =
        serde_json::from_slice(&plaintext).context("failed to deserialize plaintext message")?;

    if plain.room_id != envelope.room_id {
        anyhow::bail!(
            "inner room id '{}' does not match outer room id '{}'",
            plain.room_id,
            envelope.room_id
        );
    }

    if plain.message_id.is_empty() || plain.message_id.len() > 64 {
        anyhow::bail!("invalid message id in decrypted plaintext");
    }

    let replay_key = format!("{}:{}", envelope.sender_peer_id, plain.message_id);
    {
        let mut rooms = rooms.lock().await;
        let Some(room) = rooms.rooms.get_mut(&envelope.room_id) else {
            anyhow::bail!(
                "room '{}' disappeared while processing inbound message",
                envelope.room_id
            );
        };

        if !room.members.contains(&peer_id) {
            anyhow::bail!(
                "peer {} is no longer a local member of room '{}'",
                peer_id,
                envelope.room_id
            );
        }

        if !room.seen_message_ids.insert(replay_key) {
            anyhow::bail!(
                "replayed message rejected from peer {} in room '{}'",
                peer_id,
                envelope.room_id
            );
        }

        // Bound memory usage. This is intentionally simple for v0.1; if the
        // cache grows too large during a long session, we clear it instead of
        // keeping unbounded state. Durable replay protection belongs with the
        // future encrypted history layer.
        if room.seen_message_ids.len() > 4096 {
            room.seen_message_ids.clear();
        }
    }

    let fingerprint = fingerprint_from_public_key(&signing_public_key);
    let trust_status =
        observe_and_classify_peer(peer_id, &envelope, &fingerprint, trust, store).await?;

    println!();

    match trust_status {
        InboundTrustStatus::Trusted => {
            println!(
                "[{}] {} [{}]: {}",
                envelope.room_id, envelope.sender_alias, fingerprint, plain.body
            );
        }
        InboundTrustStatus::Untrusted => {
            println!(
                "[{}] [untrusted] {} [{}]: {}",
                envelope.room_id, envelope.sender_alias, fingerprint, plain.body
            );
            println!("hint: verify fingerprint out-of-band, then run /trust {}", peer_id);
        }
        InboundTrustStatus::KeyChanged {
            old_fingerprint,
            new_fingerprint,
        } => {
            println!("SECURITY WARNING: signing key changed for peer {peer_id}");
            println!("  old fingerprint: {old_fingerprint}");
            println!("  new fingerprint: {new_fingerprint}");
            println!(
                "[{}] [key-changed] {} [{}]: {}",
                envelope.room_id, envelope.sender_alias, fingerprint, plain.body
            );
        }
    }

    Ok(())
}



/// Enforce local message policy before encryption and network transmission.
fn enforce_message_policy(text: &str, policy: &mut MessagePolicy) -> Result<()> {
    let char_count = text.chars().count();

    if char_count == 0 {
        anyhow::bail!("message rejected by local policy\n\nreason:\n  empty messages are not allowed");
    }

    if char_count > policy.max_chars {
        anyhow::bail!(
            "message rejected by local policy\n\nreason:\n  message is too long: {char_count} chars, max {} chars",
            policy.max_chars
        );
    }

    if policy.reject_multiline && (text.contains('\n') || text.contains('\r')) {
        anyhow::bail!(
            "message rejected by local policy\n\nreason:\n  multiline input is not allowed"
        );
    }

    if policy.reject_control_chars && contains_rejected_control_char(text) {
        anyhow::bail!(
            "message rejected by local policy\n\nreason:\n  control characters are not allowed"
        );
    }

    if policy.reject_links && contains_link_like_token(text) {
        anyhow::bail!(
            "message rejected by local policy\n\nreason:\n  links are not allowed in {} mode",
            policy.mode_name()
        );
    }

    enforce_rate_limit(policy)?;

    Ok(())
}

/// Rate-limit accepted outgoing messages.
///
/// This is intentionally simple and local. It does not protect against a
/// malicious modified client, but it protects normal users from accidental
/// paste bursts and keeps the official client aligned with the product model.
fn enforce_rate_limit(policy: &mut MessagePolicy) -> Result<()> {
    let now = now_ms();
    let window_ms = policy.window.as_millis() as u64;
    let cutoff = now.saturating_sub(window_ms);

    while let Some(oldest) = policy.sent_timestamps_ms.front().copied() {
        if oldest < cutoff {
            policy.sent_timestamps_ms.pop_front();
        } else {
            break;
        }
    }

    if policy.sent_timestamps_ms.len() >= policy.max_messages_per_window {
        anyhow::bail!(
            "message rejected by local policy\n\nreason:\n  paste/rate burst detected: max {} messages per {} seconds",
            policy.max_messages_per_window,
            policy.window.as_secs()
        );
    }

    policy.sent_timestamps_ms.push_back(now);
    Ok(())
}

fn contains_rejected_control_char(text: &str) -> bool {
    text.chars().any(|ch| {
        // `rustyline` normally gives us one line, but this deliberately remains
        // defensive. Ordinary whitespace in a one-line message is allowed.
        ch.is_control() && ch != ' '
    })
}

/// Detect obvious URLs and domain-like tokens.
///
/// This is not meant to be a perfect URL parser. It is a conservative local
/// policy for the official client: if a token looks enough like a link, reject
/// it. The check catches `https://`, `www.`, common domain/path forms such as
/// `github.com/user/repo`, and compact domains such as `t.me/name`.
fn contains_link_like_token(text: &str) -> bool {
    text.split_whitespace().any(is_link_like_token)
}

fn is_link_like_token(token: &str) -> bool {
    let trimmed = token.trim_matches(|ch: char| {
        matches!(
            ch,
            '"' | '\'' | '`' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | ':' | '!' | '?'
        )
    });

    let trimmed = trimmed.trim_end_matches('.');
    let lower = trimmed.to_ascii_lowercase();

    if lower.is_empty() {
        return false;
    }

    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("www.")
    {
        return true;
    }

    if lower.contains('@') && lower.contains('.') {
        return true;
    }

    let host = lower
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(lower.as_str());

    is_domain_like(host)
}

fn is_domain_like(host: &str) -> bool {
    if !host.contains('.') || host.contains("..") {
        return false;
    }

    if host.starts_with('.') || host.ends_with('.') {
        return false;
    }

    let labels: Vec<&str> = host.split('.').collect();

    if labels.len() < 2 {
        return false;
    }

    let Some(tld) = labels.last().copied() else {
        return false;
    };

    if tld.len() < 2 || tld.len() > 24 || !tld.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return false;
    }

    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn handle_policy_command(action: PolicyCommand, state: &mut AppState) -> Result<()> {
    match action {
        PolicyCommand::Show => {
            print_message_policy(&state.message_policy);
        }
        PolicyCommand::Strict => {
            state.message_policy = MessagePolicy::strict();
            println!("message policy set to strict");
            print_message_policy(&state.message_policy);
        }
        PolicyCommand::Relaxed => {
            state.message_policy = MessagePolicy::relaxed();
            println!("message policy set to relaxed");
            println!("note: links, multiline input and control characters are still rejected");
            print_message_policy(&state.message_policy);
        }
    }

    Ok(())
}

fn print_message_policy(policy: &MessagePolicy) {
    println!("message policy:");
    println!("  mode: {}", policy.mode_name());
    println!("  max chars: {}", policy.max_chars);
    println!(
        "  links: {}",
        if policy.reject_links { "rejected" } else { "allowed" }
    );
    println!(
        "  multiline: {}",
        if policy.reject_multiline { "rejected" } else { "allowed" }
    );
    println!(
        "  control chars: {}",
        if policy.reject_control_chars { "rejected" } else { "allowed" }
    );
    println!(
        "  rate limit: {} messages / {}s",
        policy.max_messages_per_window,
        policy.window.as_secs()
    );
    println!("  paste/file-transfer mode: unavailable");
}


/// Handle `/trust` commands.
///
/// Trust is per-local-identity and persisted in
/// `~/.config/dogel/identities/<alias>/trusted_peers.toml`.
async fn handle_trust_command(
    action: TrustCommand,
    store: &IdentityStore,
    state: &mut AppState,
) -> Result<()> {
    let Some(identity) = state.active_identity.as_ref() else {
        println!("error: no active identity");
        println!();
        println!("hint:");
        println!("  /login <alias>");
        return Ok(());
    };

    match action {
        TrustCommand::List => {
            let trusted = store
                .load_trusted_peers(&identity.alias)
                .context("failed to load trusted peers")?;

            println!("trusted peers:");
            if trusted.is_empty() {
                println!("  none");
                println!();
                println!("hint:");
                println!("  receive a message, verify its fingerprint, then run /trust <peer_id>");
            } else {
                for peer in trusted {
                    println!("  {} [{}]", peer.alias, peer.fingerprint);
                    println!("    peer_id: {}", peer.peer_id);
                    println!("    trusted_at_ms: {}", peer.trusted_at_ms);
                    println!("    last_seen_at_ms: {}", peer.last_seen_at_ms);
                }
            }
        }

        TrustCommand::Add { peer_id } => {
            // Validate early so `/trust nonsense` fails before touching disk.
            let _: PeerId = peer_id
                .parse()
                .with_context(|| format!("invalid peer id: {peer_id}"))?;

            let observed = {
                let trust = state.trust.lock().await;
                trust.observed.get(&peer_id).cloned()
            };

            let Some(observed) = observed else {
                println!("error: no observed signing key for peer {peer_id}");
                println!();
                println!("hint:");
                println!("  wait for a signed message from that peer first");
                println!("  then compare the displayed fingerprint out-of-band");
                println!("  then run /trust {peer_id}");
                return Ok(());
            };

            let existing = store
                .load_trusted_peers(&identity.alias)
                .context("failed to load trusted peers")?
                .into_iter()
                .find(|record| record.peer_id == peer_id);

            if let Some(existing) = existing.as_ref() {
                if existing.signing_public_key_b64 != observed.signing_public_key_b64 {
                    println!("SECURITY WARNING: replacing trusted signing key for peer {peer_id}");
                    println!("  old fingerprint: {}", existing.fingerprint);
                    println!("  new fingerprint: {}", observed.fingerprint);
                    println!("  proceed only if you verified this change out-of-band");
                }
            }

            let record = TrustedPeerRecord {
                peer_id: observed.peer_id,
                alias: observed.alias,
                signing_public_key_b64: observed.signing_public_key_b64,
                fingerprint: observed.fingerprint,
                trusted_at_ms: now_ms(),
                last_seen_at_ms: observed.last_seen_at_ms,
            };

            store
                .trust_peer(&identity.alias, record.clone())
                .context("failed to write trusted peer record")?;

            println!("trusted peer:");
            println!("  alias: {}", record.alias);
            println!("  peer_id: {}", record.peer_id);
            println!("  fingerprint: {}", record.fingerprint);
            println!("  path: {}", store.trusted_peers_path(&identity.alias).display());
        }

        TrustCommand::Remove { peer_id } => {
            let _: PeerId = peer_id
                .parse()
                .with_context(|| format!("invalid peer id: {peer_id}"))?;

            let removed = store
                .remove_trusted_peer(&identity.alias, &peer_id)
                .context("failed to update trusted peers")?;

            if removed {
                println!("removed trusted peer:");
                println!("  {peer_id}");
            } else {
                println!("trusted peer not found:");
                println!("  {peer_id}");
            }
        }
    }

    Ok(())
}

/// Record the latest observed signing key and classify the inbound message
/// against the local trust store.
async fn observe_and_classify_peer(
    peer_id: PeerId,
    envelope: &SignedEncryptedEnvelope,
    fingerprint: &str,
    trust: &SharedTrustBook,
    store: &IdentityStore,
) -> Result<InboundTrustStatus> {
    let peer_id_string = peer_id.to_string();
    let observed = ObservedPeer {
        peer_id: peer_id_string.clone(),
        alias: envelope.sender_alias.clone(),
        signing_public_key_b64: envelope.sender_signing_public_key_b64.clone(),
        fingerprint: fingerprint.to_string(),
        last_seen_at_ms: now_ms(),
    };

    let identity_alias = {
        let mut trust = trust.lock().await;
        trust
            .observed
            .insert(peer_id_string.clone(), observed.clone());
        trust.identity_alias.clone()
    };

    let Some(identity_alias) = identity_alias else {
        return Ok(InboundTrustStatus::Untrusted);
    };

    let trusted = store
        .load_trusted_peers(&identity_alias)
        .context("failed to load trusted peers")?;

    let Some(record) = trusted
        .into_iter()
        .find(|record| record.peer_id == peer_id_string)
    else {
        return Ok(InboundTrustStatus::Untrusted);
    };

    if record.signing_public_key_b64 == observed.signing_public_key_b64 {
        Ok(InboundTrustStatus::Trusted)
    } else {
        Ok(InboundTrustStatus::KeyChanged {
            old_fingerprint: record.fingerprint,
            new_fingerprint: observed.fingerprint,
        })
    }
}


async fn observe_and_classify_invite_peer(
    peer_id: PeerId,
    invite: &RoomInvite,
    fingerprint: &str,
    trust: &SharedTrustBook,
    store: &IdentityStore,
) -> Result<InboundTrustStatus> {
    let peer_id_string = peer_id.to_string();
    let observed = ObservedPeer {
        peer_id: peer_id_string.clone(),
        alias: invite.sender_alias.clone(),
        signing_public_key_b64: invite.sender_signing_public_key_b64.clone(),
        fingerprint: fingerprint.to_string(),
        last_seen_at_ms: now_ms(),
    };

    let identity_alias = {
        let mut trust = trust.lock().await;
        trust
            .observed
            .insert(peer_id_string.clone(), observed.clone());
        trust.identity_alias.clone()
    };

    let Some(identity_alias) = identity_alias else {
        return Ok(InboundTrustStatus::Untrusted);
    };

    let trusted = store
        .load_trusted_peers(&identity_alias)
        .context("failed to load trusted peers")?;

    let Some(record) = trusted
        .into_iter()
        .find(|record| record.peer_id == peer_id_string)
    else {
        return Ok(InboundTrustStatus::Untrusted);
    };

    if record.signing_public_key_b64 == observed.signing_public_key_b64 {
        Ok(InboundTrustStatus::Trusted)
    } else {
        Ok(InboundTrustStatus::KeyChanged {
            old_fingerprint: record.fingerprint,
            new_fingerprint: observed.fingerprint,
        })
    }
}


fn parse_startup_config() -> Result<StartupConfig> {
    let mut args = std::env::args().skip(1);
    let mut listen = DEFAULT_LISTEN_ADDR.to_string();
    let mut tui = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                let Some(value) = args.next() else {
                    anyhow::bail!("--listen requires a multiaddr value");
                };
                listen = value;
            }
            "--tui" => {
                tui = true;
            }
            "--help" | "-h" => {
                println!("usage:");
                println!("  dogel.bin [--listen <multiaddr>] [--tui]");
                println!();
                println!("examples:");
                println!("  dogel.bin --listen /ip4/0.0.0.0/tcp/7777");
                println!("  dogel.bin --tui --listen /ip4/0.0.0.0/tcp/7778");
                std::process::exit(0);
            }
            other => {
                anyhow::bail!("unknown startup argument: {other}");
            }
        }
    }

    let listen_addr = listen
        .parse()
        .with_context(|| format!("invalid listen multiaddr: {listen}"))?;

    Ok(StartupConfig { listen_addr, tui })
}

fn prompt_new_password() -> Result<String> {
    let password = rpassword::prompt_password("Password: ")
        .context("failed to read password")?;
    let confirm = rpassword::prompt_password("Confirm password: ")
        .context("failed to read password confirmation")?;

    if password != confirm {
        anyhow::bail!("passwords do not match");
    }

    if password.len() < 8 {
        anyhow::bail!("password must be at least 8 characters long");
    }

    Ok(password)
}

/// Derive a deterministic one-to-one room id from two peer ids.
///
/// A direct room cannot simply use `remote_peer_id` as the room id: Alice would
/// derive `room = Bob`, while Bob would derive `room = Alice`, so they would
/// never decrypt each other's messages. Sorting both peer ids before hashing
/// makes the room id stable and symmetric on both sides.
///
/// The output intentionally uses only URL/CLI-safe characters accepted by
/// `validate_room_id`.
fn generate_invite_room_id() -> String {
    let id = generate_message_id();
    let suffix = &id[..16];
    format!("room-{suffix}")
}

fn deterministic_dm_room_id(a: PeerId, b: PeerId) -> String {
    let mut peers = [a.to_string(), b.to_string()];
    peers.sort();

    let material = format!("DOGEL_DM_ROOM_V1\0{}\0{}", peers[0], peers[1]);
    let hash = blake3::hash(material.as_bytes());

    let suffix = hash.as_bytes()[..8]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();

    format!("dm-{suffix}")
}

fn validate_room_id(room_id: &str) -> Result<()> {
    if room_id.is_empty() {
        anyhow::bail!("room id cannot be empty");
    }

    if room_id.len() > 64 {
        anyhow::bail!("room id is too long; max 64 characters");
    }

    if !room_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
    {
        anyhow::bail!(
            "room id may contain only ASCII letters, numbers, '-', '_' and '.'"
        );
    }

    Ok(())
}

fn sorted_peers(peers: &HashSet<PeerId>) -> Vec<PeerId> {
    let mut peers: Vec<_> = peers.iter().copied().collect();
    peers.sort_by_key(|peer| peer.to_string());
    peers
}

fn now_ms() -> u64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX_EPOCH");

    duration.as_millis() as u64
}

/// Print a compact operational snapshot of the current client.
///
/// `/status` overlaps with `/whoami`, `/peers`, `/rooms` and `/room peers`, but
/// it is intentionally kept as a single command because it is the fastest way
/// to debug a live P2P session while testing two terminals side by side.
async fn print_status(state: &AppState, store: &IdentityStore) -> Result<()> {
    println!("identity:");
    if let Some(identity) = state.active_identity.as_ref() {
        println!("  alias: {}", identity.alias);
        println!("  peer_id: {}", identity.peer_id);
        println!("  fingerprint: {}", identity.fingerprint);

        match store.load_trusted_peers(&identity.alias) {
            Ok(peers) => println!("  trusted peers: {}", peers.len()),
            Err(err) => println!("  trusted peers: unavailable ({err})"),
        }
    } else {
        println!("  none");
    }

    println!();
    println!("network:");
    if let Some(p2p) = state.p2p.as_ref() {
        let peers = p2p.connected_peers().await?;
        let addrs = p2p.listen_addrs().await?;

        println!("  local_peer_id: {}", p2p.local_peer_id());
        println!("  connected peers: {}", peers.len());

        if peers.is_empty() {
            println!("  peers: none");
        } else {
            println!("  peers:");
            for peer in peers {
                println!("    {peer}");
            }
        }

        println!("  listen:");
        if addrs.is_empty() {
            println!("    swarm started, but no listen address is confirmed yet");
        } else {
            for addr in addrs {
                println!(
                    "    {}",
                    addr.with(libp2p::multiaddr::Protocol::P2p(p2p.local_peer_id()))
                );
            }
        }
    } else {
        println!("  p2p runtime: not started");
        println!("  hint: /login <alias>");
    }

    println!();
    println!("active room:");
    let rooms = state.rooms.lock().await;
    if let Some(active_room) = rooms.active_room.as_ref() {
        if let Some(room) = rooms.rooms.get(active_room) {
            println!("  room_id: {}", room.room_id);
            println!("  ephemeral: {}", room.ephemeral);
            println!("  history: {}", room.history_enabled);
            println!("  members: {}", room.members.len());
            println!("  key fingerprint: {}", room.key_fingerprint);
        } else {
            println!("  corrupted state: active room points to missing room '{active_room}'");
        }
    } else {
        println!("  none");
    }
    drop(rooms);

    println!();
    println!("invites:");
    let invites = state.invites.lock().await;
    println!("  pending: {}", invites.pending.len());
    drop(invites);

    println!();
    print_message_policy(&state.message_policy);

    Ok(())
}

async fn build_doctor_report(state: &AppState, store: &IdentityStore) -> Result<Vec<String>> {
    let mut lines = Vec::new();

    lines.push("doctor:".to_string());

    lines.push("identity:".to_string());
    if let Some(identity) = state.active_identity.as_ref() {
        lines.push(format!("  active: yes"));
        lines.push(format!("  alias: {}", identity.alias));
        lines.push(format!("  peer_id: {}", identity.peer_id));
        lines.push(format!("  fingerprint: {}", identity.fingerprint));

        let lock_state = if state.session_lock_alias.as_deref() == Some(identity.alias.as_str()) {
            "held"
        } else {
            "not-held"
        };
        lines.push(format!("  session lock: {lock_state}"));

        match store.load_trusted_peers(&identity.alias) {
            Ok(peers) => lines.push(format!("  trusted peers on disk: {}", peers.len())),
            Err(err) => lines.push(format!("  trusted peers on disk: unavailable ({err})")),
        }
    } else {
        lines.push("  active: no".to_string());
        lines.push("  hint: /login <alias>".to_string());
    }

    lines.push("network:".to_string());
    if let Some(p2p) = state.p2p.as_ref() {
        let peers = p2p.connected_peers().await?;
        let addrs = p2p.listen_addrs().await?;
        lines.push("  p2p: running".to_string());
        lines.push(format!("  local_peer_id: {}", p2p.local_peer_id()));
        lines.push(format!("  connected peers: {}", peers.len()));
        lines.push(format!("  confirmed listen addresses: {}", addrs.len()));
    } else {
        lines.push("  p2p: not-started".to_string());
    }

    let rooms = state.rooms.lock().await;
    lines.push("rooms:".to_string());
    lines.push(format!("  total: {}", rooms.rooms.len()));
    match rooms.active_room.as_ref().and_then(|room_id| rooms.rooms.get(room_id)) {
        Some(room) => {
            lines.push(format!("  active: {}", room.room_id));
            lines.push(format!("  ephemeral: {}", room.ephemeral));
            lines.push(format!("  history: {}", room.history_enabled));
            lines.push(format!("  members: {}", room.members.len()));
            lines.push(format!("  replay cache: {}", room.seen_message_ids.len()));
        }
        None => lines.push("  active: none".to_string()),
    }
    drop(rooms);

    let invites = state.invites.lock().await;
    lines.push("invites:".to_string());
    lines.push(format!("  pending: {}", invites.pending.len()));
    drop(invites);

    let trust = state.trust.lock().await;
    lines.push("trust:".to_string());
    lines.push(format!("  observed peers: {}", trust.observed.len()));
    drop(trust);

    lines.push("policy:".to_string());
    lines.push(format!("  mode: {}", state.message_policy.mode_name()));
    lines.push(format!("  max chars: {}", state.message_policy.max_chars));
    lines.push(format!("  links rejected: {}", state.message_policy.reject_links));
    lines.push(format!("  multiline rejected: {}", state.message_policy.reject_multiline));
    lines.push(format!(
        "  rate limit: {} messages / {}s",
        state.message_policy.max_messages_per_window,
        state.message_policy.window.as_secs()
    ));

    lines.push("runtime:".to_string());
    lines.push(format!("  debug: {}", if state.debug_enabled { "on" } else { "off" }));

    Ok(lines)
}

async fn print_doctor(state: &AppState, store: &IdentityStore) -> Result<()> {
    for line in build_doctor_report(state, store).await? {
        println!("{line}");
    }
    Ok(())
}

/// Clear the visible terminal screen.
///
/// This uses a plain ANSI escape sequence instead of pulling in a terminal UI
/// crate. It is enough for the CLI phase and can be replaced by ratatui later.
fn clear_screen() -> Result<()> {
    print!("\x1b[2J\x1b[H");
    io::stdout()
        .flush()
        .context("failed to flush terminal after clear")?;
    Ok(())
}

fn print_parse_error(err: &eve_core::CommandParseError) {
    println!("error: {err}");

    match err {
        eve_core::CommandParseError::MissingFlag("--secret") => {
            println!();
            println!("usage:");
            println!("  /join <room_id> --secret <passphrase> [--ephemeral]");
            println!("  /dm <peer_id> --secret <passphrase> [--ephemeral]");
        }
        eve_core::CommandParseError::MissingSlash => {
            println!();
            println!("hint:");
            println!("  commands start with '/', for example /help");
        }
        _ => {}
    }
}

fn print_help() {
    println!("commands:");
    println!("  /identity create <alias>");
    println!("  /login <alias>");
    println!("  /whoami");
    println!("  /connect <multiaddr>");
    println!("  /peers");
    println!("  /create-room [room_id] [--ephemeral]");
    println!("  /invite <peer_id>");
    println!("  /invites");
    println!("  /accept-invite <invite_id>");
    println!("  /reject-invite <invite_id>");
    println!("  /join <room_id> --secret <passphrase> [--ephemeral]");
    println!("  /dm <peer_id> --secret <passphrase> [--ephemeral]");
    println!("  /room add-peer <peer_id>");
    println!("  /room peers");
    println!("  /rooms");
    println!("  /msg <text>");
    println!("  /history on");
    println!("  /history off");
    println!("  /trust <peer_id>");
    println!("  /trust list");
    println!("  /trust remove <peer_id>");
    println!("  /policy");
    println!("  /policy strict");
    println!("  /policy relaxed");
    println!("  /status");
    println!("  /doctor");
    println!("  /debug on");
    println!("  /debug off");
    println!("  /clear");
    println!("  /help");
    println!("  /quit");
    println!();
    println!("startup:");
    println!("  dogel.bin [--listen <multiaddr>] [--tui]");
    println!();
    println!("generic examples:");
    println!("  /login <alias>");
    println!("  /whoami");
    println!("  /connect /ip4/<host>/tcp/<port>/p2p/<peer_id>");
    println!("  /create-room --ephemeral");
    println!("  /invite <peer_id>");
    println!("  /invites");
    println!("  /accept-invite <invite_id>");
    println!("  hello world");
    println!();
    println!("dev shortcuts still available:");
    println!("  /join <room_id> --secret \"<shared phrase>\" --ephemeral");
    println!("  /dm <peer_id> --secret \"<shared phrase>\" --ephemeral");
}
