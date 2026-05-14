use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use crossterm::{
    event::{self, Event as CrosstermEvent, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use eve_core::{parse_command, PolicyCommand, TrustCommand, UserCommand};
use eve_crypto::{
    decrypt_room_message, derive_bound_room_key, derive_room_key, encrypt_room_message,
    fingerprint_from_public_key, generate_message_id, generate_random_room_key,
    room_key_fingerprint, sign_bytes, verify_signature,
};
use eve_p2p::{P2pConfig, P2pEvent, P2pHandle};
use eve_protocol::{
    canonical_peer_list, require_protocol_version, PlainMessage, RoomInvite, RoomMembershipState,
    SignedEncryptedEnvelope, PROTOCOL_VERSION,
};
use eve_storage::{IdentityStore, TrustedPeerRecord, UnlockedIdentity};
use eve_storage::{RoomHistoryDirection, RoomHistoryEntry};
use libp2p::{Multiaddr, PeerId};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Terminal,
};
use rustyline::{error::ReadlineError, DefaultEditor};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io::{self, Write},
    rc::Rc,
    sync::{Arc, Mutex as StdMutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

tokio::task_local! {
    static OUTPUT_CAPTURE: Rc<RefCell<Vec<String>>>;
}

type SharedOutputSink = Arc<StdMutex<VecDeque<String>>>;

static GLOBAL_OUTPUT_SINK: OnceLock<StdMutex<Option<SharedOutputSink>>> = OnceLock::new();

struct GlobalOutputSinkGuard;

impl GlobalOutputSinkGuard {
    fn install(sink: SharedOutputSink) -> Self {
        let cell = GLOBAL_OUTPUT_SINK.get_or_init(|| StdMutex::new(None));
        if let Ok(mut current) = cell.lock() {
            *current = Some(sink);
        }
        Self
    }
}

impl Drop for GlobalOutputSinkGuard {
    fn drop(&mut self) {
        if let Some(cell) = GLOBAL_OUTPUT_SINK.get() {
            if let Ok(mut current) = cell.lock() {
                *current = None;
            }
        }
    }
}

fn emit_output_line(line: String) {
    if OUTPUT_CAPTURE
        .try_with(|capture| {
            let mut lines = capture.borrow_mut();
            for segment in line.split('\n') {
                lines.push(segment.to_string());
            }
        })
        .is_err()
    {
        if let Some(cell) = GLOBAL_OUTPUT_SINK.get() {
            if let Ok(current) = cell.lock() {
                if let Some(sink) = current.as_ref() {
                    if let Ok(mut lines) = sink.lock() {
                        for segment in line.split('\n') {
                            lines.push_back(segment.to_string());
                        }
                        return;
                    }
                }
            }
        }

        std::println!("{line}");
    }
}

macro_rules! println {
    () => {
        emit_output_line(String::new())
    };
    ($($arg:tt)*) => {
        emit_output_line(format!($($arg)*))
    };
}

async fn capture_command_output<F, T>(future: F) -> (T, Vec<String>)
where
    F: Future<Output = T>,
{
    let capture = Rc::new(RefCell::new(Vec::new()));
    let result = OUTPUT_CAPTURE.scope(Rc::clone(&capture), future).await;
    let lines = std::mem::take(&mut *capture.borrow_mut());
    (result, lines)
}

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
    bootstrap_peers: Vec<Multiaddr>,
    relay_server: bool,
    external_addrs: Vec<Multiaddr>,
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
    room_seed: Option<[u8; 32]>,
    key_fingerprint: String,
    ephemeral: bool,
    history_enabled: bool,
    members: HashSet<PeerId>,
    membership: Option<RoomMembershipState>,

    /// In-memory replay cache for this room.
    ///
    /// Each entry is `sender_peer_id:message_id`. This is intentionally
    /// memory-only for v0.1 because durable history is not implemented yet.
    /// Ephemeral rooms still benefit from rejecting repeated envelopes during a
    /// live session.
    replay_cache: ReplayCache,
}

/// Bounded in-memory replay cache for decrypted message ids.
#[derive(Debug, Clone)]
struct ReplayCache {
    seen: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity: 4096,
        }
    }
}

impl ReplayCache {
    fn insert(&mut self, key: String) -> bool {
        if self.seen.contains(&key) {
            return false;
        }

        self.seen.insert(key.clone());
        self.order.push_back(key);

        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }

        true
    }

    fn len(&self) -> usize {
        self.seen.len()
    }
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
    room_seed: [u8; 32],
    key_fingerprint: String,
    ephemeral: bool,
    membership: RoomMembershipState,
    sender_alias: String,
    sender_peer_id: PeerId,
    sender_fingerprint: String,
    received_at_ms: u64,
}

impl AppState {
    fn new(config: &StartupConfig) -> Self {
        Self {
            active_identity: None,
            p2p: None,
            listen_addr: config.listen_addr.clone(),
            bootstrap_peers: config.bootstrap_peers.clone(),
            relay_server: config.relay_server,
            external_addrs: config.external_addrs.clone(),
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
    bootstrap_peers: Vec<Multiaddr>,
    relay_server: bool,
    external_addrs: Vec<Multiaddr>,
    tui: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = parse_startup_config()?;
    let store = IdentityStore::default().context("failed to initialize local identity store")?;
    let mut state = AppState::new(&config);

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
/// This remains the primary debugging mode. The TUI is an additional frontend,
/// not a replacement for the stable shell.
async fn run_shell_loop(store: &IdentityStore, state: &mut AppState) -> Result<()> {
    println!("dogel.bin v0.1 phase 16");
    println!(
        "interactive shell + encrypted P2P messages + trust + online invites + relay/bootstrap + AutoNAT/DCUtR + TUI"
    );
    println!("config root: {}", store.root().display());
    println!("listen: {}", state.listen_addr);
    println!("relay server: {}", state.relay_server);
    println!("bootstrap peers: {}", state.bootstrap_peers.len());
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
                    if let Err(err) = send_room_message(line, store, state).await {
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

/// Ratatui frontend.
///
/// The TUI reuses the same command parser and command handlers as shell mode.
/// Command output is captured into the session log instead of printing directly
/// over the alternate-screen layout.
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
    let mut tui = TuiState::new();
    let output_sink = Arc::new(StdMutex::new(VecDeque::new()));
    let _output_guard = GlobalOutputSinkGuard::install(Arc::clone(&output_sink));

    tui.push_log("dogel.bin v0.1 phase 16 TUI".to_string());
    tui.push_log("type /help, /doctor, /quit; ordinary text sends to active room".to_string());
    tui.push_log("PgUp/PgDn scroll log, Up/Down browse input history".to_string());

    loop {
        tui.drain_output_sink(&output_sink);

        let prompt = if let Some(prompt) = tui.secret_prompt() {
            prompt.to_string()
        } else {
            build_prompt(state).await
        };
        let snapshot = build_tui_snapshot(state).await;

        terminal
            .draw(|frame| {
                render_tui(frame, &snapshot, &tui, &prompt);
            })
            .context("failed to draw TUI frame")?;

        if !event::poll(Duration::from_millis(80)).context("failed to poll terminal events")? {
            continue;
        }

        tui.drain_output_sink(&output_sink);

        let CrosstermEvent::Key(key) = event::read().context("failed to read terminal event")?
        else {
            continue;
        };

        if key.kind != KeyEventKind::Press {
            continue;
        }

        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                tui.push_log("^C ignored; use /quit".to_string());
            }
            KeyCode::Esc => {
                if tui.cancel_secret_flow() {
                    tui.push_log("secret input cancelled".to_string());
                } else {
                    tui.push_log("ESC ignored; use /quit".to_string());
                }
            }
            KeyCode::Backspace => {
                tui.backspace();
            }
            KeyCode::Delete => {
                tui.delete();
            }
            KeyCode::Left => {
                tui.move_cursor_left();
            }
            KeyCode::Right => {
                tui.move_cursor_right();
            }
            KeyCode::Home => {
                tui.input_cursor = 0;
            }
            KeyCode::End => {
                tui.input_cursor = tui.input.len();
            }
            KeyCode::Up => {
                tui.history_prev();
            }
            KeyCode::Down => {
                tui.history_next();
            }
            KeyCode::PageUp => {
                tui.scroll_up();
            }
            KeyCode::PageDown => {
                tui.scroll_down();
            }
            KeyCode::Enter => {
                if tui.secret_flow.is_some() {
                    handle_tui_secret_enter(&mut tui, store, state).await;
                    continue;
                }

                let line = tui.input.trim().to_string();
                tui.commit_input(true);

                if line.is_empty() {
                    continue;
                }

                tui.push_log(format!("> {line}"));

                if !line.starts_with('/') {
                    let (result, lines) =
                        capture_command_output(send_room_message(&line, store, state)).await;
                    tui.push_lines(lines);
                    if let Err(err) = result {
                        tui.push_log(format!("error: {err}"));
                    }
                    continue;
                }

                match parse_command(&line) {
                    Ok(UserCommand::Quit) => {
                        tui.push_log("bye".to_string());
                        break;
                    }
                    Ok(UserCommand::Clear) => {
                        tui.clear_log();
                    }
                    Ok(UserCommand::IdentityCreate { alias }) => {
                        tui.start_secret_flow(TuiSecretFlow::CreateIdentity {
                            alias,
                            first_password: None,
                        });
                    }
                    Ok(UserCommand::Login { alias }) => {
                        if state.active_identity.is_some() {
                            tui.push_log(
                                "error: an identity is already unlocked in this process"
                                    .to_string(),
                            );
                        } else {
                            tui.start_secret_flow(TuiSecretFlow::Login { alias });
                        }
                    }
                    Ok(command) => {
                        run_tui_command(&mut tui, command, store, state).await;
                    }
                    Err(err) => tui.push_log(format!("parse error: {err}")),
                }
            }
            KeyCode::Char(ch) => {
                // Phase 8 policy forbids multiline and bulk paste. TUI input is
                // single-line only by construction; we additionally avoid
                // accepting control-modified characters as text.
                if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT {
                    tui.insert_char(ch);
                }
            }
            _ => {}
        }
    }

    Ok(())
}

async fn run_tui_command(
    tui: &mut TuiState,
    command: UserCommand,
    store: &IdentityStore,
    state: &mut AppState,
) {
    let (result, lines) = capture_command_output(handle_command(command, store, state)).await;
    tui.push_lines(lines);
    if let Err(err) = result {
        tui.push_log(format!("error: {err}"));
    }
}

async fn handle_tui_secret_enter(tui: &mut TuiState, store: &IdentityStore, state: &mut AppState) {
    let Some(flow) = tui.secret_flow.take() else {
        return;
    };

    let secret = tui.take_input(false);
    match flow {
        TuiSecretFlow::CreateIdentity {
            alias,
            first_password: None,
        } => {
            tui.secret_flow = Some(TuiSecretFlow::CreateIdentity {
                alias,
                first_password: Some(secret),
            });
        }
        TuiSecretFlow::CreateIdentity {
            alias,
            first_password: Some(password),
        } => {
            if password != secret {
                tui.push_log("error: passwords do not match".to_string());
                return;
            }

            let (result, lines) =
                capture_command_output(create_identity_with_password(&alias, &password, store))
                    .await;
            tui.push_lines(lines);
            if let Err(err) = result {
                tui.push_log(format!("error: {err}"));
            }
        }
        TuiSecretFlow::Login { alias } => {
            let (result, lines) =
                capture_command_output(login_with_password(&alias, &secret, store, state)).await;
            tui.push_lines(lines);
            if let Err(err) = result {
                tui.push_log(format!("error: {err}"));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TuiSecretFlow {
    CreateIdentity {
        alias: String,
        first_password: Option<String>,
    },
    Login {
        alias: String,
    },
}

struct TuiState {
    input: String,
    input_cursor: usize,
    input_history: Vec<String>,
    history_cursor: Option<usize>,
    log: VecDeque<String>,
    log_scroll: usize,
    secret_flow: Option<TuiSecretFlow>,
}

impl TuiState {
    fn new() -> Self {
        Self {
            input: String::new(),
            input_cursor: 0,
            input_history: Vec::new(),
            history_cursor: None,
            log: VecDeque::new(),
            log_scroll: 0,
            secret_flow: None,
        }
    }

    fn push_log(&mut self, line: String) {
        self.log.push_back(line);
        while self.log.len() > 1000 {
            self.log.pop_front();
        }
        self.log_scroll = 0;
    }

    fn push_lines(&mut self, lines: Vec<String>) {
        for line in lines {
            self.push_log(line);
        }
    }

    fn drain_output_sink(&mut self, sink: &SharedOutputSink) {
        let mut drained = Vec::new();
        if let Ok(mut lines) = sink.lock() {
            while let Some(line) = lines.pop_front() {
                drained.push(line);
            }
        }

        for line in drained {
            self.push_log(line);
        }
    }

    fn clear_log(&mut self) {
        self.log.clear();
        self.log_scroll = 0;
    }

    fn insert_char(&mut self, ch: char) {
        self.input.insert(self.input_cursor, ch);
        self.input_cursor += ch.len_utf8();
        self.history_cursor = None;
    }

    fn backspace(&mut self) {
        if self.input_cursor == 0 {
            return;
        }

        let previous = self.input[..self.input_cursor]
            .char_indices()
            .last()
            .map(|(index, _)| index)
            .unwrap_or(0);
        self.input.replace_range(previous..self.input_cursor, "");
        self.input_cursor = previous;
        self.history_cursor = None;
    }

    fn delete(&mut self) {
        if self.input_cursor >= self.input.len() {
            return;
        }

        let next = self.input[self.input_cursor..]
            .char_indices()
            .nth(1)
            .map(|(offset, _)| self.input_cursor + offset)
            .unwrap_or(self.input.len());
        self.input.replace_range(self.input_cursor..next, "");
        self.history_cursor = None;
    }

    fn move_cursor_left(&mut self) {
        if self.input_cursor == 0 {
            return;
        }
        self.input_cursor = self.input[..self.input_cursor]
            .char_indices()
            .last()
            .map(|(index, _)| index)
            .unwrap_or(0);
    }

    fn move_cursor_right(&mut self) {
        if self.input_cursor >= self.input.len() {
            return;
        }
        self.input_cursor = self.input[self.input_cursor..]
            .char_indices()
            .nth(1)
            .map(|(offset, _)| self.input_cursor + offset)
            .unwrap_or(self.input.len());
    }

    fn take_input(&mut self, record_history: bool) -> String {
        let line = self.input.trim().to_string();
        if record_history && !line.is_empty() && self.input_history.last() != Some(&line) {
            self.input_history.push(line);
            if self.input_history.len() > 200 {
                self.input_history.remove(0);
            }
        }
        let input = std::mem::take(&mut self.input);
        self.input_cursor = 0;
        self.history_cursor = None;
        input
    }

    fn commit_input(&mut self, record_history: bool) {
        let _ = self.take_input(record_history);
    }

    fn start_secret_flow(&mut self, flow: TuiSecretFlow) {
        self.input.clear();
        self.input_cursor = 0;
        self.history_cursor = None;
        self.secret_flow = Some(flow);
    }

    fn cancel_secret_flow(&mut self) -> bool {
        let had_flow = self.secret_flow.take().is_some();
        if had_flow {
            self.input.clear();
            self.input_cursor = 0;
            self.history_cursor = None;
        }
        had_flow
    }

    fn secret_prompt(&self) -> Option<&'static str> {
        match self.secret_flow.as_ref()? {
            TuiSecretFlow::CreateIdentity {
                first_password: None,
                ..
            } => Some("Password: "),
            TuiSecretFlow::CreateIdentity {
                first_password: Some(_),
                ..
            } => Some("Confirm password: "),
            TuiSecretFlow::Login { .. } => Some("Password: "),
        }
    }

    fn history_prev(&mut self) {
        if self.input_history.is_empty() {
            return;
        }

        let next = match self.history_cursor {
            Some(index) => index.saturating_sub(1),
            None => self.input_history.len() - 1,
        };
        self.history_cursor = Some(next);
        self.input = self.input_history[next].clone();
        self.input_cursor = self.input.len();
    }

    fn history_next(&mut self) {
        let Some(index) = self.history_cursor else {
            return;
        };

        if index + 1 >= self.input_history.len() {
            self.history_cursor = None;
            self.input.clear();
            self.input_cursor = 0;
        } else {
            let next = index + 1;
            self.history_cursor = Some(next);
            self.input = self.input_history[next].clone();
            self.input_cursor = self.input.len();
        }
    }

    fn scroll_up(&mut self) {
        self.log_scroll = (self.log_scroll + 8).min(self.log.len().saturating_sub(1));
    }

    fn scroll_down(&mut self) {
        self.log_scroll = self.log_scroll.saturating_sub(8);
    }
}

#[derive(Debug, Clone)]
struct TuiSnapshot {
    alias: String,
    room: String,
    room_count: usize,
    peer_count: usize,
    trust_count: usize,
    invite_count: usize,
    relay_server: bool,
    relay_reservations: usize,
    relayed_addrs: usize,
    bootstrap_peers: usize,
    nat_status: String,
    public_address: String,
    dcutr_events: usize,
    policy: String,
    debug: bool,
}

async fn build_tui_snapshot(state: &AppState) -> TuiSnapshot {
    let alias = state
        .active_identity
        .as_ref()
        .map(|identity| identity.alias.as_str())
        .unwrap_or("no-identity")
        .to_string();

    let (room, room_count) = {
        let rooms = state.rooms.lock().await;
        let room = rooms
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
            .unwrap_or_else(|| "no-room".to_string());
        (room, rooms.rooms.len())
    };

    let (peer_count, relay_reservations, relayed_addrs, nat_status, public_address, dcutr_events) =
        match state.p2p.as_ref() {
            Some(p2p) => match p2p.diagnostics().await {
                Ok(diagnostics) => (
                    diagnostics.connected_peers.len(),
                    diagnostics.relay_reservations.len(),
                    diagnostics.relayed_addrs.len(),
                    diagnostics.nat_status,
                    diagnostics
                        .public_address
                        .as_ref()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    diagnostics.dcutr_events.len(),
                ),
                Err(_) => (0, 0, 0, "unknown".to_string(), "none".to_string(), 0),
            },
            None => (0, 0, 0, "unknown".to_string(), "none".to_string(), 0),
        };

    let trust_count = {
        let trust = state.trust.lock().await;
        trust.observed.len()
    };

    let invite_count = {
        let invites = state.invites.lock().await;
        invites.pending.len()
    };

    TuiSnapshot {
        alias,
        room,
        room_count,
        peer_count,
        trust_count,
        invite_count,
        relay_server: state.relay_server,
        relay_reservations,
        relayed_addrs,
        bootstrap_peers: state.bootstrap_peers.len(),
        nat_status,
        public_address,
        dcutr_events,
        policy: state.message_policy.mode_name().to_string(),
        debug: state.debug_enabled,
    }
}

fn render_tui(
    frame: &mut ratatui::Frame<'_>,
    snapshot: &TuiSnapshot,
    tui: &TuiState,
    prompt: &str,
) {
    let area = frame.size();
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    render_tui_header(frame, root[0], snapshot);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(40), Constraint::Length(32)])
        .split(root[1]);

    render_tui_log(frame, body[0], tui);
    render_tui_sidebar(frame, body[1], snapshot);
    render_tui_input(frame, root[2], prompt, tui);
    render_tui_footer(frame, root[3]);
}

fn render_tui_header(frame: &mut ratatui::Frame<'_>, area: Rect, snapshot: &TuiSnapshot) {
    let title = vec![Line::from(vec![
        Span::styled(
            " dogel.bin ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            &snapshot.alias,
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("  room "),
        Span::styled(&snapshot.room, Style::default().fg(Color::Yellow)),
        Span::raw("  policy "),
        Span::styled(&snapshot.policy, Style::default().fg(Color::Green)),
    ])];

    let header = Paragraph::new(title)
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(header, area);
}

fn render_tui_log(frame: &mut ratatui::Frame<'_>, area: Rect, tui: &TuiState) {
    let visible = area.height.saturating_sub(2) as usize;
    let end = tui.log.len().saturating_sub(tui.log_scroll);
    let start = end.saturating_sub(visible);

    let items: Vec<ListItem> = tui
        .log
        .iter()
        .skip(start)
        .take(end.saturating_sub(start))
        .map(|line| {
            let style = if line.starts_with("error:") || line.starts_with("parse error:") {
                Style::default().fg(Color::Red)
            } else if line.starts_with('>') {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(Span::styled(line.clone(), style)))
        })
        .collect();

    let title = if tui.log_scroll == 0 {
        " session "
    } else {
        " session scrolled "
    };

    let log = List::new(items).block(Block::default().title(title).borders(Borders::ALL));
    frame.render_widget(log, area);
}

fn render_tui_sidebar(frame: &mut ratatui::Frame<'_>, area: Rect, snapshot: &TuiSnapshot) {
    let lines = vec![
        Line::from(vec![Span::styled(
            "Network",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(format!("peers: {}", snapshot.peer_count)),
        Line::from(format!("bootstrap: {}", snapshot.bootstrap_peers)),
        Line::from(format!("relay server: {}", snapshot.relay_server)),
        Line::from(format!("reservations: {}", snapshot.relay_reservations)),
        Line::from(format!("relayed addrs: {}", snapshot.relayed_addrs)),
        Line::from(format!("nat: {}", snapshot.nat_status)),
        Line::from(format!("public: {}", snapshot.public_address)),
        Line::from(format!("dcutr events: {}", snapshot.dcutr_events)),
        Line::from(""),
        Line::from(vec![Span::styled(
            "State",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from(format!("rooms: {}", snapshot.room_count)),
        Line::from(format!("invites: {}", snapshot.invite_count)),
        Line::from(format!("trust: {}", snapshot.trust_count)),
        Line::from(format!("debug: {}", snapshot.debug)),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Commands",
            Style::default().add_modifier(Modifier::BOLD),
        )]),
        Line::from("/login <alias>"),
        Line::from("/whoami"),
        Line::from("/connect <addr>"),
        Line::from("/create-room --ephemeral"),
        Line::from("/invite <peer>"),
        Line::from("/doctor"),
    ];

    let sidebar = Paragraph::new(lines)
        .block(Block::default().title(" status ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(sidebar, area);
}

fn render_tui_input(frame: &mut ratatui::Frame<'_>, area: Rect, prompt: &str, tui: &TuiState) {
    let visible_input = if tui.secret_flow.is_some() {
        "*".repeat(tui.input.chars().count())
    } else {
        tui.input.clone()
    };
    let input_line = format!("{prompt}{visible_input}");
    let input = Paragraph::new(input_line)
        .block(Block::default().title(" input ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    frame.render_widget(input, area);

    let cursor_x = area
        .x
        .saturating_add(1)
        .saturating_add(prompt.len() as u16)
        .saturating_add(tui.input[..tui.input_cursor].chars().count() as u16);
    let cursor_y = area.y.saturating_add(1);
    if cursor_x < area.x.saturating_add(area.width.saturating_sub(1)) {
        frame.set_cursor(cursor_x, cursor_y);
    }
}

fn render_tui_footer(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("Enter", Style::default().fg(Color::Cyan)),
        Span::raw(" send/run  "),
        Span::styled("PgUp/PgDn", Style::default().fg(Color::Cyan)),
        Span::raw(" scroll  "),
        Span::styled("Up/Down", Style::default().fg(Color::Cyan)),
        Span::raw(" history  "),
        Span::styled("/clear", Style::default().fg(Color::Cyan)),
        Span::raw(" clear log"),
    ]));
    frame.render_widget(footer, area);
}

fn release_session_lock_if_needed(store: &IdentityStore, state: &mut AppState) {
    if let Some(alias) = state.session_lock_alias.take() {
        if let Err(err) = store.release_identity_lock(&alias) {
            eprintln!("warning: failed to release identity session lock for {alias}: {err}");
        }
    }
}

async fn create_identity_with_password(
    alias: &str,
    password: &str,
    store: &IdentityStore,
) -> Result<()> {
    validate_new_password(password)?;

    let created = store
        .create_identity(alias, password)
        .with_context(|| format!("failed to create identity '{alias}'"))?;

    println!("created identity:");
    println!("  alias: {}", created.alias);
    println!("  peer_id: {}", created.peer_id);
    println!("  fingerprint: {}", created.fingerprint);
    println!("  path: {}", created.identity_dir.display());
    Ok(())
}

async fn login_with_password(
    alias: &str,
    password: &str,
    store: &IdentityStore,
    state: &mut AppState,
) -> Result<()> {
    if state.active_identity.is_some() {
        anyhow::bail!("an identity is already unlocked in this process");
    }

    let unlocked = store
        .unlock_identity(alias, password)
        .with_context(|| format!("failed to unlock identity '{alias}'"))?;

    // Phase 9 hardening: prevent accidental duplicate use of the same
    // libp2p identity in two local dogel.bin processes. Two live
    // processes with the same PeerId produce confusing handshakes and
    // weaken the operational security model.
    store
        .acquire_identity_lock(&unlocked.alias)
        .with_context(|| {
            format!(
                "failed to acquire session lock for identity '{}'",
                unlocked.alias
            )
        })?;

    println!("unlocked identity:");
    println!("  alias: {}", unlocked.alias);
    println!("  peer_id: {}", unlocked.peer_id);
    println!("  fingerprint: {}", unlocked.fingerprint);

    // Start libp2p only after successful identity unlock. This is
    // important: the network PeerId must be derived from the encrypted
    // identity, not generated freshly every process start.
    let p2p_config = P2pConfig {
        listen_addr: state.listen_addr.clone(),
        bootstrap_peers: state.bootstrap_peers.clone(),
        relay_server: state.relay_server,
        external_addrs: state.external_addrs.clone(),
    };
    let start_result = P2pHandle::start(unlocked.network_keypair.clone(), p2p_config).await;

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
    println!("  relay_server: {}", state.relay_server);
    println!("  bootstrap peers: {}", state.bootstrap_peers.len());
    if !state.bootstrap_peers.is_empty() && !state.relay_server {
        println!("  relay reservations will be requested after bootstrap dial");
    }
    println!("  use /whoami after [p2p] listening appears to copy full multiaddr");

    state.session_lock_alias = Some(unlocked.alias.clone());
    state.p2p = Some(p2p);
    state.active_identity = Some(unlocked);
    Ok(())
}

async fn handle_command(
    command: UserCommand,
    store: &IdentityStore,
    state: &mut AppState,
) -> Result<()> {
    match command {
        UserCommand::IdentityCreate { alias } => {
            let password = prompt_new_password()?;
            create_identity_with_password(&alias, &password, store).await?;
        }

        UserCommand::Login { alias } => {
            let password =
                rpassword::prompt_password("Password: ").context("failed to read password")?;
            login_with_password(&alias, &password, store, state).await?;
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
                let diagnostics = p2p.diagnostics().await?;
                let public_address = diagnostics
                    .public_address
                    .as_ref()
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "none".to_string());
                println!("nat: {}", diagnostics.nat_status);
                println!("public address: {}", public_address);
                println!("dcutr events: {}", diagnostics.dcutr_events.len());

                if diagnostics.listen_addrs.is_empty() {
                    println!("  swarm started, but no listen address is confirmed yet");
                } else {
                    for addr in diagnostics.listen_addrs {
                        println!(
                            "  {}",
                            addr.with(libp2p::multiaddr::Protocol::P2p(p2p.local_peer_id()))
                        );
                    }
                }

                if diagnostics.relayed_addrs.is_empty() {
                    println!("relayed listen:");
                    println!("  none");
                } else {
                    println!("relayed listen:");
                    for addr in diagnostics.relayed_addrs {
                        println!("  {addr}");
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
            let room_key =
                derive_room_key(&room_id, &secret).context("failed to derive Argon2id room key")?;
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
                room_seed: None,
                key_fingerprint: key_fingerprint.clone(),
                ephemeral,
                history_enabled: false,
                members,
                membership: None,
                replay_cache: ReplayCache::default(),
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
            let room_key =
                derive_room_key(&room_id, &secret).context("failed to derive Argon2id room key")?;
            let key_fingerprint = room_key_fingerprint(&room_key);

            let mut rooms = state.rooms.lock().await;

            if rooms.rooms.contains_key(&room_id) {
                let (
                    existing_ephemeral,
                    existing_history_enabled,
                    existing_key_fingerprint,
                    member_count,
                ) = {
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
                room_seed: None,
                key_fingerprint: key_fingerprint.clone(),
                ephemeral,
                history_enabled: false,
                members,
                membership: None,
                replay_cache: ReplayCache::default(),
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

            let room_id = room_id.unwrap_or_else(generate_invite_room_id);
            validate_room_id(&room_id)?;

            let room_seed = generate_random_room_key();
            let self_peer = p2p.local_peer_id();

            let mut members = HashSet::new();
            members.insert(self_peer);
            let membership = build_membership_state(
                identity,
                &room_id,
                canonical_peer_list(members.iter().map(|peer| peer.to_string())),
            )?;
            let room_key =
                derive_bound_room_key(&room_id, &membership.peers, &room_seed, PROTOCOL_VERSION);
            let key_fingerprint = room_key_fingerprint(&room_key);

            let mut rooms = state.rooms.lock().await;
            if rooms.rooms.contains_key(&room_id) {
                anyhow::bail!("room {room_id} already exists");
            }

            let session = RoomSession {
                room_id: room_id.clone(),
                room_key,
                room_seed: Some(room_seed),
                key_fingerprint: key_fingerprint.clone(),
                ephemeral,
                history_enabled: false,
                members,
                membership: Some(membership),
                replay_cache: ReplayCache::default(),
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
            send_room_message(&text, store, state).await?;
        }

        UserCommand::History { enabled } => {
            let Some(identity) = state.active_identity.as_ref() else {
                println!("error: no active identity");
                println!();
                println!("hint:");
                println!("  /login <alias>");
                return Ok(());
            };

            let (active_room, room_snapshot) = {
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
                (active_room, room.clone())
            };

            println!("room {active_room} history_enabled={enabled}");
            if enabled {
                let history_count = room_history_count(store, &room_snapshot, identity).await?;
                println!("stored history entries: {history_count}");
                print_room_history_preview(store, &room_snapshot, identity, 20).await?;
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
async fn send_room_message(text: &str, store: &IdentityStore, state: &mut AppState) -> Result<()> {
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

    let (envelope, plain) = build_signed_envelope(identity, &room, text)?;

    for peer in &targets {
        p2p.send_envelope(*peer, envelope.clone()).await?;
    }

    if let Err(err) = record_room_history(
        store,
        &room,
        &identity.alias,
        RoomHistoryDirection::Outbound,
        &plain.message_id,
        &identity.peer_id,
        &identity.alias,
        &plain.body,
        plain.timestamp_ms,
    )
    .await
    {
        println!("[history] warning: failed to persist outbound message: {err}");
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
) -> Result<(SignedEncryptedEnvelope, PlainMessage)> {
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
        version: PROTOCOL_VERSION,
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

    Ok((envelope, plain))
}

/// Build a signed online room invite for one connected peer.
///
/// Phase 10 invites are not persisted and not offline-deliverable. They carry a
/// random room key over the existing libp2p secure channel, signed by the
/// sender's Ed25519 message identity.
fn build_room_invite(identity: &UnlockedIdentity, room: &RoomSession) -> Result<RoomInvite> {
    let timestamp_ms = now_ms();
    let signing_public_key = identity.signing_key.verifying_key().to_bytes();
    let Some(membership) = room.membership.clone() else {
        anyhow::bail!("legacy /join rooms cannot be invited in Phase 12; create a hardened room with /create-room");
    };
    let Some(room_seed) = room.room_seed else {
        anyhow::bail!("hardened room is missing its room seed");
    };

    let mut invite = RoomInvite {
        version: PROTOCOL_VERSION,
        invite_id: generate_message_id(),
        room_id: room.room_id.clone(),
        room_key_b64: BASE64.encode(room_seed),
        ephemeral: room.ephemeral,
        membership,
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

fn build_membership_state(
    identity: &UnlockedIdentity,
    room_id: &str,
    peers: Vec<String>,
) -> Result<RoomMembershipState> {
    let signing_public_key = identity.signing_key.verifying_key().to_bytes();
    let mut membership = RoomMembershipState {
        version: PROTOCOL_VERSION,
        room_id: room_id.to_string(),
        creator_peer_id: identity.peer_id.clone(),
        creator_signing_public_key_b64: BASE64.encode(signing_public_key),
        peers: canonical_peer_list(peers),
        membership_signature_b64: String::new(),
    };

    let payload = membership
        .signing_payload()
        .context("failed to build membership signing payload")?;
    let signature = sign_bytes(&identity.signing_key, &payload);
    membership.membership_signature_b64 = BASE64.encode(signature);

    Ok(membership)
}

fn verify_membership_state(membership: &RoomMembershipState) -> Result<()> {
    require_protocol_version(membership.version)?;

    if membership.room_id.is_empty() || membership.room_id.len() > 64 {
        anyhow::bail!("invalid membership room id");
    }

    if membership.peers.is_empty() {
        anyhow::bail!("membership has no peers");
    }

    if membership.peers != canonical_peer_list(membership.peers.clone()) {
        anyhow::bail!("membership peers must be sorted and deduplicated");
    }

    if !membership.peers.contains(&membership.creator_peer_id) {
        anyhow::bail!("membership does not include creator peer");
    }

    let creator_public_key = BASE64
        .decode(&membership.creator_signing_public_key_b64)
        .context("invalid membership creator signing public key base64")?;
    let signature = BASE64
        .decode(&membership.membership_signature_b64)
        .context("invalid membership signature base64")?;
    let payload = membership
        .signing_payload()
        .context("failed to build membership signing payload")?;

    verify_signature(&creator_public_key, &payload, &signature)
        .context("invalid membership signature")?;

    Ok(())
}

async fn record_room_history(
    store: &IdentityStore,
    room: &RoomSession,
    identity_alias: &str,
    direction: RoomHistoryDirection,
    message_id: &str,
    peer_id: &str,
    alias: &str,
    body: &str,
    timestamp_ms: u64,
) -> Result<()> {
    if !room.history_enabled || room.ephemeral {
        return Ok(());
    }

    let entry = RoomHistoryEntry {
        version: PROTOCOL_VERSION,
        room_id: room.room_id.clone(),
        message_id: message_id.to_string(),
        direction,
        peer_id: peer_id.to_string(),
        alias: alias.to_string(),
        timestamp_ms,
        body: body.to_string(),
    };

    store
        .append_room_history(identity_alias, &room.room_id, &room.room_key, &entry)
        .context("failed to append encrypted room history")?;

    Ok(())
}

async fn load_room_history(
    store: &IdentityStore,
    room: &RoomSession,
    identity: &UnlockedIdentity,
) -> Result<Vec<RoomHistoryEntry>> {
    store
        .load_room_history(&identity.alias, &room.room_id, &room.room_key)
        .context("failed to load encrypted room history")
}

fn format_history_direction(direction: RoomHistoryDirection) -> &'static str {
    match direction {
        RoomHistoryDirection::Inbound => "<-",
        RoomHistoryDirection::Outbound => "->",
    }
}

async fn print_room_history_preview(
    store: &IdentityStore,
    room: &RoomSession,
    identity: &UnlockedIdentity,
    limit: usize,
) -> Result<()> {
    let history = load_room_history(store, room, identity).await?;

    if history.is_empty() {
        println!("history: none");
        return Ok(());
    }

    println!("history entries: {}", history.len());

    for entry in history.iter().rev().take(limit).rev() {
        println!(
            "  [{}] {} {} [{}]: {}",
            entry.room_id,
            format_history_direction(entry.direction),
            entry.alias,
            entry.message_id,
            entry.body
        );
    }

    Ok(())
}

async fn room_history_count(
    store: &IdentityStore,
    room: &RoomSession,
    identity: &UnlockedIdentity,
) -> Result<usize> {
    Ok(load_room_history(store, room, identity).await?.len())
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

        if room.membership.is_some() && room.room_seed.is_some() {
            if room
                .membership
                .as_ref()
                .map(|membership| membership.creator_peer_id.as_str())
                != Some(identity.peer_id.as_str())
            {
                anyhow::bail!("only the room creator can update signed membership in Phase 12");
            }
        }

        room.members.insert(peer);

        if let Some(room_seed) = room.room_seed {
            let membership = build_membership_state(
                identity,
                &room.room_id,
                canonical_peer_list(room.members.iter().map(|peer| peer.to_string())),
            )?;
            room.room_key = derive_bound_room_key(
                &room.room_id,
                &membership.peers,
                &room_seed,
                PROTOCOL_VERSION,
            );
            room.key_fingerprint = room_key_fingerprint(&room.room_key);
            room.membership = Some(membership);
        }

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
        println!(
            "    from: {} [{}]",
            invite.sender_alias, invite.sender_fingerprint
        );
        println!("    peer_id: {}", invite.sender_peer_id);
        println!("    ephemeral: {}", invite.ephemeral);
        println!("    received_at_ms: {}", invite.received_at_ms);
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
    if !invite.membership.peers.contains(&self_peer.to_string()) {
        anyhow::bail!(
            "signed membership for room {} does not include this peer",
            invite.room_id
        );
    }

    let mut members = HashSet::new();
    for peer in &invite.membership.peers {
        let parsed: PeerId = peer
            .parse()
            .with_context(|| format!("invalid peer id in membership: {peer}"))?;
        members.insert(parsed);
    }

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

            existing.members = members.clone();
            existing.room_key = invite.room_key;
            existing.room_seed = Some(invite.room_seed);
            existing.membership = Some(invite.membership.clone());
            existing.key_fingerprint = invite.key_fingerprint.clone();
            existing.members.len()
        };

        rooms.active_room = Some(invite.room_id.clone());

        println!("accepted invite: {}", invite.invite_id);
        println!("active room: {}", invite.room_id);
        println!(
            "from: {} [{}]",
            invite.sender_alias, invite.sender_fingerprint
        );
        println!("members: {}", member_count);
        return Ok(());
    }

    let session = RoomSession {
        room_id: invite.room_id.clone(),
        room_key: invite.room_key,
        room_seed: Some(invite.room_seed),
        key_fingerprint: invite.key_fingerprint.clone(),
        ephemeral: invite.ephemeral,
        history_enabled: false,
        members,
        membership: Some(invite.membership.clone()),
        replay_cache: ReplayCache::default(),
    };

    rooms.rooms.insert(invite.room_id.clone(), session);
    rooms.active_room = Some(invite.room_id.clone());

    println!("accepted invite: {}", invite.invite_id);
    println!("active room: {}", invite.room_id);
    println!(
        "from: {} [{}]",
        invite.sender_alias, invite.sender_fingerprint
    );
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
                P2pEvent::Log { line } => {
                    println!("{line}");
                }
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
    require_protocol_version(invite.version)?;

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
    verify_membership_state(&invite.membership)?;

    if invite.membership.room_id != invite.room_id {
        anyhow::bail!(
            "invite room id '{}' does not match membership room id '{}'",
            invite.room_id,
            invite.membership.room_id
        );
    }

    if !invite.membership.peers.contains(&peer_id.to_string()) {
        anyhow::bail!("signed membership does not include invite sender");
    }

    if invite.sender_peer_id != invite.membership.creator_peer_id {
        anyhow::bail!("Phase 12 invites must be sent by the signed room creator");
    }

    if invite.sender_signing_public_key_b64 != invite.membership.creator_signing_public_key_b64 {
        anyhow::bail!("invite signing key does not match membership creator key");
    }

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

    let room_seed_bytes = BASE64
        .decode(&invite.room_key_b64)
        .context("invalid invite room seed base64")?;

    if room_seed_bytes.len() != 32 {
        anyhow::bail!(
            "invalid invite room seed length: expected 32 bytes, got {}",
            room_seed_bytes.len()
        );
    }

    let mut room_seed = [0u8; 32];
    room_seed.copy_from_slice(&room_seed_bytes);
    let room_key = derive_bound_room_key(
        &invite.room_id,
        &invite.membership.peers,
        &room_seed,
        PROTOCOL_VERSION,
    );

    let fingerprint = fingerprint_from_public_key(&signing_public_key);
    let trust_status =
        observe_and_classify_invite_peer(peer_id, &invite, &fingerprint, trust, store).await?;

    let pending = PendingInvite {
        invite_id: invite.invite_id.clone(),
        room_id: invite.room_id.clone(),
        room_key,
        room_seed,
        key_fingerprint: room_key_fingerprint(&room_key),
        ephemeral: invite.ephemeral,
        membership: invite.membership.clone(),
        sender_alias: invite.sender_alias.clone(),
        sender_peer_id: peer_id,
        sender_fingerprint: fingerprint.clone(),
        received_at_ms: now_ms(),
    };

    {
        let mut invites = invites.lock().await;
        invites
            .pending
            .insert(pending.invite_id.clone(), pending.clone());
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
            println!(
                "hint: verify fingerprint out-of-band, then run /trust {}",
                peer_id
            );
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
    require_protocol_version(envelope.version)?;

    let (room_key, room_snapshot) = {
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

        (room.room_key, room.clone())
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

    let plaintext = decrypt_room_message(&room_key, &nonce, &ciphertext)
        .context("message decryption failed")?;
    let plain: PlainMessage =
        serde_json::from_slice(&plaintext).context("failed to deserialize plaintext message")?;

    if plain.room_id != envelope.room_id {
        anyhow::bail!(
            "inner room id '{}' does not match outer room id '{}'",
            plain.room_id,
            envelope.room_id
        );
    }

    if !is_valid_message_id(&plain.message_id) {
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

        if !room.replay_cache.insert(replay_key) {
            anyhow::bail!(
                "replayed message rejected from peer {} in room '{}'",
                peer_id,
                envelope.room_id
            );
        }
    }

    if room_snapshot.history_enabled {
        let local_identity_alias = {
            let trust = trust.lock().await;
            trust.identity_alias.clone()
        };

        if let Some(local_identity_alias) = local_identity_alias {
            let peer_id_string = peer_id.to_string();
            if let Err(err) = record_room_history(
                store,
                &room_snapshot,
                &local_identity_alias,
                RoomHistoryDirection::Inbound,
                &plain.message_id,
                &peer_id_string,
                &envelope.sender_alias,
                &plain.body,
                plain.timestamp_ms,
            )
            .await
            {
                println!("[history] warning: failed to persist inbound message: {err}");
            }
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
            println!(
                "hint: verify fingerprint out-of-band, then run /trust {}",
                peer_id
            );
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
        anyhow::bail!(
            "message rejected by local policy\n\nreason:\n  empty messages are not allowed"
        );
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
            '"' | '\''
                | '`'
                | '<'
                | '>'
                | '('
                | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | ','
                | ';'
                | ':'
                | '!'
                | '?'
        )
    });

    let trimmed = trimmed.trim_end_matches('.');
    let lower = trimmed.to_ascii_lowercase();

    if lower.is_empty() {
        return false;
    }

    if lower.starts_with("http://") || lower.starts_with("https://") || lower.starts_with("www.") {
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
        if policy.reject_links {
            "rejected"
        } else {
            "allowed"
        }
    );
    println!(
        "  multiline: {}",
        if policy.reject_multiline {
            "rejected"
        } else {
            "allowed"
        }
    );
    println!(
        "  control chars: {}",
        if policy.reject_control_chars {
            "rejected"
        } else {
            "allowed"
        }
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
            println!(
                "  path: {}",
                store.trusted_peers_path(&identity.alias).display()
            );
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
    parse_startup_config_from(std::env::args().skip(1))
}

fn parse_startup_config_from<I, S>(args: I) -> Result<StartupConfig>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let mut listen = DEFAULT_LISTEN_ADDR.to_string();
    let mut bootstraps = Vec::new();
    let mut external_addrs = Vec::new();
    let mut relay_server = false;
    let mut tui = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                let Some(value) = args.next() else {
                    anyhow::bail!("--listen requires a multiaddr value");
                };
                listen = value;
            }
            "--bootstrap" => {
                let Some(value) = args.next() else {
                    anyhow::bail!("--bootstrap requires a full multiaddr value");
                };
                let addr: Multiaddr = value
                    .parse()
                    .with_context(|| format!("invalid bootstrap multiaddr: {value}"))?;
                if !addr
                    .iter()
                    .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::P2p(_)))
                {
                    anyhow::bail!("--bootstrap multiaddr must include /p2p/<peer_id>: {value}");
                }
                bootstraps.push(addr);
            }
            "--relay-server" => {
                relay_server = true;
            }
            "--external-addr" => {
                let Some(value) = args.next() else {
                    anyhow::bail!("--external-addr requires a multiaddr value");
                };
                let addr: Multiaddr = value
                    .parse()
                    .with_context(|| format!("invalid external multiaddr: {value}"))?;
                external_addrs.push(addr);
            }
            "--tui" => {
                tui = true;
            }
            "--help" | "-h" => {
                println!("usage:");
                println!("  dogel.bin [--listen <multiaddr>] [--bootstrap <multiaddr>] [--relay-server] [--external-addr <multiaddr>] [--tui]");
                println!();
                println!("examples:");
                println!("  dogel.bin --listen /ip4/0.0.0.0/tcp/7777");
                println!("  dogel.bin --tui --listen /ip4/0.0.0.0/tcp/7778");
                println!("  dogel.bin --relay-server --listen /ip4/0.0.0.0/tcp/7777 --external-addr /ip4/<public-ip>/tcp/7777");
                println!("  dogel.bin --bootstrap /ip4/<relay-host>/tcp/7777/p2p/<relay-peer-id>");
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

    Ok(StartupConfig {
        listen_addr,
        bootstrap_peers: bootstraps,
        relay_server,
        external_addrs,
        tui,
    })
}

fn prompt_new_password() -> Result<String> {
    let password = rpassword::prompt_password("Password: ").context("failed to read password")?;
    let confirm = rpassword::prompt_password("Confirm password: ")
        .context("failed to read password confirmation")?;

    if password != confirm {
        anyhow::bail!("passwords do not match");
    }

    validate_new_password(&password)?;

    Ok(password)
}

fn validate_new_password(password: &str) -> Result<()> {
    if password.len() < 8 {
        anyhow::bail!("password must be at least 8 characters long");
    }
    Ok(())
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
        anyhow::bail!("room id may contain only ASCII letters, numbers, '-', '_' and '.'");
    }

    Ok(())
}

fn is_valid_message_id(message_id: &str) -> bool {
    message_id.len() == 32 && message_id.chars().all(|ch| ch.is_ascii_hexdigit())
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
        let diagnostics = p2p.diagnostics().await?;
        let peers = diagnostics.connected_peers.clone();
        let addrs = diagnostics.listen_addrs.clone();
        let public_address = diagnostics
            .public_address
            .as_ref()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "none".to_string());

        println!("  local_peer_id: {}", p2p.local_peer_id());
        println!("  nat: {}", diagnostics.nat_status);
        println!("  public address: {}", public_address);
        println!("  dcutr events: {}", diagnostics.dcutr_events.len());
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
    let active_room = {
        let rooms = state.rooms.lock().await;
        rooms
            .active_room
            .as_ref()
            .and_then(|room_id| rooms.rooms.get(room_id))
            .cloned()
    };

    if let Some(room) = active_room {
        println!("  room_id: {}", room.room_id);
        println!("  ephemeral: {}", room.ephemeral);
        println!("  history: {}", room.history_enabled);
        println!("  members: {}", room.members.len());
        println!("  key fingerprint: {}", room.key_fingerprint);
        if room.history_enabled {
            if let Some(identity) = state.active_identity.as_ref() {
                match room_history_count(store, &room, identity).await {
                    Ok(count) => println!("  stored history entries: {}", count),
                    Err(err) => println!("  stored history entries: unavailable ({err})"),
                }
            }
        }
    } else {
        println!("  none");
    }

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
        let diagnostics = p2p.diagnostics().await?;
        let public_address = diagnostics
            .public_address
            .as_ref()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "none".to_string());
        lines.push("  p2p: running".to_string());
        lines.push(format!("  local_peer_id: {}", p2p.local_peer_id()));
        lines.push(format!(
            "  connected peers: {}",
            diagnostics.connected_peers.len()
        ));
        lines.push(format!("  nat status: {}", diagnostics.nat_status));
        lines.push(format!("  public address: {}", public_address));
        lines.push(format!(
            "  dcutr events: {}",
            diagnostics.dcutr_events.len()
        ));
        lines.push(format!(
            "  confirmed listen addresses: {}",
            diagnostics.listen_addrs.len()
        ));
        lines.push(format!("  relay server: {}", diagnostics.relay_server));
        lines.push(format!(
            "  bootstrap peers: {}",
            diagnostics.bootstrap_peers.len()
        ));
        lines.push(format!(
            "  relay reservations: {}",
            diagnostics.relay_reservations.len()
        ));
        lines.push(format!(
            "  relayed listen addresses: {}",
            diagnostics.relayed_addrs.len()
        ));
        lines.push(format!(
            "  external addresses: {}",
            diagnostics.external_addrs.len()
        ));
        if !diagnostics.relay_reservation_errors.is_empty() {
            lines.push("  relay reservation errors:".to_string());
            for err in diagnostics.relay_reservation_errors {
                lines.push(format!("    {err}"));
            }
        }
    } else {
        lines.push("  p2p: not-started".to_string());
        lines.push(format!("  relay server: {}", state.relay_server));
        lines.push(format!(
            "  bootstrap peers: {}",
            state.bootstrap_peers.len()
        ));
        lines.push(format!(
            "  external addresses: {}",
            state.external_addrs.len()
        ));
        lines.push("  nat status: unknown".to_string());
        lines.push("  public address: none".to_string());
        lines.push("  dcutr events: 0".to_string());
    }

    let (room_count, active_room) = {
        let rooms = state.rooms.lock().await;
        (
            rooms.rooms.len(),
            rooms
                .active_room
                .as_ref()
                .and_then(|room_id| rooms.rooms.get(room_id))
                .cloned(),
        )
    };

    lines.push("rooms:".to_string());
    lines.push(format!("  total: {}", room_count));
    match active_room {
        Some(room) => {
            lines.push(format!("  active: {}", room.room_id));
            lines.push(format!("  ephemeral: {}", room.ephemeral));
            lines.push(format!("  history: {}", room.history_enabled));
            lines.push(format!("  members: {}", room.members.len()));
            lines.push(format!("  replay cache: {}", room.replay_cache.len()));
            if room.history_enabled {
                if let Some(identity) = state.active_identity.as_ref() {
                    match room_history_count(store, &room, identity).await {
                        Ok(count) => lines.push(format!("  stored history entries: {}", count)),
                        Err(err) => {
                            lines.push(format!("  stored history entries: unavailable ({err})"))
                        }
                    }
                }
            }
        }
        None => lines.push("  active: none".to_string()),
    }

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
    lines.push(format!(
        "  links rejected: {}",
        state.message_policy.reject_links
    ));
    lines.push(format!(
        "  multiline rejected: {}",
        state.message_policy.reject_multiline
    ));
    lines.push(format!(
        "  rate limit: {} messages / {}s",
        state.message_policy.max_messages_per_window,
        state.message_policy.window.as_secs()
    ));

    lines.push("runtime:".to_string());
    lines.push(format!(
        "  debug: {}",
        if state.debug_enabled { "on" } else { "off" }
    ));

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
    println!("  dogel.bin [--listen <multiaddr>] [--bootstrap <multiaddr>] [--relay-server] [--external-addr <multiaddr>] [--tui]");
    println!();
    println!("generic examples:");
    println!("  /login <alias>");
    println!("  /whoami");
    println!("  /connect /ip4/<host>/tcp/<port>/p2p/<peer_id>");
    println!("  dogel.bin --relay-server --listen /ip4/0.0.0.0/tcp/7777 --external-addr /ip4/<public-ip>/tcp/7777");
    println!("  dogel.bin --bootstrap /ip4/<relay-host>/tcp/7777/p2p/<relay-peer-id>");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_128_bit_hex_message_ids() {
        assert!(is_valid_message_id("0123456789ABCDEF0123456789ABCDEF"));
        assert!(is_valid_message_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_message_id(""));
        assert!(!is_valid_message_id("0123456789ABCDEF"));
        assert!(!is_valid_message_id("0123456789ABCDEF0123456789ABCDEG"));
    }

    #[test]
    fn replay_cache_rejects_duplicates_and_evicts_oldest() {
        let mut cache = ReplayCache {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity: 2,
        };

        assert!(cache.insert("a".to_string()));
        assert!(!cache.insert("a".to_string()));
        assert!(cache.insert("b".to_string()));
        assert!(cache.insert("c".to_string()));

        assert_eq!(cache.len(), 2);
        assert!(cache.insert("a".to_string()));
    }

    #[test]
    fn parses_phase13_startup_network_flags() {
        let relay_peer = PeerId::random();
        let bootstrap = format!("/ip4/127.0.0.1/tcp/7777/p2p/{relay_peer}");

        let config = parse_startup_config_from([
            "--listen",
            "/ip4/0.0.0.0/tcp/7778",
            "--bootstrap",
            bootstrap.as_str(),
            "--relay-server",
            "--external-addr",
            "/ip4/203.0.113.10/tcp/7777",
            "--tui",
        ])
        .expect("phase 13 startup flags should parse");

        assert_eq!(config.listen_addr.to_string(), "/ip4/0.0.0.0/tcp/7778");
        assert_eq!(config.bootstrap_peers.len(), 1);
        assert_eq!(config.bootstrap_peers[0].to_string(), bootstrap);
        assert!(config.relay_server);
        assert_eq!(config.external_addrs.len(), 1);
        assert!(config.tui);
    }

    #[test]
    fn rejects_bootstrap_without_peer_id() {
        let err =
            parse_startup_config_from(["--bootstrap", "/ip4/127.0.0.1/tcp/7777"]).unwrap_err();
        assert!(err.to_string().contains("must include /p2p/<peer_id>"));
    }

    #[test]
    fn tui_create_identity_secret_flow_reaches_confirmation() {
        let mut tui = TuiState::new();
        tui.start_secret_flow(TuiSecretFlow::CreateIdentity {
            alias: "alice".to_string(),
            first_password: None,
        });

        assert_eq!(tui.secret_prompt(), Some("Password: "));
        tui.input = "supersecret".to_string();
        tui.input_cursor = tui.input.len();
        let password = tui.take_input(false);
        tui.secret_flow = Some(TuiSecretFlow::CreateIdentity {
            alias: "alice".to_string(),
            first_password: Some(password),
        });

        assert_eq!(tui.secret_prompt(), Some("Confirm password: "));
        assert!(tui.input.is_empty());
        assert!(tui.input_history.is_empty());
    }

    #[test]
    fn tui_login_secret_flow_clears_secret_without_history() {
        let mut tui = TuiState::new();
        tui.start_secret_flow(TuiSecretFlow::Login {
            alias: "alice".to_string(),
        });

        assert_eq!(tui.secret_prompt(), Some("Password: "));
        tui.input = "supersecret".to_string();
        tui.input_cursor = tui.input.len();
        assert_eq!(tui.take_input(false), "supersecret");
        assert!(tui.input.is_empty());
        assert!(tui.input_history.is_empty());
    }

    #[tokio::test]
    async fn captures_command_output_lines() {
        let (value, lines) = capture_command_output(async {
            println!("one");
            println!();
            println!("two");
            7
        })
        .await;

        assert_eq!(value, 7);
        assert_eq!(lines, vec!["one", "", "two"]);
    }
}
