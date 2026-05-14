//! Minimal libp2p runtime for dogel.bin.
//!
//! This crate deliberately exposes an actor-like API instead of leaking `Swarm`
//! into the CLI. The CLI sends high-level commands such as "dial this multiaddr"
//! or "send this encrypted envelope"; the background task owns the libp2p event
//! loop.
//!
//! Phase 4/5 adds a tiny request-response protocol for encrypted chat envelopes.
//! The libp2p transport is responsible only for moving already-encrypted bytes
//! between peers. It does not know room keys and cannot decrypt chat messages.

use eve_protocol::{
    DiscoveryRequest, DiscoveryResponse, DogelRequest, DogelResponse, PeerAdvertisement,
    RoomInvite, SignedEncryptedEnvelope,
};
use futures::StreamExt;
use libp2p::{
    autonat, dcutr, identify, noise, ping, relay, request_response,
    request_response::{
        json, Message as RequestResponseMessage, OutboundRequestId, ProtocolSupport,
    },
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
};
use libp2p_identity::Keypair;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

/// Errors returned by the P2P actor boundary.
#[derive(Debug, Error)]
pub enum P2pError {
    #[error("failed to configure noise transport: {0}")]
    Noise(String),

    #[error("failed to listen on {addr}: {source}")]
    Listen {
        addr: Multiaddr,
        source: libp2p::TransportError<std::io::Error>,
    },

    #[error("p2p runtime is not running")]
    RuntimeClosed,

    #[error("p2p runtime dropped a response")]
    ResponseDropped,

    #[error("invalid multiaddr: {0}")]
    InvalidMultiaddr(String),

    #[error("invalid peer id: {0}")]
    InvalidPeerId(String),

    #[error("multiaddr must include /p2p/<peer_id>: {0}")]
    MissingPeerId(String),
}

/// Phase 13 network configuration.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub listen_addr: Multiaddr,
    pub bootstrap_peers: Vec<Multiaddr>,
    pub relay_server: bool,
    pub external_addrs: Vec<Multiaddr>,
    pub identity_alias: Option<String>,
}

impl P2pConfig {
    pub fn lan_only(listen_addr: Multiaddr) -> Self {
        Self {
            listen_addr,
            bootstrap_peers: Vec::new(),
            relay_server: false,
            external_addrs: Vec::new(),
            identity_alias: None,
        }
    }
}

/// Result of resolving a peer through the bootstrap directory.
#[derive(Debug, Clone)]
pub struct DiscoveryResolution {
    pub query: String,
    pub found: bool,
    pub advertisement: Option<PeerAdvertisement>,
    pub reason: Option<String>,
}

/// Snapshot returned to the CLI for `/doctor` and `/whoami` style diagnostics.
#[derive(Debug, Clone)]
pub struct P2pDiagnostics {
    pub connected_peers: Vec<PeerId>,
    pub listen_addrs: Vec<Multiaddr>,
    pub bootstrap_peers: Vec<Multiaddr>,
    pub bootstrap_connected: bool,
    pub bootstrap_last_error: Option<String>,
    pub relay_server: bool,
    pub relay_reservation_active: bool,
    pub relay_last_error: Option<String>,
    pub relay_reservations: Vec<PeerId>,
    pub relay_reservation_errors: Vec<String>,
    pub external_addrs: Vec<Multiaddr>,
    pub relayed_addrs: Vec<Multiaddr>,
    pub nat_status: String,
    pub nat_confidence: usize,
    pub nat_last_error: Option<String>,
    pub public_address: Option<Multiaddr>,
    pub dcutr_events: Vec<String>,
    pub discovery_registered: bool,
    pub discovery_registered_alias: Option<String>,
    pub discovery_expires_at_ms: Option<u64>,
    pub discovery_last_error: Option<String>,
    pub usable_route: String,
}

/// Events emitted by the P2P runtime to the CLI/application layer.
///
/// The CLI owns room keys and identity metadata, so inbound encrypted envelopes
/// are forwarded upward instead of decrypted here.
#[derive(Debug, Clone)]
pub enum P2pEvent {
    Log {
        line: String,
    },
    PeerConnected {
        peer_id: PeerId,
    },
    PeerDisconnected {
        peer_id: PeerId,
    },
    InboundEnvelope {
        peer_id: PeerId,
        envelope: SignedEncryptedEnvelope,
    },
    InboundInvite {
        peer_id: PeerId,
        invite: RoomInvite,
    },
}

/// Handle used by the CLI to interact with the background libp2p task.
#[derive(Debug, Clone)]
pub struct P2pHandle {
    local_peer_id: PeerId,
    command_tx: mpsc::Sender<P2pCommand>,
}

impl P2pHandle {
    /// Start the libp2p swarm in a background Tokio task.
    ///
    /// The network keypair must come from the unlocked local identity. That is
    /// what makes the displayed `peer_id` stable across restarts.
    pub async fn start(
        network_keypair: Keypair,
        config: P2pConfig,
    ) -> Result<(Self, mpsc::Receiver<P2pEvent>), P2pError> {
        let local_peer_id = PeerId::from(network_keypair.public());
        let public_key = network_keypair.public();

        let swarm_config = libp2p::swarm::Config::with_tokio_executor()
            // Keep LAN test connections around even when idle. Once the custom
            // messaging protocol is active, substreams will be opened on demand,
            // but the long timeout still makes manual CLI debugging friendlier.
            .with_idle_connection_timeout(Duration::from_secs(24 * 60 * 60));

        let mut swarm = SwarmBuilder::with_existing_identity(network_keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|err| P2pError::Noise(err.to_string()))?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|err| P2pError::Noise(err.to_string()))?
            .with_behaviour(|_, relay_client| DogelBehaviour {
                autonat: {
                    let mut config = autonat::Config::default();
                    config.use_connected = true;
                    autonat::Behaviour::new(local_peer_id, config)
                },
                dcutr: dcutr::Behaviour::new(local_peer_id),
                ping: ping::Behaviour::new(ping::Config::new()),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/dogel/0.1".to_string(),
                    public_key,
                )),
                messaging: json::Behaviour::<DogelRequest, DogelResponse>::new(
                    [(
                        StreamProtocol::new("/dogel/message/1"),
                        ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                ),
                discovery: json::Behaviour::<DiscoveryRequest, DiscoveryResponse>::new(
                    [(
                        StreamProtocol::new("/dogel/discovery/1"),
                        ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                ),
                relay_client,
                relay_server: relay::Behaviour::new(local_peer_id, relay::Config::default()),
            })
            .expect("dogel behaviour construction is infallible")
            .with_swarm_config(|_| swarm_config)
            .build();

        Swarm::listen_on(&mut swarm, config.listen_addr.clone()).map_err(|source| {
            P2pError::Listen {
                addr: config.listen_addr.clone(),
                source,
            }
        })?;

        for addr in &config.external_addrs {
            Swarm::add_external_address(&mut swarm, addr.clone());
        }

        let (command_tx, command_rx) = mpsc::channel(64);
        let (event_tx, event_rx) = mpsc::channel(128);

        tokio::spawn(async move {
            run_swarm(swarm, config, command_rx, event_tx).await;
        });

        Ok((
            Self {
                local_peer_id,
                command_tx,
            },
            event_rx,
        ))
    }

    /// Return the local peer id owned by this runtime.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Dial a remote peer by full multiaddr.
    ///
    /// v0.1 requires `/p2p/<peer_id>` in the address so the user explicitly
    /// connects to the expected identity instead of a naked IP:port.
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), P2pError> {
        let peer_id = peer_id_from_multiaddr(&addr)
            .ok_or_else(|| P2pError::MissingPeerId(addr.to_string()))?;

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(P2pCommand::Dial {
                addr,
                peer_id,
                reply: tx,
            })
            .await
            .map_err(|_| P2pError::RuntimeClosed)?;

        rx.await.map_err(|_| P2pError::ResponseDropped)?
    }

    /// Send an encrypted signed envelope to one connected peer.
    ///
    /// The envelope is already encrypted and signed by the CLI/application
    /// layer. P2P transport never sees plaintext.
    pub async fn send_envelope(
        &self,
        peer_id: PeerId,
        envelope: SignedEncryptedEnvelope,
    ) -> Result<(), P2pError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(P2pCommand::SendEnvelope {
                peer_id,
                envelope,
                reply: tx,
            })
            .await
            .map_err(|_| P2pError::RuntimeClosed)?;

        rx.await.map_err(|_| P2pError::ResponseDropped)?
    }

    /// Send an online room invite to one connected peer.
    ///
    /// The invite is signed by the application layer. In Phase 10 its room key is
    /// confidential because it travels over the direct libp2p Noise channel.
    pub async fn send_invite(&self, peer_id: PeerId, invite: RoomInvite) -> Result<(), P2pError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(P2pCommand::SendInvite {
                peer_id,
                invite,
                reply: tx,
            })
            .await
            .map_err(|_| P2pError::RuntimeClosed)?;

        rx.await.map_err(|_| P2pError::ResponseDropped)?
    }

    /// Snapshot of currently connected peers.
    pub async fn connected_peers(&self) -> Result<Vec<PeerId>, P2pError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(P2pCommand::ConnectedPeers { reply: tx })
            .await
            .map_err(|_| P2pError::RuntimeClosed)?;

        rx.await.map_err(|_| P2pError::ResponseDropped)
    }

    /// Snapshot of current listen addresses.
    pub async fn listen_addrs(&self) -> Result<Vec<Multiaddr>, P2pError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(P2pCommand::ListenAddrs { reply: tx })
            .await
            .map_err(|_| P2pError::RuntimeClosed)?;

        rx.await.map_err(|_| P2pError::ResponseDropped)
    }

    /// Snapshot of Phase 13 networking state.
    pub async fn diagnostics(&self) -> Result<P2pDiagnostics, P2pError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(P2pCommand::Diagnostics { reply: tx })
            .await
            .map_err(|_| P2pError::RuntimeClosed)?;

        rx.await.map_err(|_| P2pError::ResponseDropped)
    }

    /// Resolve a peer id or alias through the bootstrap directory.
    pub async fn resolve_peer(&self, query: String) -> Result<DiscoveryResolution, P2pError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(P2pCommand::ResolvePeer { query, reply: tx })
            .await
            .map_err(|_| P2pError::RuntimeClosed)?;

        rx.await.map_err(|_| P2pError::ResponseDropped)
    }

    /// List peer advertisements known to the bootstrap directory.
    pub async fn list_peers(&self) -> Result<Vec<PeerAdvertisement>, P2pError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(P2pCommand::ListPeers { reply: tx })
            .await
            .map_err(|_| P2pError::RuntimeClosed)?;

        rx.await.map_err(|_| P2pError::ResponseDropped)
    }
}

enum P2pCommand {
    Dial {
        addr: Multiaddr,
        peer_id: PeerId,
        reply: oneshot::Sender<Result<(), P2pError>>,
    },
    SendEnvelope {
        peer_id: PeerId,
        envelope: SignedEncryptedEnvelope,
        reply: oneshot::Sender<Result<(), P2pError>>,
    },
    SendInvite {
        peer_id: PeerId,
        invite: RoomInvite,
        reply: oneshot::Sender<Result<(), P2pError>>,
    },
    ConnectedPeers {
        reply: oneshot::Sender<Vec<PeerId>>,
    },
    ListenAddrs {
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    Diagnostics {
        reply: oneshot::Sender<P2pDiagnostics>,
    },
    ResolvePeer {
        query: String,
        reply: oneshot::Sender<DiscoveryResolution>,
    },
    ListPeers {
        reply: oneshot::Sender<Vec<PeerAdvertisement>>,
    },
}

#[derive(Debug, Default)]
struct DiscoveryDirectory {
    by_peer_id: HashMap<String, PeerAdvertisement>,
    alias_to_peer_id: HashMap<String, String>,
}

impl DiscoveryDirectory {
    fn cleanup_expired(&mut self, now_ms: u64) {
        let expired: Vec<String> = self
            .by_peer_id
            .iter()
            .filter(|(_, advert)| advert.expires_at_ms <= now_ms)
            .map(|(peer_id, _)| peer_id.clone())
            .collect();

        for peer_id in expired {
            self.remove_peer(&peer_id);
        }
    }

    fn remove_peer(&mut self, peer_id: &str) {
        if let Some(advert) = self.by_peer_id.remove(peer_id) {
            if let Some(alias) = advert.alias {
                let remove_alias = self
                    .alias_to_peer_id
                    .get(&alias)
                    .map(|existing| existing == peer_id)
                    .unwrap_or(false);
                if remove_alias {
                    self.alias_to_peer_id.remove(&alias);
                }
            }
        }
    }

    fn register(&mut self, advert: PeerAdvertisement) -> Result<(), String> {
        if advert.peer_id.trim().is_empty() {
            return Err("peer id cannot be empty".to_string());
        }

        if let Some(alias) = advert.alias.as_ref() {
            if alias.trim().is_empty() {
                return Err("alias cannot be empty".to_string());
            }
        }

        if let Some(alias) = advert.alias.as_ref() {
            if let Some(existing_peer_id) = self.alias_to_peer_id.get(alias) {
                if existing_peer_id != &advert.peer_id {
                    return Err(format!("alias conflict for '{alias}'"));
                }
            }
        }

        if let Some(old) = self
            .by_peer_id
            .insert(advert.peer_id.clone(), advert.clone())
        {
            if let Some(alias) = old.alias {
                if self
                    .alias_to_peer_id
                    .get(&alias)
                    .map(|existing| existing == &advert.peer_id)
                    .unwrap_or(false)
                {
                    self.alias_to_peer_id.remove(&alias);
                }
            }
        }

        if let Some(alias) = advert.alias.clone() {
            self.alias_to_peer_id.insert(alias, advert.peer_id.clone());
        }

        Ok(())
    }

    fn resolve(&mut self, query: &str, now_ms: u64) -> DiscoveryResolution {
        self.cleanup_expired(now_ms);

        if let Some(advert) = self.by_peer_id.get(query).cloned() {
            return DiscoveryResolution {
                query: query.to_string(),
                found: true,
                advertisement: Some(advert),
                reason: None,
            };
        }

        if let Some(peer_id) = self.alias_to_peer_id.get(query).cloned() {
            if let Some(advert) = self.by_peer_id.get(&peer_id).cloned() {
                return DiscoveryResolution {
                    query: query.to_string(),
                    found: true,
                    advertisement: Some(advert),
                    reason: None,
                };
            }
        }

        DiscoveryResolution {
            query: query.to_string(),
            found: false,
            advertisement: None,
            reason: Some(format!(
                "peer not found: no active advertisement for {query}"
            )),
        }
    }

    fn list(&mut self, now_ms: u64) -> Vec<PeerAdvertisement> {
        self.cleanup_expired(now_ms);
        let mut peers: Vec<_> = self.by_peer_id.values().cloned().collect();
        peers.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
        peers
    }
}

#[derive(Debug)]
enum PendingDiscovery {
    Resolve {
        query: String,
        reply: oneshot::Sender<DiscoveryResolution>,
    },
    List(oneshot::Sender<Vec<PeerAdvertisement>>),
    Register {
        alias: Option<String>,
        expires_at_ms: u64,
    },
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn nat_status_label(status: &autonat::NatStatus) -> String {
    match status {
        autonat::NatStatus::Public(addr) => format!("Public({addr})"),
        autonat::NatStatus::Private => "Private".to_string(),
        autonat::NatStatus::Unknown => "Unknown".to_string(),
    }
}

fn attach_peer_id(addr: Multiaddr, peer_id: PeerId) -> Multiaddr {
    addr.with(libp2p::multiaddr::Protocol::P2p(peer_id))
}

fn dedup_and_sort_addrs(mut addrs: Vec<String>) -> Vec<String> {
    addrs.sort();
    addrs.dedup();
    addrs
}

fn build_local_peer_advertisement(
    swarm: &Swarm<DogelBehaviour>,
    config: &P2pConfig,
    relay_reservations: &HashSet<PeerId>,
    nat_status: String,
) -> PeerAdvertisement {
    let local_peer_id = *swarm.local_peer_id();
    let mut direct_addrs: Vec<String> = Swarm::listeners(swarm)
        .cloned()
        .map(|addr| attach_peer_id(addr, local_peer_id).to_string())
        .collect();
    direct_addrs.extend(
        Swarm::external_addresses(swarm)
            .cloned()
            .map(|addr| attach_peer_id(addr, local_peer_id).to_string()),
    );

    let reservations: Vec<_> = relay_reservations.iter().copied().collect();
    let relayed_addrs: Vec<String> =
        build_relayed_addrs(&config.bootstrap_peers, &reservations, local_peer_id)
            .into_iter()
            .map(|addr| addr.to_string())
            .collect();

    let observed_at_ms = now_ms();
    PeerAdvertisement {
        peer_id: local_peer_id.to_string(),
        alias: config.identity_alias.clone(),
        direct_addrs: dedup_and_sort_addrs(direct_addrs),
        relayed_addrs: dedup_and_sort_addrs(relayed_addrs),
        nat_status,
        observed_at_ms,
        expires_at_ms: observed_at_ms + 120_000,
    }
}

fn usable_route_for_diagnostics(
    nat_status: &str,
    relay_reservation_active: bool,
    direct_available: bool,
) -> String {
    if direct_available {
        "direct".to_string()
    } else if relay_reservation_active {
        "relay".to_string()
    } else if nat_status.contains("Public") {
        "direct".to_string()
    } else {
        "none".to_string()
    }
}

fn bootstrap_peer_ids_from_addrs(addrs: &[Multiaddr]) -> HashSet<PeerId> {
    addrs.iter().filter_map(peer_id_from_multiaddr).collect()
}

fn connected_bootstrap_peers(
    connected: &HashSet<PeerId>,
    bootstrap_peer_ids: &HashSet<PeerId>,
) -> Vec<PeerId> {
    let mut peers: Vec<_> = connected
        .iter()
        .filter(|peer_id| bootstrap_peer_ids.contains(peer_id))
        .copied()
        .collect();
    peers.sort_by_key(|peer| peer.to_string());
    peers
}

async fn publish_discovery_advertisement(
    swarm: &mut Swarm<DogelBehaviour>,
    config: &P2pConfig,
    relay_reservations: &HashSet<PeerId>,
    discovery_directory: &mut DiscoveryDirectory,
    bootstrap_peer_ids: &HashSet<PeerId>,
    connected: &HashSet<PeerId>,
    pending_discovery: &mut HashMap<OutboundRequestId, PendingDiscovery>,
    event_tx: &mpsc::Sender<P2pEvent>,
    discovery_registered: &mut bool,
    discovery_registered_alias: &mut Option<String>,
    discovery_expires_at_ms: &mut Option<u64>,
    discovery_last_error: &mut Option<String>,
) {
    let nat_status = {
        let behaviour = swarm.behaviour_mut();
        nat_status_label(&behaviour.autonat.nat_status())
    };
    let advert = build_local_peer_advertisement(swarm, config, relay_reservations, nat_status);
    let now = now_ms();

    if config.relay_server {
        match discovery_directory.register(advert.clone()) {
            Ok(()) => {
                *discovery_registered = true;
                *discovery_registered_alias = advert.alias.clone();
                *discovery_expires_at_ms = Some(advert.expires_at_ms);
                *discovery_last_error = None;
                emit_log(
                    event_tx,
                    format!(
                        "[p2p] discovery directory updated locally: {}",
                        advert.peer_id
                    ),
                )
                .await;
            }
            Err(err) => {
                *discovery_last_error = Some(err.clone());
                emit_log(
                    event_tx,
                    format!("[p2p] discovery directory update failed: {err}"),
                )
                .await;
            }
        }
    }

    let targets = connected_bootstrap_peers(connected, bootstrap_peer_ids);
    if targets.is_empty() {
        if !config.relay_server {
            *discovery_registered = false;
            *discovery_last_error = Some("no bootstrap peers connected".to_string());
        }
        return;
    }

    for peer_id in targets {
        let request_id = swarm
            .behaviour_mut()
            .discovery
            .send_request(&peer_id, DiscoveryRequest::RegisterPeer(advert.clone()));
        pending_discovery.insert(
            request_id,
            PendingDiscovery::Register {
                alias: advert.alias.clone(),
                expires_at_ms: advert.expires_at_ms,
            },
        );
        *discovery_expires_at_ms = Some(advert.expires_at_ms);
        *discovery_registered_alias = advert.alias.clone();
        *discovery_last_error = None;
        emit_log(
            event_tx,
            format!("[p2p] discovery registration sent to {peer_id} at {now}"),
        )
        .await;
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "DogelBehaviourEvent")]
struct DogelBehaviour {
    autonat: autonat::Behaviour,
    dcutr: dcutr::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    messaging: json::Behaviour<DogelRequest, DogelResponse>,
    discovery: json::Behaviour<DiscoveryRequest, DiscoveryResponse>,
    relay_client: relay::client::Behaviour,
    relay_server: relay::Behaviour,
}

/// Event enum generated target for the `NetworkBehaviour` derive.
#[allow(clippy::large_enum_variant)]
enum DogelBehaviourEvent {
    AutoNat(autonat::Event),
    Dcutr(dcutr::Event),
    Ping(ping::Event),
    Identify(identify::Event),
    Messaging(request_response::Event<DogelRequest, DogelResponse>),
    Discovery(request_response::Event<DiscoveryRequest, DiscoveryResponse>),
    RelayClient(relay::client::Event),
    RelayServer(relay::Event),
}

impl From<autonat::Event> for DogelBehaviourEvent {
    fn from(event: autonat::Event) -> Self {
        Self::AutoNat(event)
    }
}

impl From<dcutr::Event> for DogelBehaviourEvent {
    fn from(event: dcutr::Event) -> Self {
        Self::Dcutr(event)
    }
}

impl From<ping::Event> for DogelBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<identify::Event> for DogelBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<request_response::Event<DogelRequest, DogelResponse>> for DogelBehaviourEvent {
    fn from(event: request_response::Event<DogelRequest, DogelResponse>) -> Self {
        Self::Messaging(event)
    }
}

impl From<request_response::Event<DiscoveryRequest, DiscoveryResponse>> for DogelBehaviourEvent {
    fn from(event: request_response::Event<DiscoveryRequest, DiscoveryResponse>) -> Self {
        Self::Discovery(event)
    }
}

impl From<relay::client::Event> for DogelBehaviourEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::RelayClient(event)
    }
}

impl From<relay::Event> for DogelBehaviourEvent {
    fn from(event: relay::Event) -> Self {
        Self::RelayServer(event)
    }
}

async fn run_swarm(
    mut swarm: Swarm<DogelBehaviour>,
    config: P2pConfig,
    mut command_rx: mpsc::Receiver<P2pCommand>,
    event_tx: mpsc::Sender<P2pEvent>,
) {
    let mut connected: HashSet<PeerId> = HashSet::new();
    let mut relay_reservations: HashSet<PeerId> = HashSet::new();
    let mut relay_reservation_errors: Vec<String> = Vec::new();
    let mut dcutr_events: VecDeque<String> = VecDeque::new();
    let mut discovery_directory = DiscoveryDirectory::default();
    let mut pending_discovery: HashMap<OutboundRequestId, PendingDiscovery> = HashMap::new();
    let bootstrap_peer_ids = bootstrap_peer_ids_from_addrs(&config.bootstrap_peers);
    let mut bootstrap_last_error: Option<String> = None;
    let mut relay_last_error: Option<String> = None;
    let mut nat_last_error: Option<String> = None;
    let mut discovery_registered = false;
    let mut discovery_registered_alias = config.identity_alias.clone();
    let mut discovery_expires_at_ms: Option<u64> = None;
    let mut discovery_last_error: Option<String> = None;
    let mut discovery_refresh = tokio::time::interval(Duration::from_secs(30));
    discovery_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    for bootstrap in &config.bootstrap_peers {
        let Some(peer_id) = peer_id_from_multiaddr(bootstrap) else {
            emit_log(
                &event_tx,
                format!("[p2p] bootstrap skipped; missing /p2p/<peer_id>: {bootstrap}"),
            )
            .await;
            continue;
        };

        match Swarm::dial(&mut swarm, bootstrap.clone()) {
            Ok(()) => {
                emit_log(
                    &event_tx,
                    format!("[p2p] bootstrap dial started: {bootstrap}"),
                )
                .await;
                if !config.relay_server {
                    let relay_addr = bootstrap
                        .clone()
                        .with(libp2p::multiaddr::Protocol::P2pCircuit);
                    match Swarm::listen_on(&mut swarm, relay_addr.clone()) {
                        Ok(_) => {
                            emit_log(
                                &event_tx,
                                format!("[p2p] relay reservation requested: {relay_addr}"),
                            )
                            .await
                        }
                        Err(err) => {
                            let message = format!(
                                "relay reservation listen failed for {peer_id} via {relay_addr}: {err}"
                            );
                            relay_last_error = Some(message.clone());
                            emit_log(&event_tx, format!("[p2p] {message}")).await;
                            relay_reservation_errors.push(message);
                        }
                    }
                }
            }
            Err(err) => {
                bootstrap_last_error = Some(format!("bootstrap dial failed: {bootstrap}: {err}"));
                emit_log(
                    &event_tx,
                    format!("[p2p] bootstrap dial failed: {bootstrap}: {err}"),
                )
                .await;
            }
        }
    }

    if config.relay_server {
        publish_discovery_advertisement(
            &mut swarm,
            &config,
            &relay_reservations,
            &mut discovery_directory,
            &bootstrap_peer_ids,
            &connected,
            &mut pending_discovery,
            &event_tx,
            &mut discovery_registered,
            &mut discovery_registered_alias,
            &mut discovery_expires_at_ms,
            &mut discovery_last_error,
        )
        .await;
    }

    // libp2p's SwarmEvent API differs a bit across minor versions. Some
    // versions expose `remaining_established` in ConnectionClosed, others do
    // not. Keep our own lightweight connection counter so this crate builds
    // without depending on that specific event field.
    let mut connection_counts: HashMap<PeerId, usize> = HashMap::new();

    loop {
        tokio::select! {
            _ = discovery_refresh.tick() => {
                publish_discovery_advertisement(
                    &mut swarm,
                    &config,
                    &relay_reservations,
                    &mut discovery_directory,
                    &bootstrap_peer_ids,
                    &connected,
                    &mut pending_discovery,
                    &event_tx,
                    &mut discovery_registered,
                    &mut discovery_registered_alias,
                    &mut discovery_expires_at_ms,
                    &mut discovery_last_error,
                )
                .await;
            }
            maybe_command = command_rx.recv() => {
                let Some(command) = maybe_command else {
                    break;
                };

                match command {
                    P2pCommand::Dial { addr, peer_id, reply } => {
                        // Dial the full user-provided multiaddr directly. Phase 3+
                        // requires `/p2p/<peer_id>` in the address so libp2p can
                        // verify that the remote endpoint is the expected peer.
                        let _ = peer_id;

                        let result = Swarm::dial(&mut swarm, addr)
                            .map_err(|err| P2pError::InvalidMultiaddr(err.to_string()));

                        let _ = reply.send(result);
                    }
                    P2pCommand::SendEnvelope { peer_id, envelope, reply } => {
                        // `send_request` opens a new substream on the existing
                        // connection. It returns immediately after scheduling
                        // the outbound request; success/failure details arrive
                        // later as request-response events.
                        swarm
                            .behaviour_mut()
                            .messaging
                            .send_request(&peer_id, DogelRequest::Envelope(envelope));

                        let _ = reply.send(Ok(()));
                    }
                    P2pCommand::SendInvite { peer_id, invite, reply } => {
                        swarm
                            .behaviour_mut()
                            .messaging
                            .send_request(&peer_id, DogelRequest::Invite(invite));

                        let _ = reply.send(Ok(()));
                    }
                    P2pCommand::ConnectedPeers { reply } => {
                        let mut peers: Vec<_> = connected.iter().copied().collect();
                        peers.sort_by_key(|peer| peer.to_string());
                        let _ = reply.send(peers);
                    }
                    P2pCommand::ResolvePeer { query, reply } => {
                        if config.relay_server {
                            let resolution = discovery_directory.resolve(&query, now_ms());
                            let _ = reply.send(resolution);
                            continue;
                        }

                        let targets = connected_bootstrap_peers(&connected, &bootstrap_peer_ids);
                        if let Some(peer_id) = targets.first().copied() {
                            let request_id = swarm.behaviour_mut().discovery.send_request(
                                &peer_id,
                                DiscoveryRequest::ResolvePeer {
                                    query: query.clone(),
                                },
                            );
                            pending_discovery.insert(
                                request_id,
                                PendingDiscovery::Resolve {
                                    query: query.clone(),
                                    reply,
                                },
                            );
                            continue;
                        }

                        let _ = reply.send(DiscoveryResolution {
                            query: query.clone(),
                            found: false,
                            advertisement: None,
                            reason: Some("no bootstrap/discovery peer configured".to_string()),
                        });
                    }
                    P2pCommand::ListPeers { reply } => {
                        if config.relay_server {
                            let peers = discovery_directory.list(now_ms());
                            let _ = reply.send(peers);
                            continue;
                        }

                        let targets = connected_bootstrap_peers(&connected, &bootstrap_peer_ids);
                        if let Some(peer_id) = targets.first().copied() {
                            let request_id =
                                swarm.behaviour_mut().discovery.send_request(&peer_id, DiscoveryRequest::ListPeers);
                            pending_discovery.insert(request_id, PendingDiscovery::List(reply));
                            continue;
                        }

                        let _ = reply.send(Vec::new());
                    }
                    P2pCommand::ListenAddrs { reply } => {
                        let addrs: Vec<_> = Swarm::listeners(&swarm).cloned().collect();
                        let _ = reply.send(addrs);
                    }
                    P2pCommand::Diagnostics { reply } => {
                        let mut peers: Vec<_> = connected.iter().copied().collect();
                        peers.sort_by_key(|peer| peer.to_string());

                        let mut reservations: Vec<_> =
                            relay_reservations.iter().copied().collect();
                        reservations.sort_by_key(|peer| peer.to_string());

                        let listen_addrs: Vec<_> = Swarm::listeners(&swarm).cloned().collect();
                        let external_addrs: Vec<_> =
                            Swarm::external_addresses(&swarm).cloned().collect();
                        let relayed_addrs = build_relayed_addrs(
                            &config.bootstrap_peers,
                            &reservations,
                            *swarm.local_peer_id(),
                        );
                        let behaviour = swarm.behaviour_mut();
                        let nat_status = nat_status_label(&behaviour.autonat.nat_status());
                        let nat_confidence = behaviour.autonat.confidence();
                        let public_address = behaviour.autonat.public_address().cloned();
                        let direct_available = !listen_addrs.is_empty() || !external_addrs.is_empty();
                        let relay_reservation_active = !reservations.is_empty();
                        let bootstrap_connected = !connected_bootstrap_peers(
                            &connected,
                            &bootstrap_peer_ids,
                        )
                        .is_empty();
                        let usable_route = usable_route_for_diagnostics(
                            &nat_status,
                            relay_reservation_active,
                            direct_available,
                        );

                        let _ = reply.send(P2pDiagnostics {
                            connected_peers: peers,
                            listen_addrs,
                            bootstrap_peers: config.bootstrap_peers.clone(),
                            bootstrap_connected,
                            bootstrap_last_error: bootstrap_last_error.clone(),
                            relay_server: config.relay_server,
                            relay_reservation_active,
                            relay_last_error: relay_last_error.clone(),
                            relay_reservations: reservations,
                            relay_reservation_errors: relay_reservation_errors.clone(),
                            external_addrs,
                            relayed_addrs,
                            nat_status,
                            nat_confidence,
                            nat_last_error: nat_last_error.clone(),
                            public_address,
                            dcutr_events: dcutr_events.iter().cloned().collect(),
                            discovery_registered,
                            discovery_registered_alias: discovery_registered_alias.clone(),
                            discovery_expires_at_ms,
                            discovery_last_error: discovery_last_error.clone(),
                            usable_route,
                        });
                    }
                }
            }

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let full = address.clone().with(libp2p::multiaddr::Protocol::P2p(*swarm.local_peer_id()));
                        emit_log(&event_tx, format!("[p2p] listening on {full}")).await;
                    }
                    SwarmEvent::ListenerClosed { addresses, reason, .. } => {
                        if let Err(err) = reason {
                            let message = format!(
                                "listener closed with error: addresses={addresses:?} error={err}"
                            );
                            relay_last_error = Some(message.clone());
                            emit_log(&event_tx, format!("[p2p] {message}")).await;
                            relay_reservation_errors.push(message);
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        let count = connection_counts.entry(peer_id).or_insert(0);
                        *count += 1;

                        let was_new_peer = connected.insert(peer_id);
                        if bootstrap_peer_ids.contains(&peer_id) {
                            bootstrap_last_error = None;
                            publish_discovery_advertisement(
                                &mut swarm,
                                &config,
                                &relay_reservations,
                                &mut discovery_directory,
                                &bootstrap_peer_ids,
                                &connected,
                                &mut pending_discovery,
                                &event_tx,
                                &mut discovery_registered,
                                &mut discovery_registered_alias,
                                &mut discovery_expires_at_ms,
                                &mut discovery_last_error,
                            )
                            .await;
                        }

                        if was_new_peer {
                            emit_log(&event_tx, format!("[p2p] connected: {peer_id}")).await;
                            let _ = event_tx
                                .send(P2pEvent::PeerConnected { peer_id })
                                .await;
                        } else {
                            emit_log(
                                &event_tx,
                                format!("[p2p] additional connection established: {peer_id}"),
                            )
                            .await;
                        }
                        emit_log(&event_tx, format!("[p2p] endpoint: {endpoint:?}")).await;
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        if bootstrap_peer_ids.contains(&peer_id) {
                            bootstrap_last_error = Some(format!("bootstrap peer disconnected: {peer_id}"));
                        }

                        if let Some(count) = connection_counts.get_mut(&peer_id) {
                            *count = count.saturating_sub(1);

                            if *count == 0 {
                                connection_counts.remove(&peer_id);
                                connected.remove(&peer_id);

                                emit_log(&event_tx, format!("[p2p] disconnected: {peer_id}")).await;
                                let _ = event_tx
                                    .send(P2pEvent::PeerDisconnected { peer_id })
                                    .await;
                            }
                        } else {
                            // Defensive fallback: if libp2p reports a close for
                            // a peer we did not count, remove it from the public
                            // connected set anyway. This keeps `/peers` honest.
                            connected.remove(&peer_id);

                            emit_log(&event_tx, format!("[p2p] disconnected: {peer_id}")).await;
                            let _ = event_tx
                                .send(P2pEvent::PeerDisconnected { peer_id })
                                .await;
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        if let Some(peer_id) = peer_id {
                            if bootstrap_peer_ids.contains(&peer_id) {
                                bootstrap_last_error = Some(format!(
                                    "bootstrap dial failed for {peer_id}: {error}"
                                ));
                            }
                        }
                        emit_log(
                            &event_tx,
                            format!("[p2p] outgoing connection error: peer={peer_id:?} error={error}"),
                        )
                        .await;
                    }
                    SwarmEvent::IncomingConnectionError { error, .. } => {
                        emit_log(&event_tx, format!("[p2p] incoming connection error: {error}")).await;
                    }
                    SwarmEvent::Behaviour(DogelBehaviourEvent::Messaging(event)) => {
                        handle_messaging_event(event, &event_tx, swarm.behaviour_mut()).await;
                    }
                    SwarmEvent::Behaviour(DogelBehaviourEvent::Discovery(event)) => {
                        handle_discovery_event(
                            event,
                            swarm.behaviour_mut(),
                            &mut discovery_directory,
                            &mut pending_discovery,
                            &event_tx,
                            &config,
                            &mut discovery_registered,
                            &mut discovery_last_error,
                        )
                        .await;
                    }
                    SwarmEvent::Behaviour(DogelBehaviourEvent::AutoNat(event)) => {
                        match event {
                            autonat::Event::StatusChanged { old, new } => {
                                emit_log(
                                    &event_tx,
                                    format!("[p2p] autonat status changed: {old:?} -> {new:?}"),
                                )
                                .await;
                            }
                            autonat::Event::OutboundProbe(autonat::OutboundProbeEvent::Error { error, .. }) => {
                                nat_last_error = Some(format!("{error:?}"));
                                emit_log(
                                    &event_tx,
                                    format!("[p2p] autonat outbound probe error: {error:?}"),
                                )
                                .await;
                            }
                            autonat::Event::InboundProbe(autonat::InboundProbeEvent::Error { error, .. }) => {
                                nat_last_error = Some(format!("{error:?}"));
                                emit_log(
                                    &event_tx,
                                    format!("[p2p] autonat inbound probe error: {error:?}"),
                                )
                                .await;
                            }
                            other => {
                                emit_log(&event_tx, format!("[p2p] autonat event: {other:?}"))
                                    .await;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(DogelBehaviourEvent::Dcutr(event)) => {
                        let message = format!(
                            "[p2p] dcutr event: remote_peer_id={} result={:?}",
                            event.remote_peer_id, event.result
                        );
                        dcutr_events.push_back(message.clone());
                        while dcutr_events.len() > 16 {
                            dcutr_events.pop_front();
                        }
                        emit_log(&event_tx, message).await;
                    }
                    SwarmEvent::Behaviour(DogelBehaviourEvent::Ping(event)) => {
                        // Useful during development but too noisy to print every time.
                        let _ = event;
                    }
                    SwarmEvent::Behaviour(DogelBehaviourEvent::Identify(event)) => {
                        handle_identify_event(event, &mut swarm, config.relay_server);
                    }
                    SwarmEvent::Behaviour(DogelBehaviourEvent::RelayClient(event)) => {
                        handle_relay_client_event(
                            event,
                            &mut relay_reservations,
                            &event_tx,
                        ).await;
                        publish_discovery_advertisement(
                            &mut swarm,
                            &config,
                            &relay_reservations,
                            &mut discovery_directory,
                            &bootstrap_peer_ids,
                            &connected,
                            &mut pending_discovery,
                            &event_tx,
                            &mut discovery_registered,
                            &mut discovery_registered_alias,
                            &mut discovery_expires_at_ms,
                            &mut discovery_last_error,
                        )
                        .await;
                    }
                    SwarmEvent::Behaviour(DogelBehaviourEvent::RelayServer(event)) => {
                        if config.relay_server {
                            emit_log(&event_tx, format!("[p2p] relay server event: {event:?}")).await;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn emit_log(event_tx: &mpsc::Sender<P2pEvent>, line: String) {
    let _ = event_tx.send(P2pEvent::Log { line }).await;
}

fn handle_identify_event(
    event: identify::Event,
    swarm: &mut Swarm<DogelBehaviour>,
    relay_server: bool,
) {
    if let identify::Event::Received { peer_id, info, .. } = event {
        let observed_addr = info.observed_addr.clone();
        if relay_server {
            Swarm::add_external_address(swarm, observed_addr.clone());
        }

        if !info.listen_addrs.is_empty() {
            let addr = info
                .listen_addrs
                .first()
                .cloned()
                .or_else(|| Some(observed_addr));
            swarm.behaviour_mut().autonat.add_server(peer_id, addr);
        }
    }
}

async fn handle_relay_client_event(
    event: relay::client::Event,
    relay_reservations: &mut HashSet<PeerId>,
    event_tx: &mpsc::Sender<P2pEvent>,
) {
    match event {
        relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } => {
            relay_reservations.insert(relay_peer_id);
            emit_log(
                event_tx,
                format!("[p2p] relay reservation accepted: {relay_peer_id}"),
            )
            .await;
        }
        other => {
            emit_log(event_tx, format!("[p2p] relay client event: {other:?}")).await;
        }
    }
}

async fn handle_discovery_event(
    event: request_response::Event<DiscoveryRequest, DiscoveryResponse>,
    behaviour: &mut DogelBehaviour,
    discovery_directory: &mut DiscoveryDirectory,
    pending_discovery: &mut HashMap<OutboundRequestId, PendingDiscovery>,
    event_tx: &mpsc::Sender<P2pEvent>,
    config: &P2pConfig,
    discovery_registered: &mut bool,
    discovery_last_error: &mut Option<String>,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => match message {
            RequestResponseMessage::Request {
                request, channel, ..
            } => match request {
                DiscoveryRequest::RegisterPeer(advert) => {
                    if config.relay_server {
                        match discovery_directory.register(advert.clone()) {
                            Ok(()) => {
                                *discovery_registered = true;
                                *discovery_last_error = None;
                                emit_log(
                                    event_tx,
                                    format!(
                                        "[p2p] discovery register accepted from {peer}: {}",
                                        advert.peer_id
                                    ),
                                )
                                .await;
                                let _ = behaviour.discovery.send_response(
                                    channel,
                                    DiscoveryResponse::Ack {
                                        ok: true,
                                        error: None,
                                    },
                                );
                            }
                            Err(err) => {
                                *discovery_last_error = Some(err.clone());
                                emit_log(
                                    event_tx,
                                    format!("[p2p] discovery register rejected from {peer}: {err}"),
                                )
                                .await;
                                let _ = behaviour.discovery.send_response(
                                    channel,
                                    DiscoveryResponse::Ack {
                                        ok: false,
                                        error: Some(err),
                                    },
                                );
                            }
                        }
                    } else {
                        let err = "peer is not a bootstrap directory".to_string();
                        *discovery_last_error = Some(err.clone());
                        let _ = behaviour.discovery.send_response(
                            channel,
                            DiscoveryResponse::Ack {
                                ok: false,
                                error: Some(err),
                            },
                        );
                    }
                }
                DiscoveryRequest::ResolvePeer { query } => {
                    if config.relay_server {
                        let resolution = discovery_directory.resolve(&query, now_ms());
                        let _ = behaviour.discovery.send_response(
                            channel,
                            DiscoveryResponse::ResolvePeerResponse {
                                found: resolution.found,
                                advertisement: resolution.advertisement,
                                reason: resolution.reason,
                            },
                        );
                    } else {
                        let err = "peer is not a bootstrap directory".to_string();
                        let _ = behaviour.discovery.send_response(
                            channel,
                            DiscoveryResponse::ResolvePeerResponse {
                                found: false,
                                advertisement: None,
                                reason: Some(err),
                            },
                        );
                    }
                }
                DiscoveryRequest::ListPeers => {
                    if config.relay_server {
                        let peers = discovery_directory.list(now_ms());
                        let _ = behaviour
                            .discovery
                            .send_response(channel, DiscoveryResponse::ListPeersResponse { peers });
                    } else {
                        let _ = behaviour.discovery.send_response(
                            channel,
                            DiscoveryResponse::ListPeersResponse { peers: Vec::new() },
                        );
                    }
                }
            },
            RequestResponseMessage::Response {
                response,
                request_id,
            } => match pending_discovery.remove(&request_id) {
                Some(PendingDiscovery::Resolve { query, reply }) => {
                    let resolution = match response {
                        DiscoveryResponse::ResolvePeerResponse {
                            found,
                            advertisement,
                            reason,
                        } => DiscoveryResolution {
                            query,
                            found,
                            advertisement,
                            reason,
                        },
                        other => DiscoveryResolution {
                            query,
                            found: false,
                            advertisement: None,
                            reason: Some(format!("unexpected discovery response: {other:?}")),
                        },
                    };
                    let _ = reply.send(resolution);
                }
                Some(PendingDiscovery::List(reply)) => {
                    let peers = match response {
                        DiscoveryResponse::ListPeersResponse { peers } => peers,
                        other => {
                            emit_log(
                                event_tx,
                                format!("[p2p] unexpected discovery list response: {other:?}"),
                            )
                            .await;
                            Vec::new()
                        }
                    };
                    let _ = reply.send(peers);
                }
                Some(PendingDiscovery::Register {
                    alias,
                    expires_at_ms,
                }) => match response {
                    DiscoveryResponse::Ack { ok, error } => {
                        if ok {
                            *discovery_registered = true;
                            *discovery_last_error = None;
                            emit_log(
                                        event_tx,
                                        format!(
                                            "[p2p] discovery registration accepted: alias={alias:?} expires_at_ms={expires_at_ms}"
                                        ),
                                    )
                                    .await;
                        } else {
                            let err = error.unwrap_or_else(|| "registration rejected".to_string());
                            *discovery_registered = false;
                            *discovery_last_error = Some(err.clone());
                            emit_log(
                                event_tx,
                                format!("[p2p] discovery registration rejected: {err}"),
                            )
                            .await;
                        }
                    }
                    other => {
                        *discovery_last_error =
                            Some(format!("unexpected discovery register response: {other:?}"));
                    }
                },
                None => {
                    emit_log(
                        event_tx,
                        format!("[p2p] unexpected discovery response from {peer}: {response:?}"),
                    )
                    .await;
                }
            },
        },
        request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            if let Some(pending) = pending_discovery.remove(&request_id) {
                let reason = format!("discovery request to {peer} failed: {error}");
                *discovery_last_error = Some(reason.clone());
                match pending {
                    PendingDiscovery::Resolve { query, reply } => {
                        let _ = reply.send(DiscoveryResolution {
                            query,
                            found: false,
                            advertisement: None,
                            reason: Some(reason),
                        });
                    }
                    PendingDiscovery::List(reply) => {
                        let _ = reply.send(Vec::new());
                    }
                    PendingDiscovery::Register { .. } => {
                        *discovery_registered = false;
                    }
                }
            } else {
                emit_log(
                    event_tx,
                    format!("[p2p] discovery outbound failure: peer={peer} error={error}"),
                )
                .await;
            }
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            emit_log(
                event_tx,
                format!("[p2p] discovery inbound failure: peer={peer} error={error}"),
            )
            .await;
        }
        request_response::Event::ResponseSent { peer, .. } => {
            let _ = peer;
        }
    }
}

fn build_relayed_addrs(
    bootstrap_peers: &[Multiaddr],
    reservations: &[PeerId],
    local_peer_id: PeerId,
) -> Vec<Multiaddr> {
    bootstrap_peers
        .iter()
        .filter_map(|addr| {
            let relay_peer_id = peer_id_from_multiaddr(addr)?;
            if !reservations.contains(&relay_peer_id) {
                return None;
            }

            Some(
                addr.clone()
                    .with(libp2p::multiaddr::Protocol::P2pCircuit)
                    .with(libp2p::multiaddr::Protocol::P2p(local_peer_id)),
            )
        })
        .collect()
}

async fn handle_messaging_event(
    event: request_response::Event<DogelRequest, DogelResponse>,
    event_tx: &mpsc::Sender<P2pEvent>,
    behaviour: &mut DogelBehaviour,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => {
            match message {
                RequestResponseMessage::Request {
                    request, channel, ..
                } => {
                    // Acknowledge transport-level receipt first. Actual message
                    // verification/decryption happens in the CLI event task.
                    let _ = behaviour
                        .messaging
                        .send_response(channel, DogelResponse::ok());

                    match request {
                        DogelRequest::Envelope(envelope) => {
                            let _ = event_tx
                                .send(P2pEvent::InboundEnvelope {
                                    peer_id: peer,
                                    envelope,
                                })
                                .await;
                        }
                        DogelRequest::Invite(invite) => {
                            let _ = event_tx
                                .send(P2pEvent::InboundInvite {
                                    peer_id: peer,
                                    invite,
                                })
                                .await;
                        }
                    }
                }
                RequestResponseMessage::Response { response, .. } => {
                    if !response.ok {
                        emit_log(
                            event_tx,
                            format!(
                                "[p2p] remote rejected message: {}",
                                response
                                    .error
                                    .unwrap_or_else(|| "unknown error".to_string())
                            ),
                        )
                        .await;
                    }
                }
            }
        }
        request_response::Event::OutboundFailure { peer, error, .. } => {
            emit_log(
                event_tx,
                format!("[p2p] outbound message failure: peer={peer} error={error}"),
            )
            .await;
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            emit_log(
                event_tx,
                format!("[p2p] inbound message failure: peer={peer} error={error}"),
            )
            .await;
        }
        request_response::Event::ResponseSent { peer, .. } => {
            let _ = peer;
        }
    }
}

fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|protocol| match protocol {
        libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advert(peer_id: &str, alias: Option<&str>, expires_at_ms: u64) -> PeerAdvertisement {
        PeerAdvertisement {
            peer_id: peer_id.to_string(),
            alias: alias.map(|value| value.to_string()),
            direct_addrs: vec!["/ip4/127.0.0.1/tcp/7777/p2p/12D3KooWTest".to_string()],
            relayed_addrs: Vec::new(),
            nat_status: "Public".to_string(),
            observed_at_ms: 1,
            expires_at_ms,
        }
    }

    #[test]
    fn registers_and_resolves_by_peer_and_alias() {
        let mut directory = DiscoveryDirectory::default();
        let advert = advert("12D3KooWPeer", Some("alice"), 1_000);
        directory.register(advert.clone()).unwrap();

        let by_peer = directory.resolve("12D3KooWPeer", 10);
        assert!(by_peer.found);
        assert_eq!(
            by_peer.advertisement.as_ref().unwrap().peer_id,
            advert.peer_id
        );

        let by_alias = directory.resolve("alice", 10);
        assert!(by_alias.found);
        assert_eq!(
            by_alias.advertisement.as_ref().unwrap().peer_id,
            advert.peer_id
        );
    }

    #[test]
    fn expired_advertisement_is_ignored() {
        let mut directory = DiscoveryDirectory::default();
        directory
            .register(advert("12D3KooWExpired", Some("expired"), 10))
            .unwrap();

        let resolution = directory.resolve("expired", 11);
        assert!(!resolution.found);
        assert!(resolution.advertisement.is_none());
        assert!(resolution.reason.unwrap().contains("expired"));
    }

    #[test]
    fn alias_conflict_is_rejected() {
        let mut directory = DiscoveryDirectory::default();
        directory
            .register(advert("12D3KooWOne", Some("alias"), 1_000))
            .unwrap();

        let err = directory
            .register(advert("12D3KooWTwo", Some("alias"), 1_000))
            .unwrap_err();
        assert!(err.contains("alias conflict"));
    }
}
