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

use eve_protocol::{DogelRequest, DogelResponse, RoomInvite, SignedEncryptedEnvelope};
use futures::StreamExt;
use libp2p::{
    identify, noise, ping, relay, request_response,
    request_response::{json, Message as RequestResponseMessage, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
};
use libp2p_identity::Keypair;
use std::collections::{HashMap, HashSet};
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
}

impl P2pConfig {
    pub fn lan_only(listen_addr: Multiaddr) -> Self {
        Self {
            listen_addr,
            bootstrap_peers: Vec::new(),
            relay_server: false,
            external_addrs: Vec::new(),
        }
    }
}

/// Snapshot returned to the CLI for `/doctor` and `/whoami` style diagnostics.
#[derive(Debug, Clone)]
pub struct P2pDiagnostics {
    pub connected_peers: Vec<PeerId>,
    pub listen_addrs: Vec<Multiaddr>,
    pub bootstrap_peers: Vec<Multiaddr>,
    pub relay_server: bool,
    pub relay_reservations: Vec<PeerId>,
    pub relay_reservation_errors: Vec<String>,
    pub external_addrs: Vec<Multiaddr>,
    pub relayed_addrs: Vec<Multiaddr>,
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
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "DogelBehaviourEvent")]
struct DogelBehaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    messaging: json::Behaviour<DogelRequest, DogelResponse>,
    relay_client: relay::client::Behaviour,
    relay_server: relay::Behaviour,
}

/// Event enum generated target for the `NetworkBehaviour` derive.
#[allow(clippy::large_enum_variant)]
enum DogelBehaviourEvent {
    Ping(ping::Event),
    Identify(identify::Event),
    Messaging(request_response::Event<DogelRequest, DogelResponse>),
    RelayClient(relay::client::Event),
    RelayServer(relay::Event),
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
                            emit_log(&event_tx, format!("[p2p] {message}")).await;
                            relay_reservation_errors.push(message);
                        }
                    }
                }
            }
            Err(err) => {
                emit_log(
                    &event_tx,
                    format!("[p2p] bootstrap dial failed: {bootstrap}: {err}"),
                )
                .await;
            }
        }
    }

    // libp2p's SwarmEvent API differs a bit across minor versions. Some
    // versions expose `remaining_established` in ConnectionClosed, others do
    // not. Keep our own lightweight connection counter so this crate builds
    // without depending on that specific event field.
    let mut connection_counts: HashMap<PeerId, usize> = HashMap::new();

    loop {
        tokio::select! {
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
                        let relayed_addrs =
                            build_relayed_addrs(&config.bootstrap_peers, &reservations, *swarm.local_peer_id());

                        let _ = reply.send(P2pDiagnostics {
                            connected_peers: peers,
                            listen_addrs,
                            bootstrap_peers: config.bootstrap_peers.clone(),
                            relay_server: config.relay_server,
                            relay_reservations: reservations,
                            relay_reservation_errors: relay_reservation_errors.clone(),
                            external_addrs,
                            relayed_addrs,
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
                            emit_log(&event_tx, format!("[p2p] {message}")).await;
                            relay_reservation_errors.push(message);
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        let count = connection_counts.entry(peer_id).or_insert(0);
                        *count += 1;

                        let was_new_peer = connected.insert(peer_id);

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
    if !relay_server {
        return;
    }

    if let identify::Event::Received { info, .. } = event {
        Swarm::add_external_address(swarm, info.observed_addr);
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
