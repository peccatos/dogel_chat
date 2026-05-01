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
    core::{transport::Boxed, upgrade},
    identify, noise, ping, request_response,
    request_response::{json, Message as RequestResponseMessage, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, Transport,
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

/// Events emitted by the P2P runtime to the CLI/application layer.
///
/// The CLI owns room keys and identity metadata, so inbound encrypted envelopes
/// are forwarded upward instead of decrypted here.
#[derive(Debug, Clone)]
pub enum P2pEvent {
    PeerConnected { peer_id: PeerId },
    PeerDisconnected { peer_id: PeerId },
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
        listen_addr: Multiaddr,
    ) -> Result<(Self, mpsc::Receiver<P2pEvent>), P2pError> {
        let local_peer_id = PeerId::from(network_keypair.public());
        let transport = build_transport(&network_keypair)?;

        let behaviour = DogelBehaviour {
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/dogel/0.1".to_string(),
                network_keypair.public(),
            )),
            messaging: json::Behaviour::<DogelRequest, DogelResponse>::new(
                [(
                    StreamProtocol::new("/dogel/message/1"),
                    ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ),
        };

        let swarm_config = libp2p::swarm::Config::with_tokio_executor()
            // Keep LAN test connections around even when idle. Once the custom
            // messaging protocol is active, substreams will be opened on demand,
            // but the long timeout still makes manual CLI debugging friendlier.
            .with_idle_connection_timeout(Duration::from_secs(24 * 60 * 60));

        let mut swarm = Swarm::new(transport, behaviour, local_peer_id, swarm_config);

        Swarm::listen_on(&mut swarm, listen_addr.clone()).map_err(|source| P2pError::Listen {
            addr: listen_addr,
            source,
        })?;

        let (command_tx, command_rx) = mpsc::channel(64);
        let (event_tx, event_rx) = mpsc::channel(128);

        tokio::spawn(async move {
            run_swarm(swarm, command_rx, event_tx).await;
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
    pub async fn send_invite(
        &self,
        peer_id: PeerId,
        invite: RoomInvite,
    ) -> Result<(), P2pError> {
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
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "DogelBehaviourEvent")]
struct DogelBehaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    messaging: json::Behaviour<DogelRequest, DogelResponse>,
}

/// Event enum generated target for the `NetworkBehaviour` derive.
#[allow(clippy::large_enum_variant)]
enum DogelBehaviourEvent {
    Ping(ping::Event),
    Identify(identify::Event),
    Messaging(request_response::Event<DogelRequest, DogelResponse>),
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

fn build_transport(
    keypair: &Keypair,
) -> Result<Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>, P2pError> {
    let tcp = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let noise = noise::Config::new(keypair).map_err(|err| P2pError::Noise(err.to_string()))?;

    Ok(tcp
        .upgrade(upgrade::Version::V1)
        .authenticate(noise)
        .multiplex(yamux::Config::default())
        .boxed())
}

async fn run_swarm(
    mut swarm: Swarm<DogelBehaviour>,
    mut command_rx: mpsc::Receiver<P2pCommand>,
    event_tx: mpsc::Sender<P2pEvent>,
) {
    let mut connected: HashSet<PeerId> = HashSet::new();

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
                }
            }

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let full = address.clone().with(libp2p::multiaddr::Protocol::P2p(*swarm.local_peer_id()));
                        println!();
                        println!("[p2p] listening on {full}");
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        let count = connection_counts.entry(peer_id).or_insert(0);
                        *count += 1;

                        let was_new_peer = connected.insert(peer_id);

                        println!();
                        if was_new_peer {
                            println!("[p2p] connected: {peer_id}");
                            let _ = event_tx
                                .send(P2pEvent::PeerConnected { peer_id })
                                .await;
                        } else {
                            println!("[p2p] additional connection established: {peer_id}");
                        }
                        println!("[p2p] endpoint: {endpoint:?}");
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        if let Some(count) = connection_counts.get_mut(&peer_id) {
                            *count = count.saturating_sub(1);

                            if *count == 0 {
                                connection_counts.remove(&peer_id);
                                connected.remove(&peer_id);

                                println!();
                                println!("[p2p] disconnected: {peer_id}");
                                let _ = event_tx
                                    .send(P2pEvent::PeerDisconnected { peer_id })
                                    .await;
                            }
                        } else {
                            // Defensive fallback: if libp2p reports a close for
                            // a peer we did not count, remove it from the public
                            // connected set anyway. This keeps `/peers` honest.
                            connected.remove(&peer_id);

                            println!();
                            println!("[p2p] disconnected: {peer_id}");
                            let _ = event_tx
                                .send(P2pEvent::PeerDisconnected { peer_id })
                                .await;
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        println!();
                        println!("[p2p] outgoing connection error: peer={peer_id:?} error={error}");
                    }
                    SwarmEvent::IncomingConnectionError { error, .. } => {
                        println!();
                        println!("[p2p] incoming connection error: {error}");
                    }
                    SwarmEvent::Behaviour(DogelBehaviourEvent::Messaging(event)) => {
                        handle_messaging_event(event, &event_tx, swarm.behaviour_mut()).await;
                    }
                    SwarmEvent::Behaviour(DogelBehaviourEvent::Ping(event)) => {
                        // Useful during development but too noisy to print every time.
                        let _ = event;
                    }
                    SwarmEvent::Behaviour(DogelBehaviourEvent::Identify(event)) => {
                        let _ = event;
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn handle_messaging_event(
    event: request_response::Event<DogelRequest, DogelResponse>,
    event_tx: &mpsc::Sender<P2pEvent>,
    behaviour: &mut DogelBehaviour,
) {
    match event {
        request_response::Event::Message { peer, message, .. } => {
            match message {
                RequestResponseMessage::Request { request, channel, .. } => {
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
                        println!();
                        println!(
                            "[p2p] remote rejected message: {}",
                            response.error.unwrap_or_else(|| "unknown error".to_string())
                        );
                    }
                }
            }
        }
        request_response::Event::OutboundFailure { peer, error, .. } => {
            println!();
            println!("[p2p] outbound message failure: peer={peer} error={error}");
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            println!();
            println!("[p2p] inbound message failure: peer={peer} error={error}");
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
