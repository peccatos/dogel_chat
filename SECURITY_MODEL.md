# dogel.bin v0.1 Security Model

## Current protections

- Local private keys are encrypted at rest.
- Passwords are used locally only and are never sent over the network.
- libp2p provides encrypted authenticated transport.
- Phase 13 relay/bootstrap improves reachability without changing the application security boundary.
- Bootstrap discovery stores only short-lived peer advertisements in memory and does not reveal message plaintext.
- AutoNAT reports external reachability and DCUtR attempts relay-assisted direct upgrades without exposing plaintext.
- Messages are encrypted at the application layer with room keys.
- Encrypted envelopes are signed with Ed25519.
- Room history is stored encrypted locally when history mode is enabled.
- Protocol version mismatches are hard-rejected.
- Invite-created room keys are bound to room id, signed membership and protocol version.
- Invite-created room membership is signed by the room creator.
- Fingerprints are derived from signing public keys.
- Trust is explicit and local.
- Replay protection is bounded and in-memory per session.
- Inbound room membership is enforced.
- Strict local policy blocks links, multiline input, control characters and message bursts.

## Threats not fully solved

- Metadata hiding.
- Offline delivery.
- Long-term durable replay protection.
- Group key rotation.
- Member removal with cryptographic revocation.
- Full multi-member membership update propagation.
- Offline sealed invites.
- Traffic analysis.
- Relay operator metadata visibility.
- Relay abuse/resource exhaustion controls.
- Malicious modified clients.
- Formal protocol verification.

## Important operational rule

Do not run two live processes with the same identity. Phase 9+ uses a session lock to prevent common accidental duplicate launches.
