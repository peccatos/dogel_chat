# dogel.bin v0.1 Security Model

## Current protections

- Local private keys are encrypted at rest.
- Passwords are used locally only and are never sent over the network.
- libp2p provides encrypted authenticated transport.
- Messages are encrypted at the application layer with room keys.
- Encrypted envelopes are signed with Ed25519.
- Fingerprints are derived from signing public keys.
- Trust is explicit and local.
- Replay protection is in-memory per session.
- Inbound room membership is enforced.
- Strict local policy blocks links, multiline input, control characters and message bursts.

## Threats not fully solved

- Metadata hiding.
- Offline delivery.
- Long-term durable replay protection.
- Group key rotation.
- Member removal with cryptographic revocation.
- Offline sealed invites.
- Traffic analysis.
- Malicious modified clients.
- Formal protocol verification.

## Important operational rule

Do not run two live processes with the same identity. Phase 9+ uses a session lock to prevent common accidental duplicate launches.
