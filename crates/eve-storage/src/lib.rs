//! Local identity storage for dogel.bin.
//!
//! Storage is deliberately local-first. Passwords never leave the machine.
//! Public metadata is stored in `profile.toml`; private key material is stored
//! in encrypted `.enc` envelopes.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use directories::BaseDirs;
use ed25519_dalek::{SigningKey, VerifyingKey};
use eve_crypto::{
    decrypt_private_key, encrypt_private_key, fingerprint_from_public_key,
    EncryptedPrivateKeyFile,
};
use libp2p_identity::{Keypair as NetworkKeypair, PeerId};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("could not locate user config directory")]
    NoConfigDirectory,

    #[error("invalid alias: {0}")]
    InvalidAlias(String),

    #[error("identity already exists: {0}")]
    IdentityAlreadyExists(String),

    #[error("identity not found: {0}")]
    IdentityNotFound(String),

    #[error("identity is already active: {alias}; lock file exists at {path}")]
    IdentityAlreadyActive { alias: String, path: PathBuf },

    #[error("io error at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },

    #[error("toml serialization failed: {0}")]
    TomlSerialize(String),

    #[error("toml deserialization failed: {0}")]
    TomlDeserialize(String),

    #[error("json serialization failed: {0}")]
    JsonSerialize(String),

    #[error("json deserialization failed: {0}")]
    JsonDeserialize(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] eve_crypto::CryptoError),

    #[error("network key encoding failed: {0}")]
    NetworkKeyEncoding(String),

    #[error("network key decoding failed: {0}")]
    NetworkKeyDecoding(String),

    #[error("signing key has invalid length: expected 32 bytes, got {0}")]
    InvalidSigningKeyLength(usize),

    #[error("stored fingerprint does not match decrypted signing key")]
    FingerprintMismatch,
}

/// Public identity metadata stored in `profile.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProfile {
    pub alias: String,
    pub created_at_ms: u64,
    pub network: NetworkProfile,
    pub signing: SigningProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProfile {
    pub peer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningProfile {
    pub fingerprint: String,
    pub public_key: String,
}

/// A trusted remote peer pinned by the local user.
///
/// This is a TOFU/manual-verification record. It binds a libp2p `peer_id` to the
/// Ed25519 signing public key that was observed in a signed message envelope.
/// The alias remains display metadata only; the real security value is the
/// pinned signing key and fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedPeerRecord {
    pub peer_id: String,
    pub alias: String,
    pub signing_public_key_b64: String,
    pub fingerprint: String,
    pub trusted_at_ms: u64,
    pub last_seen_at_ms: u64,
}

/// File stored as `trusted_peers.toml` inside an identity directory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustedPeersFile {
    pub peers: Vec<TrustedPeerRecord>,
}

/// Summary returned after identity creation.
#[derive(Debug, Clone)]
pub struct CreatedIdentity {
    pub alias: String,
    pub peer_id: String,
    pub fingerprint: String,
    pub identity_dir: PathBuf,
}

/// Unlocked identity material kept in memory after `/login`.
///
/// The private keys are intentionally not printable. Later phases will pass
/// these keys into libp2p and the message signing layer.
pub struct UnlockedIdentity {
    pub alias: String,
    pub peer_id: String,
    pub fingerprint: String,
    pub network_keypair: NetworkKeypair,
    pub signing_key: SigningKey,
}

/// Root storage handle.
#[derive(Debug, Clone)]
pub struct IdentityStore {
    root: PathBuf,
}

impl IdentityStore {
    /// Build a store using the platform config directory.
    ///
    /// On Linux this resolves to `~/.config/dogel`.
    pub fn default() -> Result<Self, StorageError> {
        let base_dirs = BaseDirs::new().ok_or(StorageError::NoConfigDirectory)?;
        Ok(Self {
            root: base_dirs.config_dir().join("dogel"),
        })
    }

    /// Build a store at an explicit path.
    ///
    /// This is mostly useful for tests.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn identity_dir(&self, alias: &str) -> PathBuf {
        self.root.join("identities").join(alias)
    }

    /// Create a new identity and write encrypted key material to disk.
    pub fn create_identity(
        &self,
        alias: &str,
        password: &str,
    ) -> Result<CreatedIdentity, StorageError> {
        validate_alias(alias)?;

        let identity_dir = self.identity_dir(alias);
        if identity_dir.exists() {
            return Err(StorageError::IdentityAlreadyExists(alias.to_string()));
        }

        fs::create_dir_all(&identity_dir).map_err(|source| StorageError::Io {
            path: identity_dir.clone(),
            source,
        })?;

        let network_keypair = NetworkKeypair::generate_ed25519();
        let peer_id = PeerId::from(network_keypair.public()).to_string();

        // The protobuf encoding is the portable private-key representation used
        // by libp2p-identity.
        let network_private_bytes = network_keypair
            .to_protobuf_encoding()
            .map_err(|err| StorageError::NetworkKeyEncoding(err.to_string()))?;

        // For ed25519-dalek v2, `SigningKey` is built from a 32-byte seed.
        // Storing the seed encrypted is sufficient to reconstruct the signing
        // key and verifying key.
        let mut signing_seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(signing_seed.as_mut());

        let signing_key = SigningKey::from_bytes(&*signing_seed);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let signing_public_key = verifying_key.to_bytes();

        let fingerprint = fingerprint_from_public_key(&signing_public_key);

        let profile = IdentityProfile {
            alias: alias.to_string(),
            created_at_ms: now_ms(),
            network: NetworkProfile { peer_id },
            signing: SigningProfile {
                fingerprint: fingerprint.clone(),
                public_key: BASE64.encode(signing_public_key),
            },
        };

        let encrypted_network = encrypt_private_key(&network_private_bytes, password)?;
        let encrypted_signing = encrypt_private_key(&*signing_seed, password)?;

        write_toml(identity_dir.join("profile.toml"), &profile)?;
        write_json(identity_dir.join("network_key.enc"), &encrypted_network)?;
        write_json(identity_dir.join("signing_key.enc"), &encrypted_signing)?;

        Ok(CreatedIdentity {
            alias: profile.alias,
            peer_id: profile.network.peer_id,
            fingerprint,
            identity_dir,
        })
    }

    /// Unlock an existing identity by decrypting both private key files.
    pub fn unlock_identity(
        &self,
        alias: &str,
        password: &str,
    ) -> Result<UnlockedIdentity, StorageError> {
        validate_alias(alias)?;

        let identity_dir = self.identity_dir(alias);
        if !identity_dir.exists() {
            return Err(StorageError::IdentityNotFound(alias.to_string()));
        }

        let profile: IdentityProfile = read_toml(identity_dir.join("profile.toml"))?;
        let encrypted_network: EncryptedPrivateKeyFile =
            read_json(identity_dir.join("network_key.enc"))?;
        let encrypted_signing: EncryptedPrivateKeyFile =
            read_json(identity_dir.join("signing_key.enc"))?;

        let network_private_bytes = decrypt_private_key(&encrypted_network, password)?;
        let signing_seed = decrypt_private_key(&encrypted_signing, password)?;

        let network_keypair = NetworkKeypair::from_protobuf_encoding(network_private_bytes.as_ref())
            .map_err(|err| StorageError::NetworkKeyDecoding(err.to_string()))?;

        let derived_peer_id = PeerId::from(network_keypair.public()).to_string();
        if derived_peer_id != profile.network.peer_id {
            return Err(StorageError::NetworkKeyDecoding(
                "decrypted network key does not match profile peer_id".to_string(),
            ));
        }

        if signing_seed.len() != 32 {
            return Err(StorageError::InvalidSigningKeyLength(signing_seed.len()));
        }

        let mut seed_array = [0u8; 32];
        seed_array.copy_from_slice(signing_seed.as_ref());

        let signing_key = SigningKey::from_bytes(&seed_array);
        let verifying_key = signing_key.verifying_key();
        let fingerprint = fingerprint_from_public_key(&verifying_key.to_bytes());

        if fingerprint != profile.signing.fingerprint {
            return Err(StorageError::FingerprintMismatch);
        }

        Ok(UnlockedIdentity {
            alias: profile.alias,
            peer_id: profile.network.peer_id,
            fingerprint,
            network_keypair,
            signing_key,
        })
    }

    /// Load trusted peers for a local identity.
    ///
    /// Missing `trusted_peers.toml` means the identity simply has not trusted
    /// anyone yet. That is not an error.
    pub fn load_trusted_peers(
        &self,
        alias: &str,
    ) -> Result<Vec<TrustedPeerRecord>, StorageError> {
        validate_alias(alias)?;

        let identity_dir = self.identity_dir(alias);
        if !identity_dir.exists() {
            return Err(StorageError::IdentityNotFound(alias.to_string()));
        }

        let path = self.trusted_peers_path(alias);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file: TrustedPeersFile = read_toml(path)?;
        Ok(file.peers)
    }

    /// Insert or replace a trusted peer record.
    ///
    /// Replacement is explicit: running `/trust <peer_id>` again after observing
    /// a different signing key updates the pin. The CLI prints warnings before
    /// calling this method, so storage remains a dumb persistence layer.
    pub fn trust_peer(
        &self,
        alias: &str,
        record: TrustedPeerRecord,
    ) -> Result<(), StorageError> {
        validate_alias(alias)?;

        let identity_dir = self.identity_dir(alias);
        if !identity_dir.exists() {
            return Err(StorageError::IdentityNotFound(alias.to_string()));
        }

        let mut peers = self.load_trusted_peers(alias)?;
        peers.retain(|existing| existing.peer_id != record.peer_id);
        peers.push(record);
        peers.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));

        write_toml(
            self.trusted_peers_path(alias),
            &TrustedPeersFile { peers },
        )
    }

    /// Remove a trusted peer pin.
    ///
    /// Returns `true` if a record existed and was removed.
    pub fn remove_trusted_peer(
        &self,
        alias: &str,
        peer_id: &str,
    ) -> Result<bool, StorageError> {
        validate_alias(alias)?;

        let identity_dir = self.identity_dir(alias);
        if !identity_dir.exists() {
            return Err(StorageError::IdentityNotFound(alias.to_string()));
        }

        let mut peers = self.load_trusted_peers(alias)?;
        let before = peers.len();
        peers.retain(|existing| existing.peer_id != peer_id);
        let removed = peers.len() != before;

        write_toml(
            self.trusted_peers_path(alias),
            &TrustedPeersFile { peers },
        )?;

        Ok(removed)
    }

    pub fn trusted_peers_path(&self, alias: &str) -> PathBuf {
        self.identity_dir(alias).join("trusted_peers.toml")
    }

    /// Acquire a best-effort local session lock for an identity.
    ///
    /// This prevents accidental use of the same libp2p identity in two local
    /// dogel.bin processes. The lock is intentionally simple and local. It is
    /// not a distributed lock and does not protect against a malicious local
    /// user who edits files directly.
    pub fn acquire_identity_lock(&self, alias: &str) -> Result<(), StorageError> {
        validate_alias(alias)?;

        let identity_dir = self.identity_dir(alias);
        if !identity_dir.exists() {
            return Err(StorageError::IdentityNotFound(alias.to_string()));
        }

        let path = self.identity_lock_path(alias);
        let content = format!(
            "pid={}\ncreated_at_ms={}\n",
            process::id(),
            now_ms()
        );

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(content.as_bytes()).map_err(|source| StorageError::Io {
                    path,
                    source,
                })?;
                Ok(())
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                Err(StorageError::IdentityAlreadyActive {
                    alias: alias.to_string(),
                    path,
                })
            }
            Err(source) => Err(StorageError::Io { path, source }),
        }
    }

    /// Release the local session lock for an identity.
    ///
    /// Missing lock files are ignored because the process may be exiting after a
    /// partial startup failure or a user may have removed a stale lock manually.
    pub fn release_identity_lock(&self, alias: &str) -> Result<(), StorageError> {
        validate_alias(alias)?;

        let path = self.identity_lock_path(alias);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(StorageError::Io { path, source }),
        }
    }

    pub fn identity_lock_path(&self, alias: &str) -> PathBuf {
        self.identity_dir(alias).join("session.lock")
    }

}

fn validate_alias(alias: &str) -> Result<(), StorageError> {
    let valid = !alias.is_empty()
        && alias.len() <= 64
        && alias
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');

    if valid {
        Ok(())
    } else {
        Err(StorageError::InvalidAlias(alias.to_string()))
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn write_toml<T: Serialize>(path: PathBuf, value: &T) -> Result<(), StorageError> {
    let content = toml::to_string_pretty(value)
        .map_err(|err| StorageError::TomlSerialize(err.to_string()))?;
    fs::write(&path, content).map_err(|source| StorageError::Io { path, source })
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: PathBuf) -> Result<T, StorageError> {
    let content = fs::read_to_string(&path).map_err(|source| StorageError::Io {
        path: path.clone(),
        source,
    })?;

    toml::from_str(&content).map_err(|err| StorageError::TomlDeserialize(err.to_string()))
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) -> Result<(), StorageError> {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| StorageError::JsonSerialize(err.to_string()))?;
    fs::write(&path, content).map_err(|source| StorageError::Io { path, source })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: PathBuf) -> Result<T, StorageError> {
    let content = fs::read_to_string(&path).map_err(|source| StorageError::Io {
        path: path.clone(),
        source,
    })?;

    serde_json::from_str(&content).map_err(|err| StorageError::JsonDeserialize(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_unlock_identity_roundtrip() {
        let unique = format!(
            "dogel-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        let store = IdentityStore::at(&root);

        let created = store
            .create_identity("Alice", "correct horse battery staple")
            .unwrap();

        assert_eq!(created.alias, "Alice");
        assert!(created.identity_dir.exists());

        let unlocked = store
            .unlock_identity("Alice", "correct horse battery staple")
            .unwrap();

        assert_eq!(unlocked.alias, "Alice");
        assert_eq!(unlocked.peer_id, created.peer_id);
        assert_eq!(unlocked.fingerprint, created.fingerprint);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn wrong_password_fails_to_unlock() {
        let unique = format!(
            "dogel-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        let store = IdentityStore::at(&root);

        store.create_identity("alice", "right").unwrap();

        let err = store.unlock_identity("alice", "wrong").unwrap_err();
        assert!(matches!(err, StorageError::Crypto(_)));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_bad_alias() {
        let store = IdentityStore::at(std::env::temp_dir().join("dogel-alias-test"));
        assert!(matches!(
            store.create_identity("../evil", "pw").unwrap_err(),
            StorageError::InvalidAlias(_)
        ));
    }
}
