//! Cryptographic primitives for dogel.bin.
//!
//! This crate owns low-level crypto decisions: password KDF, encrypted file
//! envelopes, display fingerprints, room key derivation, room encryption and
//! Ed25519 signature helpers. Higher-level crates should not manually compose
//! ciphers or KDFs.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

/// Upper bounds for Argon2id parameters loaded from disk.
///
/// The encrypted private-key envelope stores KDF parameters for migration, but
/// those values are attacker-controlled if someone tampers with the `.enc`
/// file. Without caps, a malicious file could force the client to allocate huge
/// memory during `/login`. These caps reject hostile parameters before Argon2
/// runs.
const MAX_ARGON2_MEMORY_COST_KIB: u32 = 256 * 1024;
const MAX_ARGON2_TIME_COST: u32 = 10;
const MAX_ARGON2_PARALLELISM: u32 = 8;
const EXPECTED_KEY_OUTPUT_LEN: usize = 32;

/// Argon2id settings used for room passphrases.
///
/// Room secrets are human-entered, so using a fast hash would allow cheap
/// offline dictionary attacks against captured encrypted envelopes. This KDF is
/// deterministic across peers because the salt is derived from the public room
/// id. It is intentionally separate from private-key file encryption settings.
const ROOM_ARGON2_MEMORY_COST_KIB: u32 = 64 * 1024;
const ROOM_ARGON2_TIME_COST: u32 = 3;
const ROOM_ARGON2_PARALLELISM: u32 = 1;


/// Versioned encrypted file format for local private key material.
///
/// The file is JSON-serializable. The `.enc` extension means "encrypted
/// envelope", not opaque binary. JSON is chosen for v0.1 because it is easy to
/// inspect during development without exposing plaintext private keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPrivateKeyFile {
    pub version: u32,
    pub kdf: String,
    pub kdf_params: Argon2idParams,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

/// KDF parameters are stored with each file so future versions can migrate
/// settings without breaking old identities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2idParams {
    /// Memory cost in KiB.
    pub memory_cost_kib: u32,
    /// Number of iterations.
    pub time_cost: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
    /// Output key length in bytes.
    pub output_len: usize,
}

impl Default for Argon2idParams {
    fn default() -> Self {
        Self {
            // 64 MiB is a reasonable default for an interactive CLI on developer
            // machines. It is intentionally not extreme; we can tune later.
            memory_cost_kib: 64 * 1024,
            time_cost: 3,
            parallelism: 1,
            output_len: 32,
        }
    }
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid argon2 parameters: {0}")]
    InvalidArgon2Params(String),

    #[error("argon2 key derivation failed: {0}")]
    Argon2(String),

    #[error("encryption failed")]
    Encrypt,

    #[error("decryption failed; wrong password or corrupted key file/message")]
    Decrypt,

    #[error("invalid base64 field {field}: {source}")]
    Base64 {
        field: &'static str,
        source: base64::DecodeError,
    },

    #[error("invalid nonce length: expected {expected} bytes, got {actual}")]
    InvalidNonceLength { expected: usize, actual: usize },

    #[error("invalid salt length: expected 16 bytes, got {0}")]
    InvalidSaltLength(usize),

    #[error("invalid room key length: expected 32 bytes, got {0}")]
    InvalidRoomKeyLength(usize),

    #[error("invalid Ed25519 public key length: expected 32 bytes, got {0}")]
    InvalidPublicKeyLength(usize),

    #[error("invalid Ed25519 signature length: expected 64 bytes, got {0}")]
    InvalidSignatureLength(usize),

    #[error("Ed25519 signature verification failed")]
    SignatureVerification,
}

/// Encrypt private key bytes using Argon2id(password) + XChaCha20Poly1305.
///
/// Trade-off: we derive a fresh file key for each encrypted blob using its own
/// random salt. This is slightly more work at login time, but it isolates files
/// from each other and keeps the format simple.
pub fn encrypt_private_key(
    plaintext: &[u8],
    password: &str,
) -> Result<EncryptedPrivateKeyFile, CryptoError> {
    let params = Argon2idParams::default();

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];

    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(password, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Encrypt)?;

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::Encrypt)?;

    Ok(EncryptedPrivateKeyFile {
        version: 1,
        kdf: "argon2id".to_string(),
        kdf_params: params,
        salt_b64: BASE64.encode(salt),
        nonce_b64: BASE64.encode(nonce),
        ciphertext_b64: BASE64.encode(ciphertext),
    })
}

/// Decrypt private key bytes from a versioned encrypted file envelope.
pub fn decrypt_private_key(
    file: &EncryptedPrivateKeyFile,
    password: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let salt = BASE64
        .decode(&file.salt_b64)
        .map_err(|source| CryptoError::Base64 {
            field: "salt_b64",
            source,
        })?;

    if salt.len() != 16 {
        return Err(CryptoError::InvalidSaltLength(salt.len()));
    }

    let nonce = BASE64
        .decode(&file.nonce_b64)
        .map_err(|source| CryptoError::Base64 {
            field: "nonce_b64",
            source,
        })?;

    if nonce.len() != 24 {
        return Err(CryptoError::InvalidNonceLength {
            expected: 24,
            actual: nonce.len(),
        });
    }

    let ciphertext =
        BASE64
            .decode(&file.ciphertext_b64)
            .map_err(|source| CryptoError::Base64 {
                field: "ciphertext_b64",
                source,
            })?;

    let key = derive_key(password, &salt, &file.kdf_params)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::Decrypt)?;

    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| CryptoError::Decrypt)?;

    Ok(Zeroizing::new(plaintext))
}

/// Derive a symmetric key from a password and salt using stored Argon2id params.
fn derive_key(
    password: &str,
    salt: &[u8],
    params: &Argon2idParams,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    validate_argon2id_params(params)?;

    let argon_params = Params::new(
        params.memory_cost_kib,
        params.time_cost,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|err| CryptoError::InvalidArgon2Params(err.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut output = Zeroizing::new(vec![0u8; params.output_len]);
    argon2
        .hash_password_into(password.as_bytes(), salt, output.as_mut_slice())
        .map_err(|err| CryptoError::Argon2(err.to_string()))?;

    Ok(output)
}

/// Validate KDF parameters before allocating Argon2 memory.
///
/// This protects `/login` against maliciously edited `.enc` files that request
/// extreme memory or CPU usage. It is not a secrecy feature; it is local DoS
/// hardening.
fn validate_argon2id_params(params: &Argon2idParams) -> Result<(), CryptoError> {
    if params.output_len != EXPECTED_KEY_OUTPUT_LEN {
        return Err(CryptoError::InvalidArgon2Params(format!(
            "output_len must be {EXPECTED_KEY_OUTPUT_LEN}, got {}",
            params.output_len
        )));
    }

    if params.memory_cost_kib == 0 || params.memory_cost_kib > MAX_ARGON2_MEMORY_COST_KIB {
        return Err(CryptoError::InvalidArgon2Params(format!(
            "memory_cost_kib must be between 1 and {MAX_ARGON2_MEMORY_COST_KIB}, got {}",
            params.memory_cost_kib
        )));
    }

    if params.time_cost == 0 || params.time_cost > MAX_ARGON2_TIME_COST {
        return Err(CryptoError::InvalidArgon2Params(format!(
            "time_cost must be between 1 and {MAX_ARGON2_TIME_COST}, got {}",
            params.time_cost
        )));
    }

    if params.parallelism == 0 || params.parallelism > MAX_ARGON2_PARALLELISM {
        return Err(CryptoError::InvalidArgon2Params(format!(
            "parallelism must be between 1 and {MAX_ARGON2_PARALLELISM}, got {}",
            params.parallelism
        )));
    }

    Ok(())
}

/// Derive a 32-byte room key from a room id and shared passphrase.
///
/// Phase 9 deliberately switches room derivation from a fast BLAKE3-only KDF to
/// Argon2id. Captured encrypted envelopes enable offline guessing of weak room
/// passphrases; using Argon2id makes each guess substantially more expensive.
///
/// The salt must be deterministic so both peers derive the same key. It is
/// derived from the room id plus a domain separator. The salt is not secret.
pub fn derive_room_key(room_id: &str, passphrase: &str) -> Result<[u8; 32], CryptoError> {
    let salt_hash = blake3::derive_key("DOGEL_ROOM_ARGON2_SALT_V1", room_id.as_bytes());
    let salt = &salt_hash[..16];

    let params = Argon2idParams {
        memory_cost_kib: ROOM_ARGON2_MEMORY_COST_KIB,
        time_cost: ROOM_ARGON2_TIME_COST,
        parallelism: ROOM_ARGON2_PARALLELISM,
        output_len: EXPECTED_KEY_OUTPUT_LEN,
    };

    let derived = derive_key(passphrase, salt, &params)?;
    let mut room_key = [0u8; 32];
    room_key.copy_from_slice(derived.as_slice());

    Ok(room_key)
}


/// Generate a random 256-bit room key for invite-created rooms.
///
/// This avoids human passphrases entirely. The key is later sent only inside an
/// authenticated online invite over the libp2p secure channel.
pub fn generate_random_room_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate a random 128-bit message id encoded as uppercase hex.
///
/// The message id is not secret. It is used by receivers as a replay-cache key
/// together with the sender peer id.
pub fn generate_message_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);

    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>()
}

/// Short display fingerprint for a room key.
///
/// This is not a secret and must not be treated as authorization. It is useful
/// only for debugging whether two clients derived the same room key.
pub fn room_key_fingerprint(room_key: &[u8; 32]) -> String {
    let hash = blake3::hash(room_key);
    format_fingerprint(&hash.as_bytes()[..8])
}

/// Encrypt a plaintext room message with ChaCha20Poly1305.
///
/// The caller is responsible for serializing plaintext and signing the final
/// envelope. This function only provides confidentiality and AEAD integrity for
/// the ciphertext.
pub fn encrypt_room_message(
    room_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<([u8; 12], Vec<u8>), CryptoError> {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(room_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::Encrypt)?;

    Ok((nonce, ciphertext))
}

/// Decrypt a room message with ChaCha20Poly1305.
pub fn decrypt_room_message(
    room_key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidNonceLength {
            expected: 12,
            actual: nonce.len(),
        });
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(room_key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::Decrypt)
}

/// Sign arbitrary bytes with the local Ed25519 signing identity.
pub fn sign_bytes(signing_key: &SigningKey, payload: &[u8]) -> Vec<u8> {
    signing_key.sign(payload).to_bytes().to_vec()
}

/// Verify an Ed25519 signature over arbitrary bytes.
pub fn verify_signature(
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
        CryptoError::InvalidPublicKeyLength(public_key.len())
    })?;

    let signature: [u8; 64] = signature.try_into().map_err(|_| {
        CryptoError::InvalidSignatureLength(signature.len())
    })?;

    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| CryptoError::InvalidPublicKeyLength(32))?;
    let signature = Signature::from_bytes(&signature);

    verifying_key
        .verify(payload, &signature)
        .map_err(|_| CryptoError::SignatureVerification)
}

/// Produce the dogel display fingerprint from a signing public key.
///
/// The fingerprint is intentionally short because it is displayed in the CLI,
/// not used as a cryptographic key. Users can compare it out-of-band.
pub fn fingerprint_from_public_key(public_key: &[u8]) -> String {
    let hash = blake3::hash(public_key);
    format_fingerprint(&hash.as_bytes()[..8])
}

fn format_fingerprint(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_roundtrip() {
        let password = "correct horse battery staple";
        let plaintext = b"secret private key bytes";

        let encrypted = encrypt_private_key(plaintext, password).unwrap();
        let decrypted = decrypt_private_key(&encrypted, password).unwrap();

        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn room_message_roundtrip() {
        let key = derive_room_key("123", "red wheelbarrow").unwrap();
        let plaintext = b"hello world";

        let (nonce, ciphertext) = encrypt_room_message(&key, plaintext).unwrap();
        let decrypted = decrypt_room_message(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
