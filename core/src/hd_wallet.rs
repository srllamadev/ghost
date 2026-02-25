//! HD Wallet — BIP-39 / BIP-32 / BIP-44
//!
//! GhostPay derives **three** independent hierarchical keys from a single seed:
//!
//! ```
//!  m / purpose' / coin_type' / account' / key_family' / index
//!  ─────────────────────────────────────────────────────────
//!  m / 44'      / 145'       / 0'       / 0'           / 0   → spend key
//!  m / 44'      / 145'       / 0'       / 1'           / 0   → scan key
//!  m / 44'      / 145'       / 0'       / 2'           / 0   → covenant key
//! ```
//!
//! coin_type 145 = Bitcoin Cash (SLIP-44)
//!
//! The scan key is used exclusively for ECDH scanning — it never signs
//! on-chain transactions, limiting exposure if it is compromised.
//! The covenant key signs CashScript covenant unlocking scripts.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bip39::{Language, Mnemonic};
use hmac::Hmac;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use std::fmt;

// ────────────────────────────────────────────────────────────────────────────
// Error type
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum WalletError {
    InvalidMnemonic,
    DerivationError(String),
    EncryptionError(String),
    DecryptionError(String),
}
impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMnemonic => write!(f, "Invalid BIP-39 mnemonic"),
            Self::DerivationError(s) => write!(f, "Key derivation error: {s}"),
            Self::EncryptionError(s) => write!(f, "Encryption error: {s}"),
            Self::DecryptionError(s) => write!(f, "Decryption error: {s}"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Mnemonic helpers
// ────────────────────────────────────────────────────────────────────────────

pub fn generate_mnemonic() -> String {
    Mnemonic::generate_in(Language::English, 24)
        .expect("entropy source available")
        .to_string()
}

pub fn validate_mnemonic(mnemonic: &str) -> bool {
    mnemonic.parse::<Mnemonic>().is_ok()
}

// ────────────────────────────────────────────────────────────────────────────
// Core derivation — produces the 3-key bundle
// ────────────────────────────────────────────────────────────────────────────

/// BIP-32 child key derivation path component (hardened if bit 31 set).
const HARDENED: u32 = 0x8000_0000;

/// Represents an extended private key node.
struct XPriv {
    key:   Zeroizing<[u8; 32]>,
    chain: [u8; 32],
}

impl XPriv {
    /// Derive from BIP-39 seed bytes using HMAC-SHA512 (BIP-32 master key).
    fn from_seed(seed: &[u8]) -> Self {
        use hmac::{Mac, SimpleHmac};
        type HmacSha512 = SimpleHmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
            .expect("HMAC key length valid");
        mac.update(seed);
        let result = mac.finalize().into_bytes();
        let (key_bytes, chain_bytes) = result.split_at(32);
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(key_bytes);
        let mut chain = [0u8; 32];
        chain.copy_from_slice(chain_bytes);
        Self { key, chain }
    }

    /// CKD_priv — child key derivation (BIP-32).
    fn derive_child(&self, index: u32) -> Result<Self, WalletError> {
        use hmac::{Mac, SimpleHmac};
        type HmacSha512 = SimpleHmac<Sha512>;
        let secp = Secp256k1::new();
        let mut data = Vec::with_capacity(37);
        if index >= HARDENED {
            data.push(0x00);
            data.extend_from_slice(&self.key[..]);
        } else {
            let sk = SecretKey::from_slice(&self.key[..])
                .map_err(|e| WalletError::DerivationError(e.to_string()))?;
            data.extend_from_slice(
                &PublicKey::from_secret_key(&secp, &sk).serialize(),
            );
        }
        data.extend_from_slice(&index.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(&self.chain)
            .expect("HMAC key length valid");
        mac.update(&data);
        let result = mac.finalize().into_bytes();
        let (il, ir) = result.split_at(32);

        // child_key = (parent_key + il) mod n
        let mut child_key_bytes = Zeroizing::new([0u8; 32]);
        child_key_bytes.copy_from_slice(
            &SecretKey::from_slice(il)
                .map_err(|e| WalletError::DerivationError(e.to_string()))?
                .add_tweak(
                    &secp256k1::Scalar::from_be_bytes(*self.key)
                        .map_err(|_| WalletError::DerivationError("scalar".into()))?,
                )
                .map_err(|e| WalletError::DerivationError(e.to_string()))?
                .secret_bytes(),
        );

        let mut chain = [0u8; 32];
        chain.copy_from_slice(ir);
        Ok(Self { key: child_key_bytes, chain })
    }

    /// Derive along a path such as [44', 145', 0', 0', 0]
    fn derive_path(&self, path: &[u32]) -> Result<Self, WalletError> {
        let mut node = Self {
            key:   self.key.clone(),
            chain: self.chain,
        };
        for &index in path {
            node = node.derive_child(index)?;
        }
        Ok(node)
    }

    /// Return the compressed public key bytes (33 bytes).
    fn public_key_bytes(&self) -> Result<[u8; 33], WalletError> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&self.key[..])
            .map_err(|e| WalletError::DerivationError(e.to_string()))?;
        Ok(PublicKey::from_secret_key(&secp, &sk).serialize())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Public API — derive_ghost_keys
// ────────────────────────────────────────────────────────────────────────────

/// Derive the GhostPay 3-key bundle. Returns JSON with public keys and paycode.
/// Private keys are *not* in the return value; encrypt and store them separately
/// using `encrypt_key`.
pub fn derive_ghost_keys(mnemonic: &str, passphrase: &str) -> Result<String, WalletError> {
    let mn: Mnemonic = mnemonic.parse().map_err(|_| WalletError::InvalidMnemonic)?;

    // BIP-39 seed (512-bit) — zeroize after use
    let seed = Zeroizing::new(mn.to_seed(passphrase));
    let master = XPriv::from_seed(&seed);

    // Derivation paths (all hardened as per SLIP-10 / BIP-44)
    let spend_path   = [44 | HARDENED, 145 | HARDENED, 0 | HARDENED, 0 | HARDENED, 0];
    let scan_path    = [44 | HARDENED, 145 | HARDENED, 0 | HARDENED, 1 | HARDENED, 0];
    let cov_path     = [44 | HARDENED, 145 | HARDENED, 0 | HARDENED, 2 | HARDENED, 0];

    let spend_node   = master.derive_path(&spend_path)?;
    let scan_node    = master.derive_path(&scan_path)?;
    let cov_node     = master.derive_path(&cov_path)?;

    let spend_pub    = spend_node.public_key_bytes()?;
    let scan_pub     = scan_node.public_key_bytes()?;
    let cov_pub      = cov_node.public_key_bytes()?;

    let spend_pub_hex = hex::encode(spend_pub);
    let scan_pub_hex  = hex::encode(scan_pub);
    let cov_pub_hex   = hex::encode(cov_pub);

    // Paycode = spend_pubkey ‖ scan_pubkey, base58check encoded
    let paycode = encode_paycode(&spend_pub, &scan_pub);

    Ok(serde_json::json!({
        "spend_xpub":    spend_pub_hex,
        "scan_xpub":     scan_pub_hex,
        "covenant_xpub": cov_pub_hex,
        "paycode":       paycode,
    })
    .to_string())
}

/// Encode a GhostPay paycode.
/// Format: 0x47 (version) ‖ spend_pubkey (33 bytes) ‖ scan_pubkey (33 bytes)
/// Encoded as base58check.
fn encode_paycode(spend_pub: &[u8; 33], scan_pub: &[u8; 33]) -> String {
    let mut raw = vec![0x47u8]; // 'G' for GhostPay version byte
    raw.extend_from_slice(spend_pub);
    raw.extend_from_slice(scan_pub);

    // Double-SHA256 checksum
    let check = &Sha256::digest(Sha256::digest(&raw))[..4];
    raw.extend_from_slice(check);

    bs58::encode(raw).into_string()
}

/// Decode a GhostPay paycode — returns (spend_pubkey_bytes, scan_pubkey_bytes).
pub fn decode_paycode(paycode: &str) -> Result<([u8; 33], [u8; 33]), WalletError> {
    let raw = bs58::decode(paycode)
        .into_vec()
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    if raw.len() != 71 {
        return Err(WalletError::DerivationError("Invalid paycode length".into()));
    }

    // Verify checksum
    let (payload, checksum) = raw.split_at(67);
    let computed = &Sha256::digest(Sha256::digest(payload))[..4];
    if computed != checksum {
        return Err(WalletError::DerivationError("Paycode checksum mismatch".into()));
    }
    if payload[0] != 0x47 {
        return Err(WalletError::DerivationError("Unsupported paycode version".into()));
    }

    let mut spend = [0u8; 33];
    let mut scan  = [0u8; 33];
    spend.copy_from_slice(&payload[1..34]);
    scan.copy_from_slice(&payload[34..67]);
    Ok((spend, scan))
}

// ────────────────────────────────────────────────────────────────────────────
// Key encryption — AES-256-GCM + argon2id
// ────────────────────────────────────────────────────────────────────────────

/// Argon2id parameters — calibrated for ~250 ms on a mid-range laptop.
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

/// Derive a 32-byte AES key from a password using argon2id.
fn kdf(password: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let params = argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| WalletError::EncryptionError(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| WalletError::EncryptionError(e.to_string()))?;
    Ok(key)
}

/// Encrypt raw key hex with argon2id(password) → AES-256-GCM.
/// Returns: base64( salt(16) ‖ nonce(12) ‖ ciphertext ‖ tag(16) )
pub fn encrypt_key(raw_key_hex: &str, password: &str) -> Result<String, WalletError> {
    let raw_bytes = hex::decode(raw_key_hex)
        .map_err(|e| WalletError::EncryptionError(e.to_string()))?;

    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let aes_key = kdf(password, &salt)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*aes_key));
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, raw_bytes.as_ref())
        .map_err(|e| WalletError::EncryptionError(e.to_string()))?;

    let mut out = Vec::with_capacity(16 + 12 + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(B64.encode(out))
}

/// Decrypt a key encrypted with `encrypt_key`. Returns raw key hex.
pub fn decrypt_key(encrypted_b64: &str, password: &str) -> Result<String, WalletError> {
    let data = B64
        .decode(encrypted_b64)
        .map_err(|e| WalletError::DecryptionError(e.to_string()))?;
    if data.len() < 28 {
        return Err(WalletError::DecryptionError("Ciphertext too short".into()));
    }

    let (salt, rest) = data.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let mut salt_arr = [0u8; 16];
    salt_arr.copy_from_slice(salt);
    let aes_key = kdf(password, &salt_arr)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*aes_key));
    let nonce   = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| WalletError::DecryptionError("Decryption failed — wrong password?".into()))?;

    Ok(hex::encode(plaintext))
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_roundtrip() {
        let mn = generate_mnemonic();
        assert!(validate_mnemonic(&mn), "Generated mnemonic must be valid");
        assert_eq!(mn.split_whitespace().count(), 24, "Must be 24 words");
    }

    #[test]
    fn key_derivation_deterministic() {
        let mn = "abandon abandon abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon abandon abandon art";
        let r1 = derive_ghost_keys(mn, "").unwrap();
        let r2 = derive_ghost_keys(mn, "").unwrap();
        assert_eq!(r1, r2, "Key derivation must be deterministic");
    }

    #[test]
    fn paycode_roundtrip() {
        let mn = "abandon abandon abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon abandon abandon abandon art";
        let json: serde_json::Value =
            serde_json::from_str(&derive_ghost_keys(mn, "").unwrap()).unwrap();
        let paycode = json["paycode"].as_str().unwrap();
        assert!(paycode.len() > 10, "Paycode must be non-trivial");
        // Decode must succeed
        let spend_hex = json["spend_xpub"].as_str().unwrap();
        let scan_hex  = json["scan_xpub"].as_str().unwrap();
        let (s1, s2)  = decode_paycode(paycode).unwrap();
        assert_eq!(hex::encode(s1), spend_hex);
        assert_eq!(hex::encode(s2), scan_hex);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let encrypted = encrypt_key(key, "correct-horse-battery-staple").unwrap();
        let decrypted = decrypt_key(&encrypted, "correct-horse-battery-staple").unwrap();
        assert_eq!(key, decrypted);
    }

    #[test]
    fn wrong_password_fails() {
        let key = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";
        let encrypted = encrypt_key(key, "right-password").unwrap();
        let result = decrypt_key(&encrypted, "wrong-password");
        assert!(result.is_err(), "Wrong password must fail");
    }
}
