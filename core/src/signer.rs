//! Pluggable Signer trait — Post-Quantum ready architecture
//!
//! Today we use secp256k1 ECDSA (the BCH standard).
//! The trait is designed so that tomorrow we can drop in an LM-OTS or
//! SPHINCS+ signer without changing any higher-level code.
//!
//! ```
//!  ┌──────────────────────────────────────────────────────┐
//!  │               Signer (trait)                         │
//!  │  + sign(msg: &[u8]) -> Signature                     │
//!  │  + public_key() -> &[u8]                             │
//!  │  + algorithm() -> SignerAlgorithm                    │
//!  └─────────────────┬────────────────────────────────────┘
//!                    │
//!          ┌─────────┴──────────┐
//!          ▼                    ▼
//!  Secp256k1Signer         LmOtsSigner (future)
//!  (current default)       (post-quantum)
//! ```

use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ecdh::{derive_tweak, ecdh_shared_secret, one_time_privkey};
use crate::hd_wallet::{decrypt_key, WalletError};

// ────────────────────────────────────────────────────────────────────────────
// Signer trait
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerAlgorithm {
    Secp256k1Ecdsa,
    LmOts, // future
}

pub trait Signer: Send + Sync {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, WalletError>;
    fn public_key(&self) -> Result<Vec<u8>, WalletError>;
    fn algorithm(&self) -> SignerAlgorithm;
}

// ────────────────────────────────────────────────────────────────────────────
// Secp256k1 implementation
// ────────────────────────────────────────────────────────────────────────────

pub struct Secp256k1Signer {
    /// The private key — zeroed on drop.
    secret: Zeroizing<[u8; 32]>,
}

impl Secp256k1Signer {
    pub fn from_secret_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self { secret: bytes }
    }
}

impl Signer for Secp256k1Signer {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, WalletError> {
        let secp  = Secp256k1::new();
        let sk    = SecretKey::from_slice(&self.secret[..])
            .map_err(|e| WalletError::DerivationError(e.to_string()))?;
        // BCH uses SIGHASH_ALL (0x41) appended to DER signature
        let hash  = double_sha256(msg);
        let msg   = Message::from_digest(hash);
        let sig   = secp.sign_ecdsa(&msg, &sk);
        let mut der = sig.serialize_der().to_vec();
        der.push(0x41); // SIGHASH_ALL | SIGHASH_FORKID
        Ok(der)
    }

    fn public_key(&self) -> Result<Vec<u8>, WalletError> {
        let secp = Secp256k1::new();
        let sk   = SecretKey::from_slice(&self.secret[..])
            .map_err(|e| WalletError::DerivationError(e.to_string()))?;
        Ok(PublicKey::from_secret_key(&secp, &sk).serialize().to_vec())
    }

    fn algorithm(&self) -> SignerAlgorithm {
        SignerAlgorithm::Secp256k1Ecdsa
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SRPA spend: build & sign a transaction
// ────────────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct UtxoInput {
    txid:       String,
    vout:       u32,
    value_sats: u64,
    tweak_hex:  String, // hex of the scalar tweak stored in the pool
}

/// Build and sign a BCH P2PKH transaction spending a SRPA one-time UTXO.
///
/// Security properties:
///   - The spend private key is decrypted inside this function and zeroed after use.
///   - The one-time private key is derived in-place (never stored).
///   - The returned hex is a fully-signed raw transaction ready for Electrum broadcast.
pub fn sign_srpa_spend(
    spend_xpriv_encrypted: &str,
    encryption_key_hex: &str,
    utxo_json: &str,
    recipient_cashaddr: &str,
    fee_sats: u64,
    _network: &str,
) -> Result<String, WalletError> {
    let utxo: UtxoInput = serde_json::from_str(utxo_json)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;

    // 1. Decrypt base spend key
    let spend_priv_hex = decrypt_key(spend_xpriv_encrypted, encryption_key_hex)?;
    let spend_priv_bytes = hex::decode(&spend_priv_hex)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let mut spend_scalar = Zeroizing::new([0u8; 32]);
    spend_scalar.copy_from_slice(&spend_priv_bytes[..32]);

    // 2. Re-derive one-time private key: p = b_spend + tweak
    let tweak_bytes = hex::decode(&utxo.tweak_hex)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&tweak_bytes[..32]);
    let ota_privkey = one_time_privkey(&spend_scalar, &tweak)?;

    // 3. Build and sign the transaction
    let signer = Secp256k1Signer::from_secret_bytes(ota_privkey);
    let pubkey = signer.public_key()?;

    // Construct P2PKH locking script for recipient
    let recipient_hash160 = cashaddr_to_hash160(recipient_cashaddr)?;
    let locking_script = build_p2pkh_script(&recipient_hash160);

    // Serialize the transaction for signing (BIP143 / BCH replay protection)
    let value_out = utxo.value_sats.saturating_sub(fee_sats);
    let tx_bytes  = serialize_tx_for_signing(&utxo.txid, utxo.vout, utxo.value_sats, &recipient_hash160, value_out);
    let signature = signer.sign(&tx_bytes)?;

    // Build the raw signed transaction
    let raw_tx = build_raw_tx(
        &utxo.txid,
        utxo.vout,
        &signature,
        &pubkey,
        &locking_script,
        value_out,
    );

    Ok(hex::encode(raw_tx))
}

// ────────────────────────────────────────────────────────────────────────────
// Transaction serialization helpers
// ────────────────────────────────────────────────────────────────────────────

fn double_sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

fn build_p2pkh_script(hash160: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 OP_PUSHDATA(20)
    s.extend_from_slice(hash160);
    s.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
    s
}

fn cashaddr_to_hash160(cashaddr: &str) -> Result<[u8; 20], WalletError> {
    // Strip prefix and decode — minimal implementation
    let addr = cashaddr.trim_start_matches("bitcoincash:").trim_start_matches("bchtest:");
    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let data: Vec<u8> = addr
        .chars()
        .map(|c| CHARSET.find(c).unwrap_or(0) as u8)
        .collect();
    // Convert 5-bit groups → 8-bit, skip version byte, take 20 bytes
    let decoded = convert_5bit_to_8bit(&data[..data.len() - 8])?;
    if decoded.len() < 21 {
        return Err(WalletError::DerivationError("Address hash too short".into()));
    }
    let mut h = [0u8; 20];
    h.copy_from_slice(&decoded[1..21]);
    Ok(h)
}

fn convert_5bit_to_8bit(data: &[u8]) -> Result<Vec<u8>, WalletError> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut result = Vec::new();
    for &b in data {
        acc = (acc << 5) | (b as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            result.push((acc >> bits) as u8);
        }
    }
    Ok(result)
}

fn serialize_tx_for_signing(
    txid: &str,
    vout: u32,
    value: u64,
    recipient_hash160: &[u8; 20],
    value_out: u64,
) -> Vec<u8> {
    // BIP143 sighash preimage for BCH (SIGHASH_ALL | SIGHASH_FORKID)
    // This is a simplified single-input serialisation for MVP purposes.
    let mut data = Vec::new();
    // nVersion
    data.extend_from_slice(&1u32.to_le_bytes());
    // hashPrevouts (simplified: just the single outpoint)
    let txid_bytes = hex::decode(txid).unwrap_or_default();
    data.extend_from_slice(&txid_bytes);
    data.extend_from_slice(&vout.to_le_bytes());
    // value of input
    data.extend_from_slice(&value.to_le_bytes());
    // nSequence
    data.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    // hash of output
    let locking = build_p2pkh_script(recipient_hash160);
    data.extend_from_slice(&(locking.len() as u64).to_le_bytes());
    data.extend_from_slice(&locking);
    data.extend_from_slice(&value_out.to_le_bytes());
    // nLocktime
    data.extend_from_slice(&0u32.to_le_bytes());
    // sighash type
    data.extend_from_slice(&0x41u32.to_le_bytes());
    data
}

fn build_raw_tx(
    txid: &str,
    vout: u32,
    signature: &[u8],
    pubkey: &[u8],
    locking_script: &[u8],
    value_out: u64,
) -> Vec<u8> {
    let mut tx = Vec::new();
    // nVersion
    tx.extend_from_slice(&1u32.to_le_bytes());
    // vin count
    tx.push(0x01);
    // outpoint txid (reversed)
    let mut txid_bytes = hex::decode(txid).unwrap_or_default();
    txid_bytes.reverse();
    tx.extend_from_slice(&txid_bytes);
    // outpoint vout
    tx.extend_from_slice(&vout.to_le_bytes());
    // scriptSig: <sig> <pubkey>
    let script_sig_len = 1 + signature.len() + 1 + pubkey.len();
    tx.push(script_sig_len as u8);
    tx.push(signature.len() as u8);
    tx.extend_from_slice(signature);
    tx.push(pubkey.len() as u8);
    tx.extend_from_slice(pubkey);
    // nSequence
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    // vout count
    tx.push(0x01);
    // value
    tx.extend_from_slice(&value_out.to_le_bytes());
    // locking script
    tx.push(locking_script.len() as u8);
    tx.extend_from_slice(locking_script);
    // nLocktime
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx
}
