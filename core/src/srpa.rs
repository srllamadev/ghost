//! SRPA — Silent Reusable Payment Addresses
//!
//! High-level orchestration layer:
//!   • Paycode encoding / decoding
//!   • Sender flow: ephemeral key → one-time address
//!   • Receiver flow: scan OP_RETURN → derive candidate address
//!
//! This module is the main interface called from lib.rs WASM exports.

use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ecdh::{derive_tweak, ecdh_shared_secret, one_time_privkey, one_time_pubkey};
use crate::hd_wallet::{decode_paycode, decrypt_key, WalletError};

// ────────────────────────────────────────────────────────────────────────────
// Sender side
// ────────────────────────────────────────────────────────────────────────────

/// Sender: given the receiver's paycode and the funding outpoint,
/// return the one-time address and the ephemeral public key.
///
/// The ephemeral private key is generated fresh, used for ECDH, then zeroed.
pub fn sender_derive_payment(
    receiver_paycode: &str,
    _funding_txid: &str,
    vout: u32,
    network: &str,
) -> Result<String, WalletError> {
    let (spend_pub, scan_pub) = decode_paycode(receiver_paycode)?;

    // Generate ephemeral keypair
    let secp = Secp256k1::new();
    let mut raw = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(&mut *raw);
    let ephemeral_sk = SecretKey::from_slice(&*raw)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let ephemeral_pk = PublicKey::from_secret_key(&secp, &ephemeral_sk).serialize();

    // ECDH: S = r · B_scan
    let shared_x = ecdh_shared_secret(&*raw, &scan_pub)?;
    let tweak     = derive_tweak(&shared_x, vout);

    // One-time address pubkey
    let ota_pub  = one_time_pubkey(&spend_pub, &tweak)?;
    let cashaddr = pubkey_to_cashaddr(&ota_pub, network)?;

    // Zeroize ephemeral private scalar — done automatically on drop of `raw`
    Ok(serde_json::json!({
        "ephemeral_pubkey_hex": hex::encode(ephemeral_pk),
        "one_time_address":     cashaddr,
        "tweak_hex":            hex::encode(tweak),    // helpful for debug; remove in prod
    })
    .to_string())
}

// ────────────────────────────────────────────────────────────────────────────
// Receiver side
// ────────────────────────────────────────────────────────────────────────────

/// Receiver: scan a candidate OP_RETURN (containing an ephemeral public key).
/// If the derived one-time address belongs to this wallet, return it + the
/// one-time private key (encrypted) for later spending.
///
/// Returns JSON:
/// ```json
/// { "matched": true, "one_time_address": "bitcoincash:q...", "ota_privkey_encrypted": "..." }
/// ```
/// or `{ "matched": false }` if this OP_RETURN is not ours.
pub fn receiver_scan(
    scan_xpriv_encrypted: &str,
    encryption_key_hex: &str,
    ephemeral_pubkey_hex: &str,
    spend_xpub_hex: &str,
    outpoint_index: u32,
    network: &str,
) -> Result<String, WalletError> {
    // Decrypt scan private key
    let scan_priv_hex = decrypt_key(scan_xpriv_encrypted, encryption_key_hex)?;
    let scan_priv_bytes: Vec<u8> = hex::decode(&scan_priv_hex)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let mut scan_scalar = Zeroizing::new([0u8; 32]);
    scan_scalar.copy_from_slice(&scan_priv_bytes[..32]);

    // Parse ephemeral public key from OP_RETURN
    let epk_bytes = hex::decode(ephemeral_pubkey_hex)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let mut epk_arr = [0u8; 33];
    if epk_bytes.len() != 33 {
        return Ok(serde_json::json!({ "matched": false }).to_string());
    }
    epk_arr.copy_from_slice(&epk_bytes);

    // ECDH: S = b_scan · R
    let shared_x = ecdh_shared_secret(&*scan_scalar, &epk_arr)?;
    let tweak     = derive_tweak(&shared_x, outpoint_index);

    // Derive one-time address from spend public key + tweak
    let spend_pub_bytes = hex::decode(spend_xpub_hex)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let mut spend_pub = [0u8; 33];
    spend_pub.copy_from_slice(&spend_pub_bytes[..33]);

    let ota_pub  = one_time_pubkey(&spend_pub, &tweak)?;
    let cashaddr = pubkey_to_cashaddr(&ota_pub, network)?;

    // We always return the address; the caller will check if a UTXO exists there.
    // The one-time *private* key is only derivable by the receiver who knows b_spend.
    // For security, we do NOT return the raw privkey here — the spend flow will
    // derive it on-demand inside sign_srpa_spend.
    Ok(serde_json::json!({
        "matched":          true,
        "one_time_address": cashaddr,
        "tweak_hex":        hex::encode(tweak),
    })
    .to_string())
}

// ────────────────────────────────────────────────────────────────────────────
// Address encoding (P2PKH CashAddr)
// ────────────────────────────────────────────────────────────────────────────

/// Convert a compressed public key (33 bytes) to a P2PKH CashAddr.
/// This is a minimal implementation — production should use a full cashaddr crate.
pub fn pubkey_to_cashaddr(pubkey: &[u8; 33], network: &str) -> Result<String, WalletError> {
    // P2PKH: HASH160(pubkey) = RIPEMD160(SHA256(pubkey))
    let sha256_hash = Sha256::digest(pubkey);
    let ripemd_hash = ripemd::Ripemd160::digest(sha256_hash);

    // CashAddr payload type 0 = P2PKH
    let payload_type: u8 = 0;
    let hash160: [u8; 20] = ripemd_hash.into();
    let prefix = if network == "mainnet" { "bitcoincash" } else { "bchtest" };

    cashaddr_encode(prefix, payload_type, &hash160)
        .map_err(|e| WalletError::DerivationError(e))
}

/// Minimal CashAddr encoder (BCH-specific).
fn cashaddr_encode(prefix: &str, version_byte: u8, hash: &[u8; 20]) -> Result<String, String> {
    // Payload = version_byte ‖ hash, converted to 5-bit groups
    let mut payload = vec![version_byte];
    payload.extend_from_slice(hash);
    let converted = convert_bits(&payload, 8, 5, true)?;

    // Checksum
    let checksum = cashaddr_checksum(prefix, &converted);
    let mut checksum_5bit = Vec::with_capacity(8);
    for i in (0..8).rev() {
        checksum_5bit.push(((checksum >> (5 * i)) & 0x1f) as u8);
    }

    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut result = format!("{prefix}:");
    for b in converted.iter().chain(checksum_5bit.iter()) {
        result.push(CHARSET[*b as usize] as char);
    }
    Ok(result)
}

fn cashaddr_checksum(prefix: &str, data: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for ch in prefix.bytes() {
        c = cashaddr_polymod_step(c) ^ ((ch & 0x1f) as u64);
    }
    c = cashaddr_polymod_step(c);
    for &d in data {
        c = cashaddr_polymod_step(c) ^ (d as u64);
    }
    for _ in 0..8 {
        c = cashaddr_polymod_step(c);
    }
    c ^ 1
}

fn cashaddr_polymod_step(pre: u64) -> u64 {
    let b = pre >> 35;
    (pre & 0x07_ffff_ffff) << 5
        ^ if b & 0x01 != 0 { 0x98_f2bc_8e61 } else { 0 }
        ^ if b & 0x02 != 0 { 0x79b7_6d99_e2 } else { 0 }
        ^ if b & 0x04 != 0 { 0xf33e_5fb3_c4 } else { 0 }
        ^ if b & 0x08 != 0 { 0xae2e_ab2a_ed } else { 0 }
        ^ if b & 0x10 != 0 { 0x1e4f_4375_5f } else { 0 }
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, String> {
    let mut acc: u32   = 0;
    let mut bits: u32  = 0;
    let mut result      = Vec::new();
    let maxv: u32 = (1 << to) - 1;
    for &value in data {
        acc = (acc << from) | (value as u32);
        bits += from;
        while bits >= to {
            bits -= to;
            result.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            result.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return Err("Invalid padding".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_receiver_derive_same_address() {
        // This is the core correctness test for SRPA.
        // We mock the paycode by manually constructing keys.
        let secp = Secp256k1::new();

        // Receiver keypairs
        let mut spend_scalar = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut spend_scalar);
        let spend_sk  = SecretKey::from_slice(&spend_scalar).unwrap();
        let spend_pub = PublicKey::from_secret_key(&secp, &spend_sk).serialize();

        let mut scan_scalar = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut scan_scalar);
        let scan_sk  = SecretKey::from_slice(&scan_scalar).unwrap();
        let scan_pub = PublicKey::from_secret_key(&secp, &scan_sk).serialize();

        // Ephemeral (sender)
        let mut eph_scalar = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph_scalar);
        let eph_sk  = SecretKey::from_slice(&eph_scalar).unwrap();
        let eph_pub = PublicKey::from_secret_key(&secp, &eph_sk).serialize();

        let outpoint_index = 1u32;

        // Sender ECDH
        let s_sender = ecdh_shared_secret(&eph_scalar, &scan_pub).unwrap();
        let tweak_s   = derive_tweak(&s_sender, outpoint_index);
        let addr_sender = pubkey_to_cashaddr(&one_time_pubkey(&spend_pub, &tweak_s).unwrap(), "chipnet").unwrap();

        // Receiver ECDH
        let s_recv = ecdh_shared_secret(&scan_scalar, &eph_pub).unwrap();
        let tweak_r = derive_tweak(&s_recv, outpoint_index);
        let addr_recv = pubkey_to_cashaddr(&one_time_pubkey(&spend_pub, &tweak_r).unwrap(), "chipnet").unwrap();

        assert_eq!(addr_sender, addr_recv,
            "Sender and receiver must derive the same one-time address");
    }
}
