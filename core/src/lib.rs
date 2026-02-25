//! GhostPay Core — WASM-exposed public API
//!
//! All sensitive key operations live here in Rust. The TypeScript layer
//! only ever touches *public* data (addresses, paycodes, serialised txns).
//! Private key material is held exclusively in Rust memory and zeroed on drop.

mod covenant;
mod ecdh;
mod hd_wallet;
mod signer;
pub mod srpa;

use wasm_bindgen::prelude::*;

// Re-export error panic hook so JS gets readable panics in dev mode
#[cfg(feature = "console_error_panic_hook")]
pub use console_error_panic_hook::set_once as set_panic_hook;

// ────────────────────────────────────────────────────────────────────────────
// Wallet creation / restoration
// ────────────────────────────────────────────────────────────────────────────

/// Generate a fresh BIP-39 mnemonic (24 words).
/// Returns the mnemonic string — caller MUST encrypt before persisting.
#[wasm_bindgen]
pub fn generate_mnemonic() -> String {
    hd_wallet::generate_mnemonic()
}

/// Validate a BIP-39 mnemonic.
#[wasm_bindgen]
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    hd_wallet::validate_mnemonic(mnemonic)
}

/// Derive the GhostPay 3-key bundle from a mnemonic + optional passphrase.
/// Returns a JSON string:
/// ```json
/// {
///   "spend_xpub":   "...",
///   "scan_xpub":    "...",
///   "covenant_xpub":"...",
///   "paycode":      "ghostpay:<base58check>"
/// }
/// ```
/// The *private* keys never cross the WASM boundary.
#[wasm_bindgen]
pub fn derive_keys(mnemonic: &str, passphrase: &str) -> Result<String, JsValue> {
    hd_wallet::derive_ghost_keys(mnemonic, passphrase)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ────────────────────────────────────────────────────────────────────────────
// SRPA — Sender side
// ────────────────────────────────────────────────────────────────────────────

/// Given a receiver's paycode and the funding outpoint, produce:
///   { ephemeral_pubkey_hex, one_time_address_cashaddr }
///
/// The ephemeral private key is used internally to sign; it is zeroed after
/// the function returns.
#[wasm_bindgen]
pub fn sender_derive_payment(
    receiver_paycode: &str,
    funding_txid: &str,
    vout: u32,
    network: &str,          // "chipnet" | "mainnet"
) -> Result<String, JsValue> {
    srpa::sender_derive_payment(receiver_paycode, funding_txid, vout, network)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ────────────────────────────────────────────────────────────────────────────
// SRPA — Receiver side
// ────────────────────────────────────────────────────────────────────────────

/// Scan a candidate OP_RETURN payload for an incoming SRPA payment.
/// Returns the derived one-time address if it belongs to us, or null.
#[wasm_bindgen]
pub fn receiver_scan_opreturn(
    scan_xpriv_encrypted: &str,   // AES-256-GCM encrypted scan private key
    encryption_key_hex: &str,     // 32-byte key derived from PIN/biometric
    ephemeral_pubkey_hex: &str,
    spend_xpub: &str,
    outpoint_index: u32,
    network: &str,
) -> Result<String, JsValue> {
    srpa::receiver_scan(
        scan_xpriv_encrypted,
        encryption_key_hex,
        ephemeral_pubkey_hex,
        spend_xpub,
        outpoint_index,
        network,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ────────────────────────────────────────────────────────────────────────────
// Transaction signing (spend a SRPA UTXO)
// ────────────────────────────────────────────────────────────────────────────

/// Build and sign a transaction that spends a one-time SRPA UTXO.
/// `utxo_json` must include: txid, vout, value_sats, one_time_wif (encrypted).
/// Returns the raw hex-encoded signed transaction ready for broadcast.
#[wasm_bindgen]
pub fn sign_srpa_spend(
    spend_xpriv_encrypted: &str,
    encryption_key_hex: &str,
    utxo_json: &str,
    recipient_cashaddr: &str,
    fee_sats: u64,
    network: &str,
) -> Result<String, JsValue> {
    signer::sign_srpa_spend(
        spend_xpriv_encrypted,
        encryption_key_hex,
        utxo_json,
        recipient_cashaddr,
        fee_sats,
        network,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ────────────────────────────────────────────────────────────────────────────
// Covenant ABI helpers
// ────────────────────────────────────────────────────────────────────────────

/// Serialize an unlock script (scriptSig) for the SRPA pool covenant.
/// This is the data that goes into the covenant's `unlocking_bytecode`.
#[wasm_bindgen]
pub fn build_covenant_unlock(
    spend_sig_hex: &str,
    spend_pubkey_hex: &str,
    ephemeral_pubkey_hex: &str,
) -> String {
    covenant::build_unlock(spend_sig_hex, spend_pubkey_hex, ephemeral_pubkey_hex)
}

// ────────────────────────────────────────────────────────────────────────────
// Key encryption / decryption (AES-256-GCM + argon2id)
// ────────────────────────────────────────────────────────────────────────────

/// Encrypt raw key bytes with argon2id-stretched password.
/// Returns base64(nonce ‖ ciphertext ‖ tag).
#[wasm_bindgen]
pub fn encrypt_key(raw_key_hex: &str, password: &str) -> Result<String, JsValue> {
    hd_wallet::encrypt_key(raw_key_hex, password)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Decrypt a key previously encrypted with `encrypt_key`.
#[wasm_bindgen]
pub fn decrypt_key(encrypted_b64: &str, password: &str) -> Result<String, JsValue> {
    hd_wallet::decrypt_key(encrypted_b64, password)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
