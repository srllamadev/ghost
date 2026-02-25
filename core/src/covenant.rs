//! CashScript Covenant ABI helpers
//!
//! This module serializes the data needed to call functions on the
//! SRPA pool covenant defined in `contracts/srpa_pool.cash`.
//!
//! The covenant ABI is designed to be "ZK-ready":
//!   - The covenant only checks what it absolutely must (signature validity and
//!     key ownership). Extra data (e.g., a ZK proof) can be appended without
//!     breaking existing unlock scripts by using a versioned envelope.
//!
//! Covenant function: `spend(sig: Sig, pubkey: PubKey, ephemeralPubKey: bytes33)`
//!
//! Unlock (scriptSig) byte layout:
//!   [0x00]                       version byte (0 = ECDSA + ephemeral key)
//!   [varint] signature_len       DER signature + sighash byte
//!   [signature bytes]
//!   [0x21]                       push 33 bytes
//!   [33 bytes]                   compressed pubkey
//!   [0x21]                       push 33 bytes
//!   [33 bytes]                   ephemeral pubkey (OP_RETURN payload back-reference)

/// Serialize the unlocking bytecode for the SRPA pool covenant.
pub fn build_unlock(
    spend_sig_hex: &str,
    spend_pubkey_hex: &str,
    ephemeral_pubkey_hex: &str,
) -> String {
    let sig  = hex::decode(spend_sig_hex).unwrap_or_default();
    let spk  = hex::decode(spend_pubkey_hex).unwrap_or_default();
    let epk  = hex::decode(ephemeral_pubkey_hex).unwrap_or_default();

    let mut script = Vec::new();

    // Version envelope
    script.push(0x00);

    // Push signature (OP_PUSHDATA1 or direct push)
    push_bytes(&mut script, &sig);
    // Push spend pubkey (must be 33 bytes)
    if spk.len() == 33 {
        script.push(0x21);
        script.extend_from_slice(&spk);
    }
    // Push ephemeral pubkey (must be 33 bytes)
    if epk.len() == 33 {
        script.push(0x21);
        script.extend_from_slice(&epk);
    }

    hex::encode(script)
}

/// Minimal OP_PUSHDATA serializer for BCH script.
fn push_bytes(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 75 {
        script.push(len as u8);
    } else if len <= 255 {
        script.push(0x4c); // OP_PUSHDATA1
        script.push(len as u8);
    } else {
        script.push(0x4d); // OP_PUSHDATA2
        script.extend_from_slice(&(len as u16).to_le_bytes());
    }
    script.extend_from_slice(data);
}

/// Shard index for deterministic UTXO pool placement.
///
/// Given a deposit txid and receiver scan pubkey, always returns the same
/// shard index. This makes the pool restorable from seed without scanning
/// every shard.
///
/// Formula: SHA256(txid ‖ receiver_scan_pubkey_hex) mod total_shards
pub fn get_shard_index(deposit_txid: &str, receiver_scan_pubkey_hex: &str, total_shards: u32) -> u32 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(deposit_txid.as_bytes());
    hasher.update(receiver_scan_pubkey_hex.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    // Take first 4 bytes as u32 big-endian
    let n = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    n % total_shards
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_index_deterministic() {
        let txid  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let rpk   = "02deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe01";
        let idx1  = get_shard_index(txid, rpk, 16);
        let idx2  = get_shard_index(txid, rpk, 16);
        assert_eq!(idx1, idx2, "Shard index must be deterministic");
        assert!(idx1 < 16, "Shard index must be within range");
    }

    #[test]
    fn unlock_script_non_empty() {
        let sig  = "30440220aabbcc0220ddeeff41";
        let spk  = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let epk  = "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let hex  = build_unlock(sig, spk, epk);
        assert!(!hex.is_empty());
    }
}
