//! ECDH shared-secret derivation for SRPA
//!
//! The core math:
//!   Sender:   S = r · B_scan       (r = ephemeral scalar, B_scan = receiver scan pubkey)
//!   Receiver: S = b_scan · R       ( b_scan = receiver scan privkey, R = ephemeral pubkey)
//!   Both sides arrive at the same S because r·(b_scan·G) == b_scan·(r·G).
//!
//! The shared secret is then hashed to produce a scalar tweak:
//!   t = SHA256( S_x ‖ outpoint_index_le32 )
//!
//! One-time spend key:
//!   Sender sees:   P = B_spend + t·G    (public key only)
//!   Receiver owns: p = b_spend + t       (private key)

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::hd_wallet::WalletError;

/// Compute ECDH: multiply a public key by a scalar.
/// Returns the x-coordinate of the resulting curve point (32 bytes).
pub fn ecdh_shared_secret(
    scalar_bytes: &[u8; 32],
    pubkey_bytes: &[u8; 33],
) -> Result<[u8; 32], WalletError> {
    let secp   = Secp256k1::new();
    let sk     = SecretKey::from_slice(scalar_bytes)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let pk     = PublicKey::from_slice(pubkey_bytes)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let shared = pk.mul_tweak(&secp, &sk.into())
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let mut x = [0u8; 32];
    x.copy_from_slice(&shared.serialize()[1..33]); // compressed point x-coord
    Ok(x)
}

/// Derive the scalar tweak t = SHA256( shared_secret_x ‖ outpoint_index_le32 ).
pub fn derive_tweak(shared_x: &[u8; 32], outpoint_index: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared_x);
    hasher.update(outpoint_index.to_le_bytes());
    hasher.finalize().into()
}

/// Compute the one-time *public* key P = B_spend + t·G.
/// Used by the sender to know where to send funds.
pub fn one_time_pubkey(
    spend_pubkey: &[u8; 33],
    tweak: &[u8; 32],
) -> Result<[u8; 33], WalletError> {
    let secp = Secp256k1::new();
    let pk   = PublicKey::from_slice(spend_pubkey)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let tweaked = pk
        .add_exp_tweak(&secp, &secp256k1::Scalar::from_be_bytes(*tweak)
            .map_err(|_| WalletError::DerivationError("tweak scalar overflow".into()))?)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    Ok(tweaked.serialize())
}

/// Compute the one-time *private* key p = b_spend + t  (mod n).
/// Used by the receiver to spend the UTXO.
pub fn one_time_privkey(
    spend_privkey: &Zeroizing<[u8; 32]>,
    tweak: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let secp = Secp256k1::new();
    let sk   = SecretKey::from_slice(&spend_privkey[..])
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let tweaked = sk
        .add_tweak(&secp256k1::Scalar::from_be_bytes(*tweak)
            .map_err(|_| WalletError::DerivationError("tweak scalar overflow".into()))?)
        .map_err(|e| WalletError::DerivationError(e.to_string()))?;
    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&tweaked.secret_bytes());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    /// Verify that sender and receiver arrive at the same shared secret.
    #[test]
    fn ecdh_symmetry() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        // Alice's ephemeral key
        let mut alice_scalar = [0u8; 32];
        rng.fill_bytes(&mut alice_scalar);
        let alice_sk = SecretKey::from_slice(&alice_scalar).unwrap();
        let alice_pk = PublicKey::from_secret_key(&secp, &alice_sk).serialize();

        // Bob's scan key
        let mut bob_scalar = [0u8; 32];
        rng.fill_bytes(&mut bob_scalar);
        let bob_sk = SecretKey::from_slice(&bob_scalar).unwrap();
        let bob_pk = PublicKey::from_secret_key(&secp, &bob_sk).serialize();

        // Alice computes: S = alice_sk · bob_pk
        let s_alice = ecdh_shared_secret(&alice_scalar, &bob_pk).unwrap();

        // Bob computes: S = bob_sk · alice_pk
        let s_bob = ecdh_shared_secret(&bob_scalar, &alice_pk).unwrap();

        assert_eq!(s_alice, s_bob, "ECDH must produce the same shared secret");
    }

    /// Verify that sender's public key matches the receiver's private key.
    #[test]
    fn one_time_keys_match() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        // Ephemeral (sender)
        let mut r_bytes = [0u8; 32];
        rng.fill_bytes(&mut r_bytes);
        let r = SecretKey::from_slice(&r_bytes).unwrap();

        // Spend key (receiver)
        let mut b_spend_bytes = [0u8; 32];
        rng.fill_bytes(&mut b_spend_bytes);
        let b_spend = SecretKey::from_slice(&b_spend_bytes).unwrap();
        let b_spend_pub = PublicKey::from_secret_key(&secp, &b_spend).serialize();

        // Scan key (receiver)
        let mut b_scan_bytes = [0u8; 32];
        rng.fill_bytes(&mut b_scan_bytes);
        let b_scan = SecretKey::from_slice(&b_scan_bytes).unwrap();
        let b_scan_pub = PublicKey::from_secret_key(&secp, &b_scan).serialize();
        let r_pub = PublicKey::from_secret_key(&secp, &r).serialize();

        // Sender's ECDH
        let s_sender = ecdh_shared_secret(&r_bytes, &b_scan_pub).unwrap();
        // Receiver's ECDH
        let s_receiver = ecdh_shared_secret(&b_scan_bytes, &r_pub).unwrap();
        assert_eq!(s_sender, s_receiver);

        let tweak = derive_tweak(&s_sender, 0);
        let pub_from_sender = one_time_pubkey(&b_spend_pub, &tweak).unwrap();
        let priv_from_receiver =
            one_time_privkey(&Zeroizing::new(b_spend_bytes), &tweak).unwrap();
        let pub_from_receiver =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&*priv_from_receiver).unwrap())
                .serialize();

        assert_eq!(pub_from_sender, pub_from_receiver,
            "One-time public key must match on both sides");
    }
}
