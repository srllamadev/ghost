# GhostPay — Architecture Deep Dive

## Answering the Four Strategic Questions

---

### Q1 — Electron Desktop vs. Browser Extension?

**Recommendation: Electron Desktop**

| Criterion | Electron Desktop | Browser Extension |
|---|---|---|
| **Private key security** | OS-level `safeStorage` (Keychain/DPAPI) | `chrome.storage.local` — accessible to other extensions |
| **SQLite support** | Native via `better-sqlite3` | No — must use IndexedDB |
| **Biometrics** | TouchID/FaceID via `safeStorage` | No native biometric API |
| **Offline use** | Full offline capability | Depends on background service worker |
| **WASM performance** | Node.js WASM — fast | Browser WASM — slightly constrained |
| **Auto-update** | `electron-updater` | Browser store approval delays |
| **Hackathon demo** | One binary, runs anywhere | Requires browser install |

**Verdict:** Electron wins on every security-relevant dimension. The OS keychain
provides a second layer of protection that no browser extension can match.
For the hackathon MVP, Electron lets us demo with a clean, installable `.AppImage`
or `.dmg` that judges can run in 30 seconds.

*Future plan:* Once the core is stable, a **browser extension** with degraded-but-
acceptable security (IndexedDB + software AES-256) can be built on top of the same
WASM core + React components with minimal changes.

---

### Q2 — IndexedDB vs. SQLite? (Schema included)

**Recommendation: SQLite for Electron, IndexedDB for web**

The same schema is used for both (see `app/src/store/db.ts`). Here it is annotated:

```sql
-- ─────────────────────────────────────────────────────────
-- Wallet singleton
-- ─────────────────────────────────────────────────────────
CREATE TABLE wallet_meta (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  network        TEXT NOT NULL,                -- "chipnet" | "mainnet"
  paycode        TEXT NOT NULL,                -- static GhostPay paycode (public)
  spend_xpub     TEXT NOT NULL,                -- compressed pubkey hex
  scan_xpub      TEXT NOT NULL,                -- compressed pubkey hex
  covenant_xpub  TEXT NOT NULL,                -- compressed pubkey hex
  created_at     INTEGER NOT NULL,             -- Unix ms
  last_synced_at INTEGER NOT NULL DEFAULT 0
);

-- ─────────────────────────────────────────────────────────
-- UTXOs (one row per discovered invisible payment)
-- ─────────────────────────────────────────────────────────
CREATE TABLE utxos (
  id             TEXT PRIMARY KEY,    -- "txid:vout"
  txid           TEXT NOT NULL,
  vout           INTEGER NOT NULL,
  value_sats     TEXT NOT NULL,       -- decimal string (avoids JS BigInt JSON issues)
  address        TEXT NOT NULL,       -- one-time P2PKH cashaddr
  tweak_hex      TEXT NOT NULL,       -- AES-256-GCM encrypted scalar tweak
                                      -- (used at spend time to re-derive one-time privkey)
  commitment_hex TEXT NOT NULL,       -- ephemeral pubkey from OP_RETURN (public)
  shard_index    INTEGER NOT NULL,    -- 0-15, deterministic
  height         INTEGER NOT NULL,    -- block confirmation height (0 = unconfirmed)
  spent          INTEGER NOT NULL,    -- SQLite boolean (0/1)
  spent_txid     TEXT                 -- txid of the spending transaction
);

CREATE INDEX idx_utxos_shard   ON utxos(shard_index);  -- fast per-shard queries
CREATE INDEX idx_utxos_address ON utxos(address);       -- fast "is this mine?" checks
CREATE INDEX idx_utxos_spent   ON utxos(spent);         -- fast balance computation

-- ─────────────────────────────────────────────────────────
-- Scan position (resume from last checked block per shard)
-- ─────────────────────────────────────────────────────────
CREATE TABLE scan_checkpoints (
  shard_index  INTEGER PRIMARY KEY,   -- 0-15
  last_height  INTEGER NOT NULL DEFAULT 0,
  updated_at   INTEGER NOT NULL DEFAULT 0
);
```

**Key decisions:**
- `value_sats TEXT` — avoids JSON integer overflow for large values (bigint safe).
- `tweak_hex TEXT` — the tweak is encrypted with AES-256-GCM before storage. If the
  database file is exfiltrated, the attacker gets UTXOs but cannot spend them.
- `commitment_hex TEXT` — the ephemeral pubkey is public data; no need to encrypt.
- Separate `scan_checkpoints` table enables resuming each shard independently,
  which is critical for recovering a wallet with millions of blocks to scan.

---

### Q3 — How to handle Stealth Change?

**Problem:** In a normal BCH transaction, a portion of the UTXO is "change" that
goes back to the sender. If this change goes to a known address, an observer can
link the sender's wallet across transactions.

**Solution: Stealth Change**

The sender generates a *second* SRPA payment directed at themselves:

```
Standard BCH inputs:  [Bob's regular UTXO]
Standard BCH outputs:
  1. ONE-TIME P2PKH (receiver Alice):  sha256(r1·B_scan_Alice) · G + B_spend_Alice
  2. ONE-TIME P2PKH (self change):     sha256(r2·B_scan_Bob)   · G + B_spend_Bob
  3. OP_RETURN:  <R1 — Alice's ephemeral pubkey> ‖ <R2 — Bob's change ephemeral pubkey>
```

Both outputs look identical on-chain — two P2PKH addresses with no link to any
historical address. Bob's scanner will find output #2 the same way Alice's scanner
finds output #1.

**Implementation in code:**
- `Send.tsx` calls `senderDerivePayment(meta.paycode, ..., vout=1)` for the change
  output (different `vout` = different tweak = different address).
- The second ephemeral pubkey is appended to the OP_RETURN payload.
- Bob's scanner processes *all* OP_RETURN payloads, so it naturally finds the change.

**OP_RETURN format (versioned):**
```
6a           OP_RETURN
4c           OP_PUSHDATA1
42           68 bytes total
01           Version 1 (two ephemeral keys)
<33 bytes>   Ephemeral key for output 0 (payment to receiver)
<33 bytes>   Ephemeral key for output 1 (change to self)
```

---

### Q4 — Security Checklist

See [SECURITY.md](SECURITY.md) for the full prioritized checklist with implementation
notes and threat model.

---

## SRPA Protocol — Full Technical Specification

### Key Derivation Tree

```
m/44'/145'/0'/0'/0  → spend_priv   (signs spending transactions)
m/44'/145'/0'/1'/0  → scan_priv    (performs ECDH scanning — read-only exposure)
m/44'/145'/0'/2'/0  → covenant_priv (signs CashScript covenant unlock scripts)
```

All three keys are derived with hardened indices to prevent child key compromise
from exposing the parent. The scan key is kept separate so that a "watch-only"
receiver can share it with a server-side scanner without exposing spending ability.

### SRPA Payment Flow (Sequence)

```
Sender (Alice)                              Receiver (Bob)
────────────────────────────────────────────────────────────────────────────────

1. Bob publishes:
   paycode = B58Check(0x47 ‖ spend_pub_B ‖ scan_pub_B ‖ checksum)

2. Alice wants to pay Bob:
   a. r  ← CSPRNG() (ephemeral scalar)
   b. R  = r·G        (ephemeral public key)
   c. S  = r·scan_pub_B  (ECDH shared secret x-coordinate)
   d. t  = SHA256(S.x ‖ le32(vout))  (scalar tweak, bound to outpoint)
   e. P  = spend_pub_B + t·G  (one-time public key — receiver's address)
   f. Build tx:
      - Output 0: P2PKH at P, amount = payment_sats
      - Output 1: P2PKH at stealth_change_addr, amount = change_sats  [optional]
      - Output 2: OP_RETURN  R  (+optional R_change)
   g. Sign with Alice's own UTXOs and broadcast.

3. Bob scans OP_RETURN:
   a. Parse R from OP_RETURN
   b. S  = scan_priv_B · R   (same shared secret as Alice's step c)
   c. t  = SHA256(S.x ‖ le32(vout))
   d. P  = spend_pub_B + t·G
   e. Query UTXO set: is there a UTXO at P?
   f. YES → "Funds appeared 🎉"
      spend_priv_OTA = spend_priv_B + t  (one-time private key for spending)

4. Bob spends:
   - Standard P2PKH scriptSig: <sig(spend_priv_OTA)> <spend_pub_OTA>
   - The covenant version adds: <ephemeral_pub_key> for on-chain binding
   - Tx looks like a normal P2PKH spend. No link to Bob's paycode.
```

### CashScript Covenant Integration

The covenant adds an extra guarantee: the UTXO at P is locked inside
`SrpaPool`, which enforces:

1. Only the holder of `spend_priv_OTA` (verified via `hash160(pubkey) == stored`)
   can unlock it.
2. An optional time-based reclaim for the sender after N blocks.
3. Token forwarding for CashTokens compatibility.

This means even if someone *knows* P, they cannot spend it without the private key.
The covenant binding of `ephemeralPubKey` as a parameter means every deployment is
uniquely identifiable by the CashScript compiler — no two deposits share a locking
script prefix.

### Post-Quantum Migration Path

The `Signer` trait in Rust is designed for this:

```rust
pub trait Signer: Send + Sync {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, WalletError>;
    fn public_key(&self) -> Result<Vec<u8>, WalletError>;
    fn algorithm(&self) -> SignerAlgorithm;
}
```

**Phase 1 (now):** `Secp256k1Signer` — standard BCH ECDSA.

**Phase 2 (post-quantum readiness):** The paycode format uses a versioned byte
(`0x47` currently). A future version byte (e.g., `0x48`) signals that the
`spend_pubkey` and `scan_pubkey` fields contain post-quantum key material
(e.g., SPHINCS+ or LM-OTS keys). The SRPA math changes slightly:

```
Instead of:  P = B_spend + t·G
We use:      P = LM-OTS_sign(B_spend, t)  [hash-based, no elliptic curve]
```

The `LmOtsSigner` struct implements the same `Signer` trait. **No UX changes
required** — the paycode string gets longer, but otherwise the flow is identical.

BCH Script can verify hash-based signatures with `OP_SHA256` chains, meaning
PQ signatures can be embedded in covenants without consensus changes.

### Sharded Pool — Why Shards Matter

The pool is not just an optimisation — it enables **deterministic wallet recovery**:

```
Given: mnemonic, scan_priv
For each outpoint in blockchain:
    shard_i = SHA256(txid ‖ scan_pub)[0:4] % 16
    Scan only shard_i's address range → O(1/16) work per shard

Recovery: restore from seed → re-derive scan_priv → replay all shards
          from their last checkpoint → balance restored in minutes, not hours.
```

Without shards, a full-history wallet scan could take 30+ minutes. With 16 shards
running in parallel, each processing 1/16th of the work, the same scan takes ~2
minutes on a mid-range laptop.
