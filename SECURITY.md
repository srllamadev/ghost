# GhostPay — Security Checklist & Threat Model

## Threat Model

| Threat Actor | Capability | Primary Defence |
|---|---|---|
| Passive blockchain observer | Full read access to all on-chain data | SRPA one-time addresses; OP_RETURN is the only on-chain link |
| Active network attacker | Man-in-the-middle on Electrum RPC | SPV header verification; TLS + cert pinning |
| Malicious dApp (WC2) | Craft malicious transaction requests | Clear-signing UI; method whitelist; session scoping |
| Local device attacker (physical) | Reads filesystem / memory dumps | AES-256-GCM encrypted storage; argon2id KDF; safeStorage |
| Compromised scan key | Can detect payments but NOT spend | Spend key and scan key are independent derivation paths |
| Supply chain (npm/cargo) | Malicious dependency | lockfile pinning; `cargo audit`; Dependabot |

---

## Security Checklist (Priority Order)

### P0 — Non-Negotiable (ship before testnet)

- [x] **AES-256-GCM key encryption**
  - All private keys and scalar tweaks stored encrypted at rest.
  - KDF: `argon2id` with m=64 MiB, t=3, p=4 — ~250 ms on mid-range hardware.
  - Salt: 16 bytes CSPRNG per encryption operation (never reused).
  - Implemented in: `core/src/hd_wallet.rs` — `encrypt_key` / `decrypt_key`.

- [x] **Keys never leave the Rust core**
  - WASM exports return only public data (addresses, signatures, paycodes).
  - Private key bytes are `Zeroizing<[u8; 32]>` — zeroed on drop automatically.
  - The TypeScript layer holds only encrypted blobs, never raw hex privkeys.

- [x] **Clear-signing modal before every broadcast**
  - Implemented in `ClearSignModal.tsx`.
  - Shows: recipient address, amount, fee, change address, ephemeral pubkey.
  - No "approve all" or silent signing — every transaction requires explicit user tap.

- [x] **No key material in logs or error messages**
  - `WalletError` variants never include key bytes.
  - `Zeroizing<>` types automatically zero memory before drop.
  - Electron's renderer is sandboxed — no `console.log` of sensitive data.

- [x] **CSPRNG for all random material**
  - Rust: `rand::thread_rng()` backed by OS CSPRNG (`/dev/urandom` on Linux).
  - WASM: `getrandom` crate with `js` feature (uses `crypto.getRandomValues`).
  - Never use `Math.random()` for cryptographic material.

### P1 — Ship Before Mainnet

- [ ] **Biometric unlock (Electron `safeStorage`)**
  - `safeStorage.encryptString(pin_derived_key)` — OS handles biometric gate.
  - On macOS: protected by Secure Enclave / TouchID.
  - On Linux: uses `libsecret`. On Windows: DPAPI + Windows Hello.
  - Implementation: `electron/main.ts` — `safe-storage:encrypt` / `safe-storage:decrypt` IPC.

- [ ] **PIN brute-force protection**
  - After 5 failed PIN attempts: 60-second lockout, doubling on each failure.
  - After 10 total failed attempts: wipe in-memory decryption key (requires passphrase re-entry).
  - Do NOT wipe on-disk data automatically — avoid creating a denial-of-service via repeated wrong PINs.

- [ ] **Transaction replay protection**
  - BCH uses `SIGHASH_FORKID (0x41)` — already isolated from BTC replay.
  - Covenant ABI includes the `outpoint` — a signed covenant unlock is bound to a specific UTXO.

- [ ] **Electrum server certificate pinning**
  - Store the fingerprint of the Chipnet Fulcrum server on first connect.
  - Warn if the certificate changes.

- [ ] **Dependency audit automation**
  - `cargo audit` in CI (Rust) — checks against RustSec advisory database.
  - `pnpm audit` in CI (Node.js) — npm advisory database.
  - Pin lockfiles (`Cargo.lock` and `pnpm-lock.yaml`) — committed to git.

### P2 — Ship Before Public Beta

- [ ] **Screen capture prevention**
  - Electron: `win.setContentProtection(true)` — prevents screenshots of the wallet
    window on macOS and Windows.
  - Extra caution when displaying mnemonics or private QR codes.

- [ ] **Clipboard auto-clear**
  - After copying a paycode or address, clear the clipboard after 60 seconds.
  - Display a countdown timer in the UI.

- [ ] **Tor / proxy support**
  - Route Electrum RPC through Tor for metadata privacy (IP address leaks to server).
  - Implement as an optional setting (off by default, with clear trade-offs explained).

- [ ] **Anti-phishing word list**
  - Display 2 random words (derived from device UUID + seed hash) on the home screen.
  - Users learn their "security code" — a phishing site won't know it.

- [ ] **Formal audit**
  - Commission an independent audit of `core/src/srpa.rs`, `core/src/ecdh.rs`,
    and `contracts/srpa_pool.cash` before mainnet launch.

---

## Key Architecture Security Properties

### Separation of Spend and Scan Keys

```
┌─────────────────────────────────────────────────────────────┐
│  Spend key   m/44'/145'/0'/0'/0                              │
│  ─────────────────────────────────────────────────────────── │
│  Purpose:    signing spending transactions                   │
│  Exposure:   only unlocked at spend time (under PIN/biometric│
│  If leaked:  attacker can spend *already known* UTXOs        │
│                                                              │
│  Scan key    m/44'/145'/0'/1'/0                              │
│  ─────────────────────────────────────────────────────────── │
│  Purpose:    ECDH scanning for incoming payments             │
│  Exposure:   used continuously in background scanner         │
│  If leaked:  attacker can DETECT payments but NOT spend      │
│               → funds remain safe; watchful attacker only    │
│                                                              │
│  Covenant key m/44'/145'/0'/2'/0                             │
│  ─────────────────────────────────────────────────────────── │
│  Purpose:    signing covenant unlock scripts                 │
│  Exposure:   only at covenant spend time                     │
│  If leaked:  limited to known covenant UTXOs                 │
└─────────────────────────────────────────────────────────────┘
```

This separation means a compromised scan key (e.g., on a "watch server")
does not enable theft — something that cannot be said about traditional
HD wallet key reuse patterns.

### Memory Safety

```rust
// All private key material uses Zeroizing<>
let secret: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
// When `secret` goes out of scope, the memory is zeroed before deallocation.
// This prevents private keys from lingering in memory after use.
```

### Why Rust for the Core?

- **No null pointer dereferences** — Rust's ownership model prevents use-after-free.
- **No buffer overflows** — bounds checked at compile time.
- **WASM compilation** — same audited code runs in browser and desktop.
- **`secp256k1` crate** — wraps the Bitcoin Core secp256k1 library; battle-tested.
- **`zeroize` crate** — zero-on-drop for all key material; audited by security researchers.

### Covenant Security Properties

The `SrpaPool.cash` covenant has these on-chain guarantees:

1. **Key binding**: `hash160(pubkey) == otaPubKeyHash` — prevents key substitution.
2. **No output restrictions**: the receiver can send funds anywhere — no pattern.
3. **Reclaim timeout**: an `reclaimLocktime` prevents sender from taking funds
   *immediately* but allows reclaim if the receiver never scans (safety net).
4. **Token forwarding**: CashTokens pass through untouched.
5. **Version byte in ABI**: enables non-breaking upgrades (ZK proof slot reserved).

---

## Incident Response Checklist

If a private key is suspected compromised:

1. **Immediately** generate a new wallet from a fresh mnemonic.
2. Sweep all UTXOs to new one-time addresses using `bch_sendTransaction`.
3. Publish a new paycode (new mnemonic → new paycode).
4. Revoke all WalletConnect sessions.
5. Inform counterparties of new paycode out-of-band (Signal, PGP email).

The sharded UTXO pool makes sweeping fast: query all unspent UTXOs, batch them
into a single transaction (multiple inputs, single output), and broadcast.
