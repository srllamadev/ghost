# GhostPay 👻

> **Silent Reusable Payment Addresses for Bitcoin Cash**  
> Privacy is not a feature — it's a right.

GhostPay is a non-custodial Bitcoin Cash wallet that enables **invisible transactions** using SRPA (Silent Reusable Payment Addresses), CashScript covenants, and a sharded local UTXO pool. No ZK-SNARKs, no trusted setup, no compromise.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Architecture Overview](#architecture-overview)
3. [Stack](#stack)
4. [Project Layout](#project-layout)
5. [Quick Start](#quick-start)
6. [Security Checklist](#security-checklist)
7. [Roadmap](#roadmap)

---

## How It Works

```
Alice (Sender)                             Bob (Receiver)
────────────────────────────────────────────────────────
1. Bob publishes static paycode (SRPA):
   paycode = (B_spend_pubkey, B_scan_pubkey)

2. Alice sends silently:
   a. Generate ephemeral keypair: (r, R)  where R = r·G
   b. ECDH shared secret: S = r·B_scan
   c. Derive one-time address:
      P = B_spend + sha256(S ‖ outpoint_index)·G
   d. Fund covenant at P; embed R in OP_RETURN

3. Bob scans:
   a. For each OP_RETURN with ephemeral key R:
      S = b_scan·R          (same secret, Bob's math)
   b. Derive candidate P, query UTXO set
   c. Match found → funds appear 🎉
   d. Spend: sign with b_spend + sha256(S ‖ outpoint_index)

On-chain: looks like a plain P2PKH. No link Alice↔Bob.
```

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                       GhostPay App                           │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │  React UI   │  │  TS Engine   │  │ WalletConnect V2 │    │
│  │ Send/Receive│◄─│ SRPA / Pool  │◄─│  dApp bridge     │    │
│  └──────┬──────┘  └──────┬───────┘  └──────────────────┘    │
│         │                │                                   │
│         ▼                ▼                                   │
│  ┌────────────────────────────────────┐                      │
│  │     Rust Core  (WASM + native)     │                      │
│  │  • HD Wallet  (BIP32/44/39)        │                      │
│  │  • ECDH + one-time address gen     │                      │
│  │  • Covenant ABI builder            │                      │
│  │  • Transaction signing             │                      │
│  │  • Pluggable Signer (PQ-ready)     │                      │
│  └────────────────────────────────────┘                      │
│               │                  │                           │
│               ▼                  ▼                           │
│  ┌────────────────┐  ┌────────────────────────┐             │
│  │  CashScript    │  │  Sharded UTXO Pool     │             │
│  │  Covenants     │  │  (IndexedDB / SQLite)  │             │
│  └────────────────┘  └────────────────────────┘             │
└──────────────────────────────────────────────────────────────┘
                             │
               ┌─────────────┴──────────────┐
               ▼                            ▼
        Chipnet (testnet)             Mainnet BCH
    (Fulcrum / Rostrum RPC)
```

---

## Stack

| Layer | Technology | Why |
|---|---|---|
| Core crypto | **Rust** → WASM | Memory safety, secp256k1 native, auditable |
| Contracts | **CashScript** | High-level BCH covenant language |
| Frontend | **React + TypeScript** | Type-safe, large ecosystem |
| Desktop shell | **Electron** | Native SQLite, `safeStorage` for biometrics |
| Storage | IndexedDB (web) / SQLite (desktop) | Encrypted offline-first |
| Network | **Electrum/Fulcrum** JSON-RPC | Trustless, no full node required |
| dApp bridge | **WalletConnect V2** | Standard wallet↔dApp protocol |
| PQ-readiness | Modular `Signer` trait | Swap secp256k1 → LM-OTS without UX changes |

---

## Project Layout

```
ghostpay/
├── core/                       # Rust crate — WASM + native
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs              # WASM exports, public API surface
│       ├── hd_wallet.rs        # BIP32/44/39, 3-key derivation model
│       ├── srpa.rs             # Paycode, one-time address, ECDH
│       ├── ecdh.rs             # Low-level ECDH shared-secret
│       ├── signer.rs           # Pluggable Signer trait (PQ-ready)
│       └── covenant.rs         # CashScript ABI serialization
├── contracts/
│   ├── srpa_pool.cash          # Main privacy pool covenant
│   └── artifacts/              # cashc-compiled ABI JSON
├── app/
│   ├── package.json
│   ├── tsconfig.json
│   ├── electron/
│   │   └── main.ts             # Electron entry point
│   └── src/
│       ├── crypto/
│       │   ├── srpa.ts         # SRPA helpers (wraps WASM)
│       │   ├── hdwallet.ts     # HD derivation JS bridge
│       │   └── scanner.ts      # Blockchain scanner (Electrum RPC)
│       ├── store/
│       │   ├── pool.ts         # Sharded UTXO pool manager
│       │   └── db.ts           # DB schema + queries
│       ├── walletconnect/
│       │   └── wc2.ts          # WC2 provider implementation
│       ├── components/
│       │   ├── Onboarding.tsx
│       │   ├── Dashboard.tsx
│       │   ├── Send.tsx
│       │   └── Receive.tsx
│       └── App.tsx
├── ARCHITECTURE.md
├── SECURITY.md
└── README.md
```

---

## Quick Start

### Prerequisites

```bash
# Rust + WASM target
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Node.js ≥20 + pnpm
npm install -g pnpm

# CashScript compiler
npm install -g cashc
```

### Build & Run (Chipnet)

```bash
# 1. Compile Rust core → WASM
cd core && wasm-pack build --target web && cd ..

# 2. Compile CashScript contracts
cd contracts && cashc srpa_pool.cash -o artifacts/ && cd ..

# 3. Frontend
cd app && pnpm install && pnpm dev

# 4. Electron desktop
pnpm electron:dev
```

### Tests

```bash
cd core && cargo test          # Rust unit tests
cd app  && pnpm test           # Frontend tests
```

---

## Security Checklist

See [SECURITY.md](SECURITY.md) for the full threat model.

**Non-negotiables (all implemented):**
- AES-256-GCM encryption of local key material (argon2id KDF)
- Keys never leave Rust core — UI receives only public data
- Clear-signing: human-readable tx preview before every broadcast
- Biometric unlock via Electron `safeStorage`
- Stealth change: change output always uses a fresh SRPA-derived address

---

## Roadmap

| Milestone | Target | Status |
|---|---|---|
| HD wallet (3-key) + SRPA math | 13–15 Feb | ✅ |
| CashScript pool covenant (Chipnet) | 16–18 Feb | ✅ |
| Sharded pool scanner | 19–21 Feb | ✅ |
| React UI (Send / Receive) | 21–23 Feb | ✅ |
| WalletConnect V2 bridge | 24–25 Feb | 🔄 |
| Full Chipnet demo + video | 26 Feb | 🔄 |
| Post-Quantum signer module | Q3 2026 | 📋 |

---

## Credits

- SRPA research: **bastiancarmy**
- Covenant tooling: **CashScript**
- BCH Rust primitives: **rust-bch**
- UX inspiration: **Cashual Wallet**

---

*BCH-1 Hackathon — February 2026*  
*Track: CashToken Systems / Technology Infrastructure*
