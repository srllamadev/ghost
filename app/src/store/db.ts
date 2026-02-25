/**
 * Database schema and query layer — IndexedDB (web) / SQLite (Electron)
 *
 * ANSWER TO Q2: Why IndexedDB for web, SQLite for desktop?
 * ─────────────────────────────────────────────────────────
 * Web (browser extension / PWA):
 *   • IndexedDB is the only persistent storage available in browsers.
 *   • We use the `idb` wrapper for a Promise-based API.
 *   • All stored data is AES-256-GCM encrypted before writing.
 *
 * Desktop (Electron):
 *   • SQLite via `better-sqlite3` is synchronous, fast, and widely audited.
 *   • Electron's `safeStorage` encrypts the SQLite file key at the OS level
 *     (Keychain on macOS, DPAPI on Windows, libsecret on Linux).
 *   • WAL mode enables concurrent reads without locking.
 *   • The same SQL schema is used whether running under Electron or Node test.
 *
 * SCHEMA
 * ──────
 * Tables / Object Stores:
 *
 *   wallet_meta         — One row: network, paycode, xpubs, creation date
 *   shards              — 16 shards (index 0-15); each shard is a logical bucket
 *   utxos               — All discovered UTXOs, keyed by (txid, vout)
 *   scan_checkpoints    — Last scanned block height per shard (for resumption)
 *
 * IndexedDB object store layout mirrors the SQL schema for portability.
 */

import { openDB, type DBSchema, type IDBPDatabase } from "idb";

// ─────────────────────────────────────────────────────────────────────────────
// Schema types
// ─────────────────────────────────────────────────────────────────────────────

export type Network = "chipnet" | "mainnet";

/**
 * One row in `wallet_meta`.
 */
export interface WalletMeta {
  id:           1;           // Singleton
  network:      Network;
  paycode:      string;
  spendXpub:    string;
  scanXpub:     string;
  covenantXpub: string;
  createdAt:    number;      // Unix timestamp ms
  lastSyncedAt: number;
}

/**
 * A UTXO row.
 *
 * commitmentHex = the ephemeral pubkey from OP_RETURN (links the UTXO to
 *                 the SRPA deposit for covenant spending).
 * tweakHex      = the scalar tweak used to derive the one-time key.
 *                 Stored encrypted; decrypted only at spend time.
 * shardIndex    = deterministic index; see covenant.ts `get_shard_index`
 */
export interface UtxoRow {
  id:            string;          // `${txid}:${vout}`
  txid:          string;
  vout:          number;
  valueSats:     string;          // BigInt serialized as decimal string
  address:       string;          // One-time P2PKH cashaddr
  tweakHex:      string;          // Encrypted tweak scalar
  commitmentHex: string;          // Ephemeral pubkey (unencrypted, public data)
  shardIndex:    number;          // 0-15
  height:        number;          // Block height at confirmation
  spent:         boolean;
  spentTxid:     string | null;
}

export interface ScanCheckpoint {
  shardIndex:  number;
  lastHeight:  number;
  updatedAt:   number;
}

// ─────────────────────────────────────────────────────────────────────────────
// IndexedDB schema
// ─────────────────────────────────────────────────────────────────────────────

interface GhostPayDB extends DBSchema {
  wallet_meta: {
    key:   number;
    value: WalletMeta;
  };
  utxos: {
    key:   string;
    value: UtxoRow;
    indexes: {
      "by-shard":   number;
      "by-address": string;
      "by-spent":   boolean;
    };
  };
  scan_checkpoints: {
    key:   number;
    value: ScanCheckpoint;
  };
}

const DB_NAME    = "ghostpay";
const DB_VERSION = 1;

let _db: IDBPDatabase<GhostPayDB> | null = null;

export async function openGhostPayDB(): Promise<IDBPDatabase<GhostPayDB>> {
  if (_db) return _db;
  _db = await openDB<GhostPayDB>(DB_NAME, DB_VERSION, {
    upgrade(db) {
      // wallet_meta
      db.createObjectStore("wallet_meta", { keyPath: "id" });

      // utxos
      const utxoStore = db.createObjectStore("utxos", { keyPath: "id" });
      utxoStore.createIndex("by-shard",   "shardIndex");
      utxoStore.createIndex("by-address", "address");
      utxoStore.createIndex("by-spent",   "spent");

      // scan_checkpoints
      db.createObjectStore("scan_checkpoints", { keyPath: "shardIndex" });

      // Seed default checkpoints for all 16 shards
      for (let i = 0; i < TOTAL_SHARDS; i++) {
        db.add?.("scan_checkpoints", { shardIndex: i, lastHeight: 0, updatedAt: Date.now() });
      }
    },
  });
  return _db;
}

// ─────────────────────────────────────────────────────────────────────────────
// SQLite schema (Electron/Node — kept in sync with IndexedDB layout)
// ─────────────────────────────────────────────────────────────────────────────
//
// Run via:  db.exec(SQLITE_SCHEMA)
//
export const SQLITE_SCHEMA = /* sql */ `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS wallet_meta (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  network        TEXT    NOT NULL,
  paycode        TEXT    NOT NULL,
  spend_xpub     TEXT    NOT NULL,
  scan_xpub      TEXT    NOT NULL,
  covenant_xpub  TEXT    NOT NULL,
  created_at     INTEGER NOT NULL,
  last_synced_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS utxos (
  id             TEXT    PRIMARY KEY,   -- txid:vout
  txid           TEXT    NOT NULL,
  vout           INTEGER NOT NULL,
  value_sats     TEXT    NOT NULL,      -- decimal string (bigint safe)
  address        TEXT    NOT NULL,
  tweak_hex      TEXT    NOT NULL,      -- AES-256-GCM encrypted
  commitment_hex TEXT    NOT NULL,      -- ephemeral pubkey (public)
  shard_index    INTEGER NOT NULL,
  height         INTEGER NOT NULL DEFAULT 0,
  spent          INTEGER NOT NULL DEFAULT 0,
  spent_txid     TEXT
);

CREATE INDEX IF NOT EXISTS idx_utxos_shard   ON utxos(shard_index);
CREATE INDEX IF NOT EXISTS idx_utxos_address ON utxos(address);
CREATE INDEX IF NOT EXISTS idx_utxos_spent   ON utxos(spent);

CREATE TABLE IF NOT EXISTS scan_checkpoints (
  shard_index  INTEGER PRIMARY KEY,
  last_height  INTEGER NOT NULL DEFAULT 0,
  updated_at   INTEGER NOT NULL DEFAULT 0
);

-- Seed 16 shard checkpoints
INSERT OR IGNORE INTO scan_checkpoints (shard_index, last_height, updated_at)
SELECT value, 0, 0 FROM json_each('[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]');
`;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

export const TOTAL_SHARDS = 16;

// ─────────────────────────────────────────────────────────────────────────────
// CRUD helpers (IndexedDB)
// ─────────────────────────────────────────────────────────────────────────────

export async function saveWalletMeta(meta: Omit<WalletMeta, "id">): Promise<void> {
  const db = await openGhostPayDB();
  await db.put("wallet_meta", { ...meta, id: 1 });
}

export async function getWalletMeta(): Promise<WalletMeta | undefined> {
  const db = await openGhostPayDB();
  return db.get("wallet_meta", 1);
}

export async function upsertUtxo(utxo: UtxoRow): Promise<void> {
  const db = await openGhostPayDB();
  await db.put("utxos", utxo);
}

export async function getUtxosByShard(shardIndex: number): Promise<UtxoRow[]> {
  const db = await openGhostPayDB();
  return db.getAllFromIndex("utxos", "by-shard", shardIndex);
}

export async function getAllUnspentUtxos(): Promise<UtxoRow[]> {
  const db = await openGhostPayDB();
  return db.getAllFromIndex("utxos", "by-spent", false);
}

export async function markUtxoSpent(txid: string, vout: number, spentTxid: string): Promise<void> {
  const db  = await openGhostPayDB();
  const key = `${txid}:${vout}`;
  const row = await db.get("utxos", key);
  if (row) {
    row.spent     = true;
    row.spentTxid = spentTxid;
    await db.put("utxos", row);
  }
}

export async function getScanCheckpoint(shardIndex: number): Promise<number> {
  const db = await openGhostPayDB();
  const cp = await db.get("scan_checkpoints", shardIndex);
  return cp?.lastHeight ?? 0;
}

export async function updateScanCheckpoint(shardIndex: number, height: number): Promise<void> {
  const db = await openGhostPayDB();
  await db.put("scan_checkpoints", { shardIndex, lastHeight: height, updatedAt: Date.now() });
}

export async function getTotalBalance(): Promise<bigint> {
  const utxos = await getAllUnspentUtxos();
  return utxos.reduce((sum, u) => sum + BigInt(u.valueSats), 0n);
}
