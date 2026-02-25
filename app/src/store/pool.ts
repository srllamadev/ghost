/**
 * Sharded UTXO Pool Manager
 *
 * The pool is the heart of GhostPay's offline-first architecture.
 * All SRPA payments directed at the wallet are stored here as UTXOs,
 * organised into 16 deterministic shards.
 *
 * SHARD DESIGN (answering Q1 in detail)
 * ──────────────────────────────────────
 * Why shards?
 *   • Scanning the full blockchain every startup would be prohibitively slow.
 *   • Shards let us resume scanning from the last known block per shard.
 *   • Shard assignment is *deterministic*: given the outpoint + scan pubkey,
 *     the same shard is always selected. This means the pool is fully
 *     reconstructable from the wallet seed + a blockchain rescan.
 *
 * Shard index formula:
 *   shardIndex = SHA256(depositTxid ‖ receiverScanPubKeyHex)[0..4] mod 16
 *
 * This is implemented in the Rust core (covenant.rs `get_shard_index`) and
 * mirrored here for TypeScript callers.
 *
 * POOL STATE TYPE (TypeScript)
 * ─────────────────────────────
 * ```ts
 * type PoolState = {
 *   network: "chipnet" | "mainnet";
 *   shards: Array<{
 *     index:  number;
 *     utxos:  Array<{
 *       txid:          string;
 *       vout:          number;
 *       valueSats:     bigint;
 *       commitmentHex: string;   // ephemeral pubkey from OP_RETURN
 *       tweakHex:      string;   // encrypted scalar tweak
 *     }>;
 *   }>;
 * };
 * ```
 */

import { create } from "zustand";
import {
  upsertUtxo,
  getUtxosByShard,
  getAllUnspentUtxos,
  markUtxoSpent,
  getScanCheckpoint,
  updateScanCheckpoint,
  getTotalBalance,
  TOTAL_SHARDS,
  type UtxoRow,
} from "./db";

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic shard index
// ─────────────────────────────────────────────────────────────────────────────

async function sha256Hex(data: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const buf     = await crypto.subtle.digest("SHA-256", encoder.encode(data));
  return new Uint8Array(buf);
}

export async function getShardIndex(
  depositTxid: string,
  receiverScanPubKeyHex: string,
  totalShards = TOTAL_SHARDS,
): Promise<number> {
  const preimage = depositTxid + receiverScanPubKeyHex;
  const hash     = await sha256Hex(preimage);
  // Read first 4 bytes as big-endian uint32
  const n = (hash[0]! << 24) | (hash[1]! << 16) | (hash[2]! << 8) | hash[3]!;
  return (n >>> 0) % totalShards; // unsigned mod
}

// ─────────────────────────────────────────────────────────────────────────────
// Zustand store — in-memory reactive view of the pool
// ─────────────────────────────────────────────────────────────────────────────

export interface PoolUtxo {
  txid:          string;
  vout:          number;
  valueSats:     bigint;
  address:       string;
  tweakHex:      string;
  commitmentHex: string;
  shardIndex:    number;
  height:        number;
}

export interface PoolShard {
  index:         number;
  utxos:         PoolUtxo[];
  lastSyncHeight: number;
}

export interface PoolState {
  network:        "chipnet" | "mainnet";
  shards:         PoolShard[];
  totalBalance:   bigint;
  isLoading:      boolean;
  error:          string | null;
}

interface PoolActions {
  /** Load all shards from IndexedDB into Zustand state. */
  hydrate:     () => Promise<void>;
  /** Insert a newly discovered UTXO into the pool. */
  insertUtxo:  (utxo: Omit<PoolUtxo, "shardIndex"> & { shardIndex?: number; scanPubKeyHex?: string }) => Promise<void>;
  /** Mark a UTXO as spent after a successful broadcast. */
  markSpent:   (txid: string, vout: number, spentTxid: string) => Promise<void>;
  /** Update the last-scanned block height for a shard. */
  setCheckpoint: (shardIndex: number, height: number) => Promise<void>;
  /** Return all unspent UTXOs across all shards. */
  getUnspent:  () => Promise<PoolUtxo[]>;
  /** Return total spendable balance in satoshis. */
  getBalance:  () => Promise<bigint>;
}

export type PoolStore = PoolState & PoolActions;

function buildEmptyShards(): PoolShard[] {
  return Array.from({ length: TOTAL_SHARDS }, (_, i) => ({
    index:          i,
    utxos:          [],
    lastSyncHeight: 0,
  }));
}

function rowToUtxo(row: UtxoRow): PoolUtxo {
  return {
    txid:          row.txid,
    vout:          row.vout,
    valueSats:     BigInt(row.valueSats),
    address:       row.address,
    tweakHex:      row.tweakHex,
    commitmentHex: row.commitmentHex,
    shardIndex:    row.shardIndex,
    height:        row.height,
  };
}

export const usePoolStore = create<PoolStore>((set, get) => ({
  network:      "chipnet",
  shards:       buildEmptyShards(),
  totalBalance: 0n,
  isLoading:    false,
  error:        null,

  // ── hydrate ──────────────────────────────────────────────────────────────
  async hydrate() {
    set({ isLoading: true, error: null });
    try {
      const shards = buildEmptyShards();
      for (let i = 0; i < TOTAL_SHARDS; i++) {
        const rows      = await getUtxosByShard(i);
        const height    = await getScanCheckpoint(i);
        shards[i] = {
          index:          i,
          utxos:          rows.filter(r => !r.spent).map(rowToUtxo),
          lastSyncHeight: height,
        };
      }
      const balance = await getTotalBalance();
      set({ shards, totalBalance: balance, isLoading: false });
    } catch (e) {
      set({ isLoading: false, error: String(e) });
    }
  },

  // ── insertUtxo ───────────────────────────────────────────────────────────
  async insertUtxo(input) {
    let { shardIndex } = input;

    // If shardIndex not provided, derive it deterministically
    if (shardIndex === undefined) {
      const scanKey = input.scanPubKeyHex ?? "";
      shardIndex = await getShardIndex(input.txid, scanKey);
    }

    const row: UtxoRow = {
      id:            `${input.txid}:${input.vout}`,
      txid:          input.txid,
      vout:          input.vout,
      valueSats:     input.valueSats.toString(),
      address:       input.address,
      tweakHex:      input.tweakHex,
      commitmentHex: input.commitmentHex,
      shardIndex,
      height:        input.height,
      spent:         false,
      spentTxid:     null,
    };

    await upsertUtxo(row);

    // Update Zustand state
    set(state => {
      const shards  = [...state.shards];
      const target  = shards[shardIndex!];
      if (!target) return state;
      const exists  = target.utxos.some(u => u.txid === input.txid && u.vout === input.vout);
      if (!exists) {
        shards[shardIndex!] = {
          ...target,
          utxos: [...target.utxos, rowToUtxo(row)],
        };
      }
      return {
        shards,
        totalBalance: state.totalBalance + input.valueSats,
      };
    });
  },

  // ── markSpent ────────────────────────────────────────────────────────────
  async markSpent(txid, vout, spentTxid) {
    await markUtxoSpent(txid, vout, spentTxid);
    set(state => {
      const shards = state.shards.map(shard => ({
        ...shard,
        utxos: shard.utxos.filter(u => !(u.txid === txid && u.vout === vout)),
      }));
      const removed = state.shards
        .flatMap(s => s.utxos)
        .find(u => u.txid === txid && u.vout === vout);
      return {
        shards,
        totalBalance: state.totalBalance - (removed?.valueSats ?? 0n),
      };
    });
  },

  // ── setCheckpoint ────────────────────────────────────────────────────────
  async setCheckpoint(shardIndex, height) {
    await updateScanCheckpoint(shardIndex, height);
    set(state => {
      const shards = [...state.shards];
      const shard  = shards[shardIndex];
      if (shard) shards[shardIndex] = { ...shard, lastSyncHeight: height };
      return { shards };
    });
  },

  // ── getUnspent ───────────────────────────────────────────────────────────
  async getUnspent() {
    const rows = await getAllUnspentUtxos();
    return rows.map(rowToUtxo);
  },

  // ── getBalance ───────────────────────────────────────────────────────────
  async getBalance() {
    return getTotalBalance();
  },
}));

// ─────────────────────────────────────────────────────────────────────────────
// PoolManager interface — used by the scanner to decouple from Zustand
// ─────────────────────────────────────────────────────────────────────────────

export interface PoolManager {
  insertUtxo: (utxo: Omit<PoolUtxo, "shardIndex"> & { scanPubKeyHex?: string }) => Promise<void>;
}

/**
 * Create a PoolManager that writes to the Zustand store.
 * The scanner uses this interface so it can be tested with a mock store.
 */
export function createPoolManager(): PoolManager {
  const store = usePoolStore.getState();
  return {
    insertUtxo: store.insertUtxo.bind(store),
  };
}
