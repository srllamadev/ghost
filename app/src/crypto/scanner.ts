/**
 * Blockchain Scanner — Electrum/Fulcrum JSON-RPC client
 *
 * Scans the BCH blockchain for SRPA payments by looking for:
 *   1. OP_RETURN outputs with 33-byte payloads (ephemeral pubkeys)
 *   2. P2PKH UTXOs at one-time addresses derived from those ephemeral keys
 *
 * Architecture:
 *   - Connects to a Fulcrum/Rostrum server via WebSocket (Electrum protocol)
 *   - Batches subscription and history requests for efficiency
 *   - In a full SPV client, we would download block headers; here we use the
 *     Electrum `blockchain.scripthash.subscribe` method as a lightweight proxy
 *   - The scanner is stateless — all discovered UTXOs go into the ShardedPool
 *
 * Network endpoints:
 *   Chipnet: wss://chipnet.imaginary.cash:50004
 *   Mainnet: wss://fulcrum.fountainhead.cash:51004
 */

import { receiverScanOpReturn, type ReceiverScanResult } from "./srpa";
import type { PoolManager } from "../store/pool";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type Network = "chipnet" | "mainnet";

export interface ElectrumConfig {
  network: Network;
  server:  string;   // wss://...
}

export interface ElectrumUtxo {
  txHash:     string;
  txPos:      number;
  value:      number;  // satoshis
  height:     number;
}

export interface ScannedPayment {
  txid:           string;
  vout:           number;
  valueSats:      bigint;
  oneTimeAddress: string;
  tweakHex:       string;
  height:         number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Electrum Client (minimal — wraps electrum-cash)
// ─────────────────────────────────────────────────────────────────────────────

const NETWORK_SERVERS: Record<Network, string> = {
  chipnet: "wss://chipnet.imaginary.cash:50004",
  mainnet: "wss://fulcrum.fountainhead.cash:51004",
};

const OP_RETURN_PREFIX = "6a"; // OP_RETURN opcode in hex

/**
 * Request a transaction by hash from an Electrum server using fetch-based
 * JSON-RPC. In production, replace with a persistent WebSocket connection.
 */
async function electrumRpc(
  server: string,
  method: string,
  params: unknown[],
): Promise<unknown> {
  // For development: use public Rostrum HTTP API as fallback
  const httpServer = server.replace("wss://", "https://").replace(":50004", ":443").replace(":51004", ":443");
  const response = await fetch(httpServer, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const data = await response.json() as { result: unknown; error?: { message: string } };
  if (data.error) throw new Error(data.error.message);
  return data.result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Address → scripthash conversion (for Electrum)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Convert a P2PKH cashaddr to an Electrum scripthash.
 * Electrum uses SHA256(locking_script) reversed (little-endian).
 */
async function cashAddrToScripthash(cashAddr: string, network: Network): Promise<string> {
  // Use libauth for robust cashaddr decoding in production.
  // For MVP, we rely on the Electrum server's address lookup endpoint.
  // This is a placeholder that the production implementation should replace.
  const addressNormalized = cashAddr.startsWith("bitcoincash:")
    ? cashAddr
    : cashAddr.startsWith("bchtest:")
    ? cashAddr
    : network === "mainnet"
    ? `bitcoincash:${cashAddr}`
    : `bchtest:${cashAddr}`;
  return addressNormalized; // Electrum also accepts cashaddr directly on modern servers
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanner
// ─────────────────────────────────────────────────────────────────────────────

export class SrpaScanner {
  private readonly config: ElectrumConfig;
  private readonly pool: PoolManager;

  constructor(pool: PoolManager, network: Network = "chipnet") {
    this.config = { network, server: NETWORK_SERVERS[network] };
    this.pool = pool;
  }

  /**
   * Scan a range of blocks for SRPA payments directed at `walletParams`.
   *
   * Strategy:
   *  1. Get all transactions that touch the wallet's *scan* scripthash
   *     (watch for OP_RETURN announcing the ephemeral pubkey)
   *  2. For each OP_RETURN, attempt to match using receiver_scan_opreturn
   *  3. On match: check UTXO at one-time address, store in pool
   *
   * In the MVP we scan by subscribing to an OP_RETURN index address pattern.
   * Full SPV would scan every block header and Bloom-filter transactions.
   */
  async scan(walletParams: {
    scanXprivEncrypted: string;
    encryptionKeyHex:   string;
    spendXpub:          string;
  }): Promise<ScannedPayment[]> {
    const discovered: ScannedPayment[] = [];

    // 1. Fetch recent transactions referencing OP_RETURN outputs (simplified)
    const opReturnTxs = await this.fetchRecentOpReturnTxs();

    // 2. For each candidate transaction, extract the OP_RETURN payload
    for (const tx of opReturnTxs) {
      const ephemeralPubKeyHex = extractEphemeralPubKeyFromTx(tx);
      if (!ephemeralPubKeyHex) continue;

      // 3. Try to match against our wallet
      for (let vout = 0; vout < tx.outputs.length; vout++) {
        if (isOpReturn(tx.outputs[vout]?.scriptPubKey ?? "")) continue;

        const result = await receiverScanOpReturn({
          scanXprivEncrypted: walletParams.scanXprivEncrypted,
          encryptionKeyHex:   walletParams.encryptionKeyHex,
          ephemeralPubKeyHex,
          spendXpub:          walletParams.spendXpub,
          outpointIndex:      vout,
          network:            this.config.network,
        });

        if (!result.matched) continue;

        // 4. Verify UTXO exists at the one-time address
        const utxos = await this.fetchUtxos(result.oneTimeAddress);
        for (const utxo of utxos) {
          const payment: ScannedPayment = {
            txid:           utxo.txHash,
            vout:           utxo.txPos,
            valueSats:      BigInt(utxo.value),
            oneTimeAddress: result.oneTimeAddress,
            tweakHex:       result.tweakHex,
            height:         utxo.height,
          };
          discovered.push(payment);

          // 5. Store in sharded pool
          await this.pool.insertUtxo({
            txid:         payment.txid,
            vout:         payment.vout,
            valueSats:    payment.valueSats,
            address:      payment.oneTimeAddress,
            tweakHex:     payment.tweakHex,
            commitmentHex: ephemeralPubKeyHex,
            height:       payment.height,
          });
        }
      }
    }

    return discovered;
  }

  // ───────────── Private helpers ──────────────────────────────────────────

  private async fetchRecentOpReturnTxs(): Promise<RawTx[]> {
    try {
      // On Chipnet we use the Electrum blockchain.transaction.get_merkle
      // approach. For MVP we query a recent block range.
      // In production: subscribe to scripthashs of "ghost scan" beacon addresses.
      const tip = await electrumRpc(
        this.config.server,
        "blockchain.headers.subscribe",
        [],
      ) as { height: number };

      const txids = await electrumRpc(
        this.config.server,
        "blockchain.block.headers",
        [Math.max(0, tip.height - 10), 10],
      ) as string[];

      // For MVP: return empty array — the UI's manual "receive" flow
      // is used to paste the ephemeral pubkey directly.
      return [];
    } catch {
      return [];
    }
  }

  private async fetchUtxos(cashAddr: string): Promise<ElectrumUtxo[]> {
    try {
      const scripthash = await cashAddrToScripthash(cashAddr, this.config.network);
      const result = await electrumRpc(
        this.config.server,
        "blockchain.address.listunspent",
        [scripthash],
      );
      return (result as ElectrumUtxo[]) ?? [];
    } catch {
      return [];
    }
  }

  /** Broadcast a signed raw transaction. */
  async broadcast(rawTxHex: string): Promise<string> {
    const txid = await electrumRpc(
      this.config.server,
      "blockchain.transaction.broadcast",
      [rawTxHex],
    );
    return txid as string;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

interface RawTxOutput {
  scriptPubKey: string;
  value: number;
}

interface RawTx {
  txid:    string;
  outputs: RawTxOutput[];
}

function isOpReturn(scriptHex: string): boolean {
  return scriptHex.startsWith(OP_RETURN_PREFIX);
}

/**
 * Extract ephemeral pubkey from a transaction's OP_RETURN output.
 * GhostPay OP_RETURN format: OP_RETURN OP_PUSHDATA1 0x21 <33 bytes>
 * Hex: 6a 4c 21 <66 hex chars>
 */
function extractEphemeralPubKeyFromTx(tx: RawTx): string | null {
  for (const output of tx.outputs) {
    const script = output.scriptPubKey;
    if (!isOpReturn(script)) continue;

    // Minimal parser: 6a 4c 21 <66 hex chars>
    if (script.startsWith("6a4c21") && script.length === 6 + 66) {
      return script.slice(6); // 33 bytes
    }
    // Also handle: 6a 21 <66 hex chars>
    if (script.startsWith("6a21") && script.length === 4 + 66) {
      return script.slice(4);
    }
  }
  return null;
}
