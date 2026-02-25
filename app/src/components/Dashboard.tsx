/**
 * Dashboard — main wallet home screen
 *
 * Shows:
 *  • Total balance across all pool shards
 *  • List of pending/confirmed UTXOs
 *  • Quick-action buttons: Send / Receive
 *  • Pool health: shard sync status
 *  • WalletConnect session indicator
 */

import { useEffect, useState } from "react";
import { usePoolStore } from "../store/pool";
import { getWalletMeta } from "../store/db";

interface DashboardProps {
  onSend:    () => void;
  onReceive: () => void;
}

function formatBCH(sats: bigint): string {
  return (Number(sats) / 1e8).toFixed(8);
}

function truncate(s: string, n = 8): string {
  return s.length > n * 2 + 3 ? `${s.slice(0, n)}…${s.slice(-n)}` : s;
}

export default function Dashboard({ onSend, onReceive }: DashboardProps) {
  const pool         = usePoolStore();
  const [paycode, setPaycode] = useState<string | null>(null);
  const [network, setNetwork] = useState("chipnet");

  useEffect(() => {
    pool.hydrate();
    getWalletMeta().then(m => {
      if (m) { setPaycode(m.paycode); setNetwork(m.network); }
    });
  }, []);

  const utxos = pool.shards.flatMap(s => s.utxos);
  const syncedShards = pool.shards.filter(s => s.lastSyncHeight > 0).length;

  return (
    <div className="flex flex-col min-h-screen bg-gray-950 text-white">
      {/* Header */}
      <div className="px-6 pt-12 pb-6 bg-gradient-to-b from-gray-900 to-gray-950">
        <div className="flex items-center justify-between mb-6">
          <div>
            <p className="text-gray-500 text-xs uppercase tracking-widest">{network}</p>
            <h1 className="text-2xl font-bold">👻 GhostPay</h1>
          </div>
          <div className="w-8 h-8 rounded-full bg-green-600 flex items-center justify-center text-sm">
            ✓
          </div>
        </div>

        {/* Balance */}
        <div className="text-center py-4">
          {pool.isLoading ? (
            <div className="text-gray-600 animate-pulse text-lg">Loading…</div>
          ) : (
            <>
              <p className="text-5xl font-bold font-mono">
                {formatBCH(pool.totalBalance)}
              </p>
              <p className="text-gray-500 text-sm mt-1">BCH</p>
            </>
          )}
        </div>

        {/* Action buttons */}
        <div className="grid grid-cols-2 gap-3 mt-4">
          <button
            className="bg-green-600 hover:bg-green-500 text-white font-semibold py-4 rounded-2xl transition"
            onClick={onSend}
          >
            ↑ Send
          </button>
          <button
            className="bg-gray-800 hover:bg-gray-700 text-white font-semibold py-4 rounded-2xl transition"
            onClick={onReceive}
          >
            ↓ Receive
          </button>
        </div>
      </div>

      {/* UTXO list */}
      <div className="flex-1 px-6 pt-4 pb-24">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-gray-400 text-xs uppercase tracking-widest">Incoming Payments</h2>
          <span className="text-gray-600 text-xs">{utxos.length} UTXOs</span>
        </div>

        {utxos.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
            <div className="text-4xl opacity-30">👻</div>
            <p className="text-gray-600 text-sm">No payments yet.</p>
            <p className="text-gray-700 text-xs">
              Share your paycode to receive a ghost payment.
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {utxos.map(u => (
              <div
                key={`${u.txid}:${u.vout}`}
                className="bg-gray-900 rounded-xl p-4 flex items-center justify-between"
              >
                <div>
                  <p className="text-white font-mono text-sm">
                    {formatBCH(u.valueSats)} BCH
                  </p>
                  <p className="text-gray-600 text-xs mt-1">
                    {truncate(u.txid)} · shard #{u.shardIndex}
                    {u.height > 0 ? ` · block ${u.height}` : " · unconfirmed"}
                  </p>
                </div>
                <div className="text-green-500 text-lg">👻</div>
              </div>
            ))}
          </div>
        )}

        {/* Pool health */}
        <div className="mt-6">
          <h2 className="text-gray-600 text-xs uppercase tracking-widest mb-2">Pool Status</h2>
          <div className="bg-gray-900 rounded-xl p-4">
            <div className="flex justify-between text-sm mb-2">
              <span className="text-gray-400">Shards synced</span>
              <span className="text-white">{syncedShards} / 16</span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-1.5">
              <div
                className="bg-green-600 h-1.5 rounded-full"
                style={{ width: `${(syncedShards / 16) * 100}%` }}
              />
            </div>
          </div>
        </div>

        {/* Paycode snippet */}
        {paycode && (
          <div className="mt-4 bg-gray-900 rounded-xl p-4">
            <p className="text-gray-500 text-xs mb-1">Your Paycode (static)</p>
            <p className="font-mono text-xs text-gray-400 truncate">{paycode}</p>
            <button
              className="text-green-500 text-xs mt-2"
              onClick={() => navigator.clipboard.writeText(paycode)}
            >
              Copy →
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
