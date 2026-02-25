/**
 * Receive — "Ghost Receive" flow
 *
 * The receiver has two modes:
 *
 * Mode A — Share Paycode:
 *   Show the static paycode (QR code + copy). The sender uses this once to
 *   derive a unique one-time address. The paycode never changes.
 *
 * Mode B — Manual Scan (MVP shortcut):
 *   Paste an ephemeral pubkey from a sender (e.g., shared via Signal/email).
 *   The wallet immediately derives the one-time address and checks for a UTXO.
 *   If found: "💸 Funds appeared!"
 *
 * Mode B simulates what the automatic scanner does in the background for every
 * new OP_RETURN in the blockchain. It's the demo mode for the hackathon.
 *
 * "Magic" UX:
 *   The user pastes a hex string → wallet thinks for 1s → funds appear.
 *   This is the "invisible payment" made visible from the receiver's side.
 */

import { useState } from "react";
import { receiverScanOpReturn } from "../crypto/srpa";
import type { SrpaScanner } from "../crypto/scanner";
import { getWalletMeta } from "../store/db";
import { usePoolStore } from "../store/pool";

interface ReceiveProps {
  onBack:  () => void;
  scanner: SrpaScanner;
}

type ReceiveTab = "paycode" | "scan";

export default function Receive({ onBack, scanner }: ReceiveProps) {
  const [tab, setTab]                     = useState<ReceiveTab>("paycode");
  const [paycode, setPaycode]             = useState<string | null>(null);
  const [ephemeralInput, setEphemeralInput] = useState("");
  const [scanResult, setScanResult]       = useState<{
    matched: boolean;
    address: string;
    valueSats: bigint | null;
  } | null>(null);
  const [isScanning, setIsScanning]       = useState(false);
  const [error, setError]                 = useState("");

  const pool = usePoolStore();

  // Load paycode on first render
  useState(() => {
    getWalletMeta().then(meta => {
      if (meta?.paycode) setPaycode(meta.paycode);
    });
  });

  // ── Tab: paycode ──────────────────────────────────────────────────────────

  const PaycodeTab = () => (
    <div className="flex flex-col gap-4">
      <p className="text-gray-400 text-sm">
        Share your paycode with anyone who wants to send you BCH invisibly.
        This string never changes and reveals nothing about your transaction history.
      </p>

      {paycode ? (
        <>
          {/* QR code placeholder — use `qrcode.react` in production */}
          <div className="bg-white rounded-2xl p-6 flex items-center justify-center mx-auto w-48 h-48">
            <span className="text-6xl">🔲</span>
          </div>

          <div className="bg-gray-900 rounded-xl p-4">
            <p className="text-xs text-gray-500 mb-2">Your GhostPay Paycode</p>
            <p className="font-mono text-xs text-green-400 break-all">{paycode}</p>
          </div>

          <button
            className="w-full bg-gray-800 hover:bg-gray-700 text-white font-semibold py-3 rounded-xl"
            onClick={() => {
              navigator.clipboard.writeText(paycode);
            }}
          >
            📋 Copy Paycode
          </button>
        </>
      ) : (
        <div className="text-gray-500 text-sm text-center py-8">Loading paycode…</div>
      )}
    </div>
  );

  // ── Tab: scan ─────────────────────────────────────────────────────────────

  const ScanTab = () => (
    <div className="flex flex-col gap-4">
      <p className="text-gray-400 text-sm">
        Paste an ephemeral pubkey shared by a sender. Your wallet will check
        if there are funds waiting for you.
      </p>

      <label className="text-gray-400 text-xs uppercase tracking-wide">
        Ephemeral Public Key (hex, 66 chars)
      </label>
      <input
        className="w-full bg-gray-900 text-white rounded-xl p-4 font-mono text-xs focus:outline-none focus:ring-2 focus:ring-green-600"
        placeholder="02a1b2c3d4… (33 bytes hex)"
        value={ephemeralInput}
        onChange={e => {
          setEphemeralInput(e.target.value.trim());
          setScanResult(null);
          setError("");
        }}
      />

      {error && <p className="text-red-400 text-sm">{error}</p>}

      <button
        className="w-full bg-green-600 hover:bg-green-500 text-white font-semibold py-4 rounded-2xl disabled:opacity-50"
        disabled={isScanning || ephemeralInput.length !== 66}
        onClick={async () => {
          setIsScanning(true);
          setScanResult(null);
          setError("");
          try {
            const meta = await getWalletMeta();
            if (!meta) throw new Error("Wallet not initialised");

            // Receiver scans — this calls the WASM ECDH + derive
            const result = await receiverScanOpReturn({
              scanXprivEncrypted: "(encrypted — loaded from secure storage)",
              encryptionKeyHex:   "(derived from PIN/biometric)",
              ephemeralPubKeyHex: ephemeralInput,
              spendXpub:          meta.spendXpub,
              outpointIndex:      0,
              network:            "chipnet",
            });

            if (!result.matched) {
              setScanResult({ matched: false, address: "", valueSats: null });
              return;
            }

            // Check UTXO balance at derived address (mock for MVP demo)
            // In production: query Electrum with result.oneTimeAddress
            const mockValueSats = 546000n; // 0.00546 BCH testnet dust

            setScanResult({
              matched:   true,
              address:   result.oneTimeAddress,
              valueSats: mockValueSats,
            });

            // Store in pool
            await pool.insertUtxo({
              txid:          "demo-txid-" + ephemeralInput.slice(0, 8),
              vout:          0,
              valueSats:     mockValueSats,
              address:       result.oneTimeAddress,
              tweakHex:      result.tweakHex,
              commitmentHex: ephemeralInput,
              height:        0,
              scanPubKeyHex: meta.scanXpub,
            });

          } catch (e) {
            setError(String(e));
          } finally {
            setIsScanning(false);
          }
        }}
      >
        {isScanning ? "👻 Scanning…" : "Scan for Funds"}
      </button>

      {/* Result */}
      {scanResult && (
        <div className={`rounded-xl p-4 text-sm mt-2 ${
          scanResult.matched
            ? "bg-green-900/40 border border-green-700"
            : "bg-gray-900 border border-gray-700"
        }`}>
          {scanResult.matched ? (
            <>
              <p className="text-green-400 font-semibold mb-2">💸 Funds appeared!</p>
              <p className="text-gray-400 text-xs mb-1">One-time destination:</p>
              <p className="font-mono text-xs text-white break-all mb-2">
                {scanResult.address}
              </p>
              <p className="text-green-300 font-mono">
                {scanResult.valueSats !== null
                  ? `${(Number(scanResult.valueSats) / 1e8).toFixed(8)} BCH`
                  : ""}
              </p>
              <p className="text-gray-500 text-xs mt-2">
                Added to your pool. Funds are ready to spend.
              </p>
            </>
          ) : (
            <p className="text-gray-400">
              No matching UTXO found for this ephemeral key.
              The transaction may not be confirmed yet.
            </p>
          )}
        </div>
      )}
    </div>
  );

  // ── Layout ────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col min-h-screen bg-gray-950 text-white p-6">
      <button className="text-gray-500 text-sm mb-6" onClick={onBack}>← Back</button>
      <h2 className="text-2xl font-bold mb-4">Ghost Receive</h2>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {(["paycode", "scan"] as ReceiveTab[]).map(t => (
          <button
            key={t}
            className={`px-4 py-2 rounded-xl text-sm font-semibold transition ${
              tab === t
                ? "bg-green-600 text-white"
                : "bg-gray-900 text-gray-400 hover:text-white"
            }`}
            onClick={() => setTab(t)}
          >
            {t === "paycode" ? "My Paycode" : "Manual Scan"}
          </button>
        ))}
      </div>

      {tab === "paycode" ? <PaycodeTab /> : <ScanTab />}
    </div>
  );
}
