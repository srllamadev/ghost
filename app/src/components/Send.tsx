/**
 * Send — "Ghost Send" flow
 *
 * The sender enters:
 *   1. Receiver's paycode (GhostPay base58 string)
 *   2. Amount in BCH
 *
 * Behind the scenes:
 *   a. A fresh ephemeral keypair is generated in WASM
 *   b. ECDH → one-time P2PKH address derived
 *   c. Transaction built: normal P2PKH output + OP_RETURN(ephemeral_pubkey)
 *   d. Signed with the sender's spend key
 *   e. Broadcast via Electrum
 *
 * The receiver sees a plain P2PKH transaction. Only they can detect it's theirs.
 *
 * STEALTH CHANGE (Q3 answer — embedded in the send flow)
 * ────────────────────────────────────────────────────────
 * Change is handled by generating a *new* ephemeral keypair for the change
 * output — using the sender's own paycode as the "receiver". This means:
 *   • The change address is also a one-time P2PKH (stealth)
 *   • No one can tell which output is payment and which is change
 *   • The change UTXO is added to the sender's own pool (scanner will find it)
 *
 * The change ephemeral pubkey is embedded as a second OP_RETURN, or in a
 * versioned OP_RETURN payload if the protocol allows it.
 */

import { useState } from "react";
import { senderDerivePayment, type SenderPaymentResult } from "../crypto/srpa";
import { SrpaScanner } from "../crypto/scanner";
import { createPoolManager } from "../store/pool";
import { getWalletMeta } from "../store/db";
import ClearSignModal from "./ClearSignModal";

interface SendProps {
  onBack: () => void;
}

interface PendingTx {
  paymentResult: SenderPaymentResult;
  changeResult:  SenderPaymentResult | null;
  receiverAddr:  string;
  changeAddr:    string | null;
  amountSats:    bigint;
  feeSats:       bigint;
  rawTxHex:      string;
}

export default function Send({ onBack }: SendProps) {
  const [paycode, setPaycode]       = useState("");
  const [amount, setAmount]         = useState("");
  const [step, setStep]             = useState<"input" | "confirm" | "sending" | "done">("input");
  const [pending, setPending]       = useState<PendingTx | null>(null);
  const [txid, setTxid]             = useState("");
  const [error, setError]           = useState("");
  const [isLoading, setIsLoading]   = useState(false);

  const network = "chipnet";
  const scanner = new SrpaScanner(createPoolManager(), network);

  // ── BCH ↔ satoshi helpers ─────────────────────────────────────────────────

  const bchToSats = (bch: string): bigint => {
    const n = parseFloat(bch);
    if (isNaN(n) || n <= 0) return 0n;
    return BigInt(Math.round(n * 1e8));
  };

  const satsToDisplay = (sats: bigint): string =>
    `${(Number(sats) / 1e8).toFixed(8)} BCH`;

  // ── Step: input ───────────────────────────────────────────────────────────

  if (step === "input") {
    return (
      <div className="flex flex-col min-h-screen bg-gray-950 text-white p-6">
        <button className="text-gray-500 text-sm mb-6" onClick={onBack}>← Back</button>
        <h2 className="text-2xl font-bold mb-1">Ghost Send</h2>
        <p className="text-gray-400 text-sm mb-6">
          Enter the receiver's paycode. The payment is invisible on-chain.
        </p>

        {/* Paycode input */}
        <label className="text-gray-400 text-xs mb-1 uppercase tracking-wide">Receiver Paycode</label>
        <input
          className="w-full bg-gray-900 text-white rounded-xl p-4 font-mono text-sm mb-4 focus:outline-none focus:ring-2 focus:ring-green-600"
          placeholder="Paste GhostPay paycode…"
          value={paycode}
          onChange={e => { setPaycode(e.target.value.trim()); setError(""); }}
        />

        {/* Amount */}
        <label className="text-gray-400 text-xs mb-1 uppercase tracking-wide">Amount (BCH)</label>
        <input
          type="number"
          className="w-full bg-gray-900 text-white rounded-xl p-4 mb-2 focus:outline-none focus:ring-2 focus:ring-green-600"
          placeholder="0.00001"
          value={amount}
          onChange={e => { setAmount(e.target.value); setError(""); }}
          min="0.00001"
          step="0.00001"
        />
        <p className="text-gray-600 text-xs mb-6">
          ≈ {bchToSats(amount).toLocaleString()} satoshis
        </p>

        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}

        <button
          className="w-full bg-green-600 hover:bg-green-500 text-white font-semibold py-4 rounded-2xl disabled:opacity-50"
          disabled={isLoading || !paycode || bchToSats(amount) <= 0n}
          onClick={async () => {
            setIsLoading(true);
            setError("");
            try {
              const meta = await getWalletMeta();
              if (!meta) throw new Error("Wallet not found");

              const amountSats = bchToSats(amount);
              const feeSats    = 1000n; // 1000 sat minimum fee

              // Placeholder outpoint — in production, select UTXOs from pool
              const placeholderTxid = "0".repeat(64);
              const placeholderVout = 0;

              // Sender derives one-time address for receiver
              const paymentResult = await senderDerivePayment(
                paycode,
                placeholderTxid,
                placeholderVout,
                network,
              );

              // Stealth change — derive using sender's own paycode
              let changeResult: SenderPaymentResult | null = null;
              const changeAmount = amountSats + feeSats + 1000n; // mock inputs
              if (changeAmount > 0n && meta.paycode) {
                changeResult = await senderDerivePayment(
                  meta.paycode,
                  placeholderTxid,
                  1,  // Different vout for change
                  network,
                );
              }

              // In production: build and sign the actual transaction via Rust core
              const rawTxHex = "(raw transaction would be built here)";

              setPending({
                paymentResult,
                changeResult,
                receiverAddr:  paymentResult.oneTimeAddress,
                changeAddr:    changeResult?.oneTimeAddress ?? null,
                amountSats,
                feeSats,
                rawTxHex,
              });
              setStep("confirm");
            } catch (e) {
              setError(String(e));
            } finally {
              setIsLoading(false);
            }
          }}
        >
          {isLoading ? "Preparing…" : "Preview Transaction →"}
        </button>
      </div>
    );
  }

  // ── Step: confirm (Clear-Signing) ─────────────────────────────────────────

  if (step === "confirm" && pending) {
    return (
      <ClearSignModal
        title="Ghost Send"
        fields={[
          { label: "To (one-time address)", value: pending.receiverAddr, mono: true },
          { label: "Amount",                value: satsToDisplay(pending.amountSats) },
          { label: "Network fee",           value: satsToDisplay(pending.feeSats) },
          { label: "Change address",        value: pending.changeAddr ?? "—", mono: true },
          { label: "Change note",           value: "Stealth — only you can detect this output" },
          { label: "Ephemeral pubkey",      value: pending.paymentResult.ephemeralPubKeyHex, mono: true },
        ]}
        warningText="Once broadcast, this transaction cannot be reversed."
        onConfirm={async () => {
          setStep("sending");
          try {
            const txid = await scanner.broadcast(pending.rawTxHex);
            setTxid(txid);
            setStep("done");
          } catch (e) {
            setError(String(e));
            setStep("input");
          }
        }}
        onCancel={() => setStep("input")}
      />
    );
  }

  // ── Step: sending ─────────────────────────────────────────────────────────

  if (step === "sending") {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-gray-950 text-white p-6 gap-4">
        <div className="text-5xl animate-pulse">👻</div>
        <p className="text-gray-300">Broadcasting your ghost payment…</p>
      </div>
    );
  }

  // ── Step: done ────────────────────────────────────────────────────────────

  if (step === "done") {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-gray-950 text-white p-6 gap-4 text-center">
        <div className="text-5xl">✅</div>
        <h2 className="text-2xl font-bold">Payment Sent!</h2>
        <p className="text-gray-400 text-sm max-w-xs">
          Your ghost payment is on its way. The receiver's wallet will detect it
          automatically — no memo, no address reuse, no trace.
        </p>
        {txid && (
          <div className="bg-gray-900 rounded-xl p-4 w-full max-w-sm">
            <p className="text-xs text-gray-500 mb-1">Transaction ID</p>
            <p className="font-mono text-xs text-green-400 break-all">{txid}</p>
          </div>
        )}
        <button
          className="w-full max-w-sm bg-gray-800 hover:bg-gray-700 text-white font-semibold py-4 rounded-2xl mt-4"
          onClick={onBack}
        >
          Back to Wallet
        </button>
      </div>
    );
  }

  return null;
}
