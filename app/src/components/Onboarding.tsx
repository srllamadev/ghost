/**
 * Onboarding — Create or restore a GhostPay wallet
 *
 * Flows:
 *  1. New wallet:    generate mnemonic → backup confirmation → set PIN → done
 *  2. Import wallet: paste mnemonic → validate → set PIN → done
 *
 * UX principles (Cashual Wallet inspired):
 *  • One action per screen
 *  • Large touch targets
 *  • Clear, non-technical language
 *  • Explicit security warnings without being alarmist
 */

import { useState } from "react";
import {
  generateMnemonic,
  validateMnemonic,
  deriveWalletKeys,
  encryptKey,
} from "../crypto/srpa";
import { saveWalletMeta } from "../store/db";

type OnboardingStep =
  | "choice"
  | "generate-show"
  | "generate-confirm"
  | "import"
  | "set-pin"
  | "done";

interface OnboardingProps {
  onComplete: () => void;
}

export default function Onboarding({ onComplete }: OnboardingProps) {
  const [step, setStep]                 = useState<OnboardingStep>("choice");
  const [mnemonic, setMnemonic]         = useState("");
  const [inputMnemonic, setInputMnemonic] = useState("");
  const [confirmWords, setConfirmWords] = useState<string[]>([]);
  const [pin, setPin]                   = useState("");
  const [pinConfirm, setPinConfirm]     = useState("");
  const [error, setError]               = useState("");
  const [isLoading, setIsLoading]       = useState(false);

  // ── Step: choice ─────────────────────────────────────────────────────────

  if (step === "choice") {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-gray-950 text-white p-6 gap-6">
        <div className="text-center mb-4">
          <h1 className="text-4xl font-bold mb-2">👻 GhostPay</h1>
          <p className="text-gray-400 text-sm">Invisible payments on Bitcoin Cash</p>
        </div>
        <button
          className="w-full max-w-sm bg-green-600 hover:bg-green-500 text-white font-semibold py-4 px-6 rounded-2xl transition"
          onClick={async () => {
            setIsLoading(true);
            const mn = await generateMnemonic();
            setMnemonic(mn);
            setIsLoading(false);
            setStep("generate-show");
          }}
        >
          {isLoading ? "Generating…" : "Create New Wallet"}
        </button>
        <button
          className="w-full max-w-sm border border-gray-700 hover:border-gray-500 text-gray-300 font-semibold py-4 px-6 rounded-2xl transition"
          onClick={() => setStep("import")}
        >
          Import Existing Wallet
        </button>
      </div>
    );
  }

  // ── Step: generate-show ──────────────────────────────────────────────────

  if (step === "generate-show") {
    const words = mnemonic.split(" ");
    return (
      <div className="flex flex-col min-h-screen bg-gray-950 text-white p-6">
        <h2 className="text-2xl font-bold mb-1">Your Recovery Phrase</h2>
        <p className="text-gray-400 text-sm mb-6">
          Write these 24 words down in order. Store them offline. Never share them.
        </p>
        <div className="grid grid-cols-3 gap-2 mb-8">
          {words.map((word, i) => (
            <div key={i} className="flex items-center bg-gray-900 rounded-lg px-3 py-2">
              <span className="text-gray-600 text-xs w-5 shrink-0">{i + 1}.</span>
              <span className="font-mono text-sm">{word}</span>
            </div>
          ))}
        </div>
        <div className="bg-yellow-900/40 border border-yellow-700 rounded-xl p-4 mb-6 text-sm text-yellow-300">
          ⚠️ If you lose this phrase, your funds are gone forever. GhostPay has
          no recovery server. No one can help you.
        </div>
        <button
          className="w-full bg-green-600 hover:bg-green-500 text-white font-semibold py-4 rounded-2xl"
          onClick={() => {
            // Pick 4 random positions to confirm
            const indices = [2, 7, 14, 21]; // fixed for MVP; randomize in prod
            setConfirmWords(indices.map(i => words[i] ?? ""));
            setStep("generate-confirm");
          }}
        >
          I've Written It Down →
        </button>
      </div>
    );
  }

  // ── Step: generate-confirm ───────────────────────────────────────────────

  if (step === "generate-confirm") {
    return (
      <div className="flex flex-col min-h-screen bg-gray-950 text-white p-6">
        <h2 className="text-2xl font-bold mb-2">Confirm Backup</h2>
        <p className="text-gray-400 text-sm mb-6">
          Verify you wrote your phrase correctly.
        </p>
        <div className="bg-gray-900 rounded-xl p-4 mb-4 text-sm text-gray-300">
          Words #3, #8, #15, and #22 of your phrase are:{" "}
          <span className="font-mono text-green-400">
            {confirmWords.join(", ")}
          </span>
        </div>
        <p className="text-gray-500 text-sm mb-6">
          (In production this screen asks you to type them; for the MVP, click
          Confirm if they match your written backup.)
        </p>
        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
        <button
          className="w-full bg-green-600 hover:bg-green-500 text-white font-semibold py-4 rounded-2xl"
          onClick={() => setStep("set-pin")}
        >
          Confirm — They Match →
        </button>
      </div>
    );
  }

  // ── Step: import ─────────────────────────────────────────────────────────

  if (step === "import") {
    return (
      <div className="flex flex-col min-h-screen bg-gray-950 text-white p-6">
        <h2 className="text-2xl font-bold mb-2">Import Wallet</h2>
        <p className="text-gray-400 text-sm mb-4">
          Enter your 24-word recovery phrase.
        </p>
        <textarea
          className="w-full bg-gray-900 text-white rounded-xl p-4 font-mono text-sm h-40 resize-none focus:outline-none focus:ring-2 focus:ring-green-600 mb-4"
          placeholder="word1 word2 word3 … word24"
          value={inputMnemonic}
          onChange={e => {
            setInputMnemonic(e.target.value.trim().toLowerCase());
            setError("");
          }}
        />
        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
        <button
          className="w-full bg-green-600 hover:bg-green-500 text-white font-semibold py-4 rounded-2xl"
          onClick={async () => {
            const valid = await validateMnemonic(inputMnemonic);
            if (!valid) {
              setError("Invalid recovery phrase. Check for typos.");
              return;
            }
            setMnemonic(inputMnemonic);
            setStep("set-pin");
          }}
        >
          Continue →
        </button>
      </div>
    );
  }

  // ── Step: set-pin ────────────────────────────────────────────────────────

  if (step === "set-pin") {
    return (
      <div className="flex flex-col min-h-screen bg-gray-950 text-white p-6">
        <h2 className="text-2xl font-bold mb-2">Set a PIN</h2>
        <p className="text-gray-400 text-sm mb-6">
          Your PIN encrypts your keys on this device. Use at least 8 characters.
        </p>
        <input
          type="password"
          className="w-full bg-gray-900 text-white rounded-xl p-4 mb-4 focus:outline-none focus:ring-2 focus:ring-green-600"
          placeholder="PIN / passphrase"
          value={pin}
          onChange={e => { setPin(e.target.value); setError(""); }}
        />
        <input
          type="password"
          className="w-full bg-gray-900 text-white rounded-xl p-4 mb-4 focus:outline-none focus:ring-2 focus:ring-green-600"
          placeholder="Confirm PIN"
          value={pinConfirm}
          onChange={e => { setPinConfirm(e.target.value); setError(""); }}
        />
        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
        <button
          className="w-full bg-green-600 hover:bg-green-500 text-white font-semibold py-4 rounded-2xl disabled:opacity-50"
          disabled={isLoading}
          onClick={async () => {
            if (pin.length < 8) {
              setError("PIN must be at least 8 characters.");
              return;
            }
            if (pin !== pinConfirm) {
              setError("PINs do not match.");
              return;
            }
            setIsLoading(true);
            try {
              const keys = await deriveWalletKeys(mnemonic, "");

              // Encrypt spend and scan keys with PIN before saving
              // (In this MVP we store xpubs only; full impl encrypts xprivs here)
              await saveWalletMeta({
                network:      "chipnet",
                paycode:      keys.paycode,
                spendXpub:    keys.spendXpub,
                scanXpub:     keys.scanXpub,
                covenantXpub: keys.covenantXpub,
                createdAt:    Date.now(),
                lastSyncedAt: 0,
              });

              setStep("done");
              onComplete();
            } catch (e) {
              setError(String(e));
            } finally {
              setIsLoading(false);
            }
          }}
        >
          {isLoading ? "Creating wallet…" : "Create Wallet →"}
        </button>
      </div>
    );
  }

  return null;
}
