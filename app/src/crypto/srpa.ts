/**
 * SRPA — Silent Reusable Payment Addresses (TypeScript layer)
 *
 * This module wraps the Rust WASM core for SRPA operations.
 * All private key cryptography runs inside the WASM sandbox.
 * This TypeScript layer only manages:
 *   - Paycode parsing / display
 *   - Coordinating sender/receiver flows
 *   - Electrum RPC for UTXO queries
 */

// Dynamic WASM import — loaded once at startup
let core: typeof import("../../../core/pkg/ghostpay_core") | null = null;

async function getCore() {
  if (!core) {
    core = await import("../../../core/pkg/ghostpay_core");
    core.set_panic_hook?.();
  }
  return core;
}

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface Paycode {
  raw:           string;          // Base58check encoded paycode string
  spendPubKeyHex: string;
  scanPubKeyHex:  string;
  network:        "chipnet" | "mainnet";
}

export interface SenderPaymentResult {
  ephemeralPubKeyHex: string;    // embed this in OP_RETURN
  oneTimeAddress:     string;    // P2PKH cashaddr to fund
  tweakHex:           string;    // stored in local pool for the sender
}

export interface ReceiverScanResult {
  matched:          boolean;
  oneTimeAddress:   string;
  tweakHex:         string;      // stored in pool for later spend
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet key bundle (public side only — private keys stay in WASM)
// ─────────────────────────────────────────────────────────────────────────────

export interface WalletPublicBundle {
  spendXpub:    string;
  scanXpub:     string;
  covenantXpub: string;
  paycode:      string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Mnemonic helpers
// ─────────────────────────────────────────────────────────────────────────────

export async function generateMnemonic(): Promise<string> {
  const c = await getCore();
  return c.generate_mnemonic();
}

export async function validateMnemonic(mnemonic: string): Promise<boolean> {
  const c = await getCore();
  return c.validate_mnemonic(mnemonic);
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet creation
// ─────────────────────────────────────────────────────────────────────────────

export async function deriveWalletKeys(
  mnemonic: string,
  passphrase = "",
): Promise<WalletPublicBundle> {
  const c   = await getCore();
  const raw = c.derive_keys(mnemonic, passphrase);
  const parsed = JSON.parse(raw) as {
    spend_xpub: string;
    scan_xpub:  string;
    covenant_xpub: string;
    paycode: string;
  };
  return {
    spendXpub:    parsed.spend_xpub,
    scanXpub:     parsed.scan_xpub,
    covenantXpub: parsed.covenant_xpub,
    paycode:      parsed.paycode,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Sender flow
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Derive the one-time address and ephemeral pubkey for a payment.
 *
 * The sender:
 *   1. Calls this with the receiver's paycode.
 *   2. Sends BCH to `oneTimeAddress` in a normal P2PKH output.
 *   3. Adds an OP_RETURN output with `ephemeralPubKeyHex` so the receiver
 *      can scan and find the payment.
 */
export async function senderDerivePayment(
  receiverPaycode: string,
  fundingTxid: string,
  vout: number,
  network: "chipnet" | "mainnet" = "chipnet",
): Promise<SenderPaymentResult> {
  const c   = await getCore();
  const raw = c.sender_derive_payment(receiverPaycode, fundingTxid, vout, network);
  const parsed = JSON.parse(raw) as {
    ephemeral_pubkey_hex: string;
    one_time_address:     string;
    tweak_hex:            string;
  };
  return {
    ephemeralPubKeyHex: parsed.ephemeral_pubkey_hex,
    oneTimeAddress:     parsed.one_time_address,
    tweakHex:           parsed.tweak_hex,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Receiver flow
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Scan an OP_RETURN payload for an incoming SRPA payment.
 *
 * The receiver calls this for each OP_RETURN found during block scanning.
 * If the result has `matched: true`, a UTXO at `oneTimeAddress` belongs to us.
 */
export async function receiverScanOpReturn(params: {
  scanXprivEncrypted: string;
  encryptionKeyHex:   string;
  ephemeralPubKeyHex: string;
  spendXpub:          string;
  outpointIndex:      number;
  network:            "chipnet" | "mainnet";
}): Promise<ReceiverScanResult> {
  const c   = await getCore();
  const raw = c.receiver_scan_opreturn(
    params.scanXprivEncrypted,
    params.encryptionKeyHex,
    params.ephemeralPubKeyHex,
    params.spendXpub,
    params.outpointIndex,
    params.network,
  );
  const parsed = JSON.parse(raw) as {
    matched:          boolean;
    one_time_address: string;
    tweak_hex:        string;
  };
  return {
    matched:        parsed.matched,
    oneTimeAddress: parsed.one_time_address ?? "",
    tweakHex:       parsed.tweak_hex ?? "",
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Spend flow
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sign and build a raw BCH transaction spending a SRPA UTXO.
 * Returns hex-encoded signed transaction ready for Electrum broadcast.
 */
export async function signSrpaSpend(params: {
  spendXprivEncrypted: string;
  encryptionKeyHex:    string;
  utxo: {
    txid:      string;
    vout:      number;
    valueSats: bigint;
    tweakHex:  string;
  };
  recipientCashAddr:   string;
  feeSats:             bigint;
  network:             "chipnet" | "mainnet";
}): Promise<string> {
  const c = await getCore();
  return c.sign_srpa_spend(
    params.spendXprivEncrypted,
    params.encryptionKeyHex,
    JSON.stringify({
      txid:       params.utxo.txid,
      vout:       params.utxo.vout,
      value_sats: Number(params.utxo.valueSats),
      tweak_hex:  params.utxo.tweakHex,
    }),
    params.recipientCashAddr,
    Number(params.feeSats),
    params.network,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Key encryption helpers
// ─────────────────────────────────────────────────────────────────────────────

export async function encryptKey(rawKeyHex: string, password: string): Promise<string> {
  const c = await getCore();
  return c.encrypt_key(rawKeyHex, password);
}

export async function decryptKey(encryptedB64: string, password: string): Promise<string> {
  const c = await getCore();
  return c.decrypt_key(encryptedB64, password);
}
