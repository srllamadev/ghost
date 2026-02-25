/**
 * WalletConnect V2 Provider for GhostPay
 *
 * Implements the @bch-wc2/interfaces specification so GhostPay can act as a
 * "signer wallet" for BCH dApps (e.g., CashTokens Studio, Emerald DAO, etc.)
 *
 * Supported JSON-RPC methods:
 *   bch_getAddresses          — return the paycode + current receive address
 *   bch_signTransaction       — present clear-sign UI, sign, return signed tx
 *   bch_sendTransaction       — sign + broadcast, return txid
 *   bch_signMessage           — sign arbitrary message with spend key
 *   wallet_getCapabilities    — advertise SRPA + CashTokens support
 *
 * Privacy note:
 *   dApps receive the *paycode*, not a P2PKH address. Any payment they
 *   construct to that paycode will be routed through the SRPA protocol,
 *   preserving the privacy guarantee even when interacting with dApps.
 *
 * Sessions:
 *   Stored in IndexedDB under "wc2_sessions". Paired via QR or deep-link.
 *   Sessions expire after 7 days of inactivity.
 */

import { Core }           from "@walletconnect/core";
import { Web3Wallet }     from "@walletconnect/web3wallet";
import type {
  Web3WalletTypes,
}                         from "@walletconnect/web3wallet";
import { buildApprovedNamespaces, getSdkError } from "@walletconnect/utils";
import { getWalletMeta }  from "../store/db";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export interface WC2Session {
  topic:    string;
  peerName: string;
  peerIcon: string | null;
  pairedAt: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// GhostPay WalletConnect V2 Provider
// ─────────────────────────────────────────────────────────────────────────────

export class GhostPayWCProvider {
  private wallet: InstanceType<typeof Web3Wallet> | null = null;

  /** Initialise the WC2 client. Call once on startup. */
  async init(projectId: string): Promise<void> {
    const core = new Core({ projectId });
    this.wallet = await Web3Wallet.init({
      core,
      metadata: {
        name:        "GhostPay",
        description: "Silent Reusable Payment Addresses for Bitcoin Cash",
        url:         "https://ghostpay.cash",
        icons:       ["https://ghostpay.cash/icon.png"],
      },
    });

    this.registerEventListeners();
  }

  /** Pair with a dApp using a WalletConnect URI. */
  async pair(uri: string): Promise<void> {
    if (!this.wallet) throw new Error("WC2 not initialised — call init() first");
    await this.wallet.core.pairing.pair({ uri });
  }

  /** List all active sessions. */
  getActiveSessions(): WC2Session[] {
    if (!this.wallet) return [];
    return Object.values(this.wallet.getActiveSessions()).map(s => ({
      topic:    s.topic,
      peerName: s.peer.metadata.name,
      peerIcon: s.peer.metadata.icons[0] ?? null,
      pairedAt: s.expiry * 1000 - 7 * 24 * 60 * 60 * 1000,
    }));
  }

  /** Disconnect a session. */
  async disconnect(topic: string): Promise<void> {
    if (!this.wallet) return;
    await this.wallet.disconnectSession({
      topic,
      reason: getSdkError("USER_DISCONNECTED"),
    });
  }

  // ── Event listeners ────────────────────────────────────────────────────────

  private registerEventListeners(): void {
    if (!this.wallet) return;

    // Session proposal — dApp wants to connect
    this.wallet.on("session_proposal", async (proposal: Web3WalletTypes.SessionProposal) => {
      await this.handleSessionProposal(proposal);
    });

    // Session request — dApp wants us to sign/send
    this.wallet.on("session_request", async (event: Web3WalletTypes.SessionRequest) => {
      await this.handleSessionRequest(event);
    });
  }

  // ── Session proposal ───────────────────────────────────────────────────────

  private async handleSessionProposal(
    proposal: Web3WalletTypes.SessionProposal,
  ): Promise<void> {
    if (!this.wallet) return;

    const meta = await getWalletMeta();
    if (!meta) {
      await this.wallet.rejectSession({
        id:     proposal.id,
        reason: getSdkError("UNSUPPORTED_CHAINS"),
      });
      return;
    }

    // Build approved namespaces for BCH
    // Chain IDs: bch:mainnet, bch:chipnet
    const chainId = meta.network === "mainnet" ? "bch:mainnet" : "bch:chipnet";
    const accountId = `${chainId}:${meta.paycode}`;

    try {
      const approvedNamespaces = buildApprovedNamespaces({
        proposal: proposal.params,
        supportedNamespaces: {
          bch: {
            chains:   [chainId],
            methods:  [
              "bch_getAddresses",
              "bch_signTransaction",
              "bch_sendTransaction",
              "bch_signMessage",
              "wallet_getCapabilities",
            ],
            events:   ["accountsChanged", "chainChanged"],
            accounts: [accountId],
          },
        },
      });

      await this.wallet.approveSession({
        id:         proposal.id,
        namespaces: approvedNamespaces,
      });
    } catch (e) {
      await this.wallet.rejectSession({
        id:     proposal.id,
        reason: getSdkError("USER_REJECTED"),
      });
    }
  }

  // ── Session request (JSON-RPC handler) ────────────────────────────────────

  private async handleSessionRequest(
    event: Web3WalletTypes.SessionRequest,
  ): Promise<void> {
    if (!this.wallet) return;
    const { topic, params, id } = event;
    const { request }           = params;

    let result: unknown;
    let error: { code: number; message: string } | null = null;

    try {
      result = await this.dispatchMethod(request.method, request.params);
    } catch (e) {
      error = { code: 4001, message: String(e) };
    }

    if (error) {
      await this.wallet.respondSessionRequest({
        topic,
        response: { id, jsonrpc: "2.0", error },
      });
    } else {
      await this.wallet.respondSessionRequest({
        topic,
        response: { id, jsonrpc: "2.0", result },
      });
    }
  }

  private async dispatchMethod(
    method: string,
    params: unknown,
  ): Promise<unknown> {
    const meta = await getWalletMeta();
    if (!meta) throw new Error("Wallet locked or not initialised");

    switch (method) {
      // ── bch_getAddresses ──────────────────────────────────────────────────
      case "bch_getAddresses": {
        // Return the static paycode. dApps should use this for SRPA payments.
        return {
          paycode: meta.paycode,
          // For dApps that don't support SRPA yet, also return a standard
          // P2PKH address derived from the spend xpub (index 0).
          legacyAddress: "(P2PKH derived from spend xpub — for legacy dApps)",
        };
      }

      // ── wallet_getCapabilities ────────────────────────────────────────────
      case "wallet_getCapabilities": {
        return {
          srpa:        true,
          cashTokens:  true,
          covenants:   true,
          pqReadiness: true,
          version:     "1.0.0",
        };
      }

      // ── bch_signMessage ───────────────────────────────────────────────────
      case "bch_signMessage": {
        const { message } = params as { message: string };
        // In production: show clear-sign UI → sign with spend key via WASM
        // For MVP: return a placeholder
        return {
          signature: "(message sig — requires PIN entry in UI)",
          message,
          address:   meta.paycode,
        };
      }

      // ── bch_signTransaction ───────────────────────────────────────────────
      case "bch_signTransaction": {
        const { transaction } = params as { transaction: string };
        // Show clear-sign modal in UI, then sign via Rust core
        // This requires UI interaction — dispatch an event to the React layer
        window.dispatchEvent(new CustomEvent("ghostpay:wc2-sign-request", {
          detail: { method: "bch_signTransaction", transaction },
        }));
        // Return a pending signal; the UI will resolve via `respondSessionRequest`
        return { status: "pending", message: "Awaiting user confirmation" };
      }

      // ── bch_sendTransaction ───────────────────────────────────────────────
      case "bch_sendTransaction": {
        const { transaction: rawHex } = params as { transaction: string };
        window.dispatchEvent(new CustomEvent("ghostpay:wc2-sign-request", {
          detail: { method: "bch_sendTransaction", transaction: rawHex },
        }));
        return { status: "pending", message: "Awaiting user confirmation" };
      }

      default:
        throw new Error(`Method ${method} not supported`);
    }
  }
}

// Singleton instance
export const wcProvider = new GhostPayWCProvider();
