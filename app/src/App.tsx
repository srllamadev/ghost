/**
 * App.tsx — Root component and router
 *
 * Screens:
 *   onboarding → (walletExists) → dashboard → send | receive
 *
 * Auth gate: check IndexedDB for existing wallet on startup.
 * If none: show Onboarding. If exists: show locked Dashboard + PIN prompt.
 */

import { useEffect, useState } from "react";
import Onboarding from "./components/Onboarding";
import Dashboard  from "./components/Dashboard";
import Send       from "./components/Send";
import Receive    from "./components/Receive";
import { getWalletMeta } from "./store/db";
import { SrpaScanner } from "./crypto/scanner";
import { createPoolManager } from "./store/pool";

type Screen = "loading" | "onboarding" | "dashboard" | "send" | "receive";

const scanner = new SrpaScanner(createPoolManager(), "chipnet");

export default function App() {
  const [screen, setScreen] = useState<Screen>("loading");

  useEffect(() => {
    getWalletMeta().then(meta => {
      setScreen(meta ? "dashboard" : "onboarding");
    });
  }, []);

  if (screen === "loading") {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-950">
        <div className="text-5xl animate-pulse">👻</div>
      </div>
    );
  }

  if (screen === "onboarding") {
    return <Onboarding onComplete={() => setScreen("dashboard")} />;
  }

  if (screen === "send") {
    return <Send onBack={() => setScreen("dashboard")} />;
  }

  if (screen === "receive") {
    return (
      <Receive
        onBack={() => setScreen("dashboard")}
        scanner={scanner}
      />
    );
  }

  return (
    <Dashboard
      onSend={() => setScreen("send")}
      onReceive={() => setScreen("receive")}
    />
  );
}
