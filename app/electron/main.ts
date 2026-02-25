/**
 * Electron main process — GhostPay desktop entry point
 *
 * Provides:
 *  • Native window management
 *  • `safeStorage` encryption (OS keychain) for the PIN-derived key
 *  • SQLite database (better-sqlite3) via IPC bridges
 *  • Auto-update (electron-updater) stub
 *
 * Security:
 *  • contextIsolation: true, nodeIntegration: false (renderer is sandboxed)
 *  • preload.ts exposes *only* the specific IPC methods needed — no raw Node.js
 *  • The SQLite file path is under app.getPath("userData") — platform protected
 */

import { app, BrowserWindow, ipcMain, safeStorage, shell } from "electron";
import * as path from "path";
import Database from "better-sqlite3";
import { SQLITE_SCHEMA } from "../src/store/db";

// ─────────────────────────────────────────────────────────────────────────────
// SQLite
// ─────────────────────────────────────────────────────────────────────────────

let db: Database.Database;

function initDatabase(): void {
  const dbPath = path.join(app.getPath("userData"), "ghostpay.db");
  db = new Database(dbPath, { verbose: process.env.NODE_ENV === "development" ? console.log : undefined });
  db.exec(SQLITE_SCHEMA);
}

// ─────────────────────────────────────────────────────────────────────────────
// IPC handlers — exposed to renderer via preload.ts
// ─────────────────────────────────────────────────────────────────────────────

function registerIpcHandlers(): void {
  // ── safeStorage (OS keychain) ─────────────────────────────────────────────
  ipcMain.handle("safe-storage:encrypt", (_event, plaintext: string): string => {
    if (!safeStorage.isEncryptionAvailable()) return plaintext; // fallback: no OS keychain
    const encrypted = safeStorage.encryptString(plaintext);
    return encrypted.toString("base64");
  });

  ipcMain.handle("safe-storage:decrypt", (_event, b64: string): string => {
    if (!safeStorage.isEncryptionAvailable()) return b64;
    return safeStorage.decryptString(Buffer.from(b64, "base64"));
  });

  // ── SQLite generic query (read) ───────────────────────────────────────────
  ipcMain.handle("db:query", (_event, sql: string, params: unknown[]): unknown[] => {
    const stmt = db.prepare(sql);
    return stmt.all(...params);
  });

  // ── SQLite run (write) ────────────────────────────────────────────────────
  ipcMain.handle("db:run", (_event, sql: string, params: unknown[]): { changes: number; lastInsertRowid: number } => {
    const stmt   = db.prepare(sql);
    const info   = stmt.run(...params);
    return { changes: info.changes, lastInsertRowid: Number(info.lastInsertRowid) };
  });

  // ── Open external URL (block by default unless explicitly allowed) ────────
  ipcMain.handle("shell:openExternal", (_event, url: string): void => {
    const allowedDomains = [
      "explorer.bch.ninja",
      "chipnet.imaginary.cash",
      "github.com/srllamadev",
    ];
    const isAllowed = allowedDomains.some(d => url.includes(d));
    if (isAllowed) shell.openExternal(url);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Window
// ─────────────────────────────────────────────────────────────────────────────

function createWindow(): void {
  const win = new BrowserWindow({
    width:           390,
    height:          844,
    resizable:       true,
    titleBarStyle:   "hiddenInset",
    backgroundColor: "#030712", // gray-950
    webPreferences: {
      nodeIntegration:  false,
      contextIsolation: true,
      sandbox:          true,
      preload:          path.join(__dirname, "preload.js"),
    },
  });

  if (process.env.NODE_ENV === "development") {
    win.loadURL("http://localhost:5173");
    win.webContents.openDevTools({ mode: "detach" });
  } else {
    win.loadFile(path.join(__dirname, "../dist/index.html"));
  }

  // Prevent navigation away from app
  win.webContents.on("will-navigate", (event, url) => {
    if (!url.startsWith("file://") && !url.startsWith("http://localhost")) {
      event.preventDefault();
    }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// App lifecycle
// ─────────────────────────────────────────────────────────────────────────────

app.whenReady().then(() => {
  initDatabase();
  registerIpcHandlers();
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

// Graceful shutdown — flush and close SQLite
app.on("quit", () => {
  db?.close();
});
