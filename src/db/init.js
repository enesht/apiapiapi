// api/src/db/init.js
import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Lambda'da /tmp kullan (writable), local'de proje klasörü
const DB_PATH = process.env.AWS_LAMBDA_FUNCTION_NAME
  ? '/tmp/akca.db'  // Lambda environment
  : join(__dirname, '..', '..', 'akca.db');  // Local development

export function initDatabase() {
  const db = new Database(DB_PATH);

  // ============================================================================
  // PAYMENTS (IP tracking)
  // ============================================================================
  db.exec(`
    CREATE TABLE IF NOT EXISTS payments (
      id TEXT PRIMARY KEY,              -- UUID reference
      wallet TEXT NOT NULL,             -- Solana wallet address
      plan TEXT NOT NULL,               -- 'standard' | 'pro'
      amount_sol REAL NOT NULL,         -- Payment amount in SOL
      amount_usdt REAL NOT NULL,        -- Payment amount in USDT
      amount_usd REAL NOT NULL,         -- USD value at payment time
      tx_signature TEXT,                -- Solana transaction signature
      status TEXT NOT NULL,             -- 'pending' | 'paid' | 'failed'
      payment_method TEXT DEFAULT 'sol',-- 'sol' | 'usdt'
      ip_address TEXT NOT NULL,         -- User's IP at payment time
      user_agent TEXT,                  -- Browser user agent
      created_at TEXT NOT NULL,
      updated_at TEXT,
      confirmed_at TEXT
    )
  `);

  // ============================================================================
  // SUBSCRIPTIONS (NFT-based, no Arweave)  <-- status eklendi
  // ============================================================================
  db.exec(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id TEXT PRIMARY KEY,              -- Unique subscription ID (UUID)
      wallet TEXT NOT NULL,             -- User's Solana wallet
      plan TEXT NOT NULL,               -- 'standard' | 'pro'
      nft_mint TEXT UNIQUE,             -- NFT mint address (unique ID) - nullable until minted
      device_limit INTEGER NOT NULL,    -- 2 (standard) | 5 (pro)
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,         -- +30 days from creation
      price_usd REAL NOT NULL,
      price_sol REAL,
      price_usdt REAL,
      tx_signature TEXT NOT NULL,
      mint_ip_address TEXT NOT NULL,    -- IP where NFT was minted
      status TEXT NOT NULL DEFAULT 'active', -- 'pending' | 'active' | 'cancelled'
      is_active INTEGER DEFAULT 1,
      cancelled_at TEXT,
      auto_renew INTEGER DEFAULT 0
    )
  `);

  // ============================================================================
  // VPN SESSIONS (detailed IP logging + WireGuard)
  // ============================================================================
  db.exec(`
    CREATE TABLE IF NOT EXISTS vpn_sessions (
      id TEXT PRIMARY KEY,              -- Session UUID
      wallet TEXT NOT NULL,
      subscription_id TEXT NOT NULL,
      nft_mint TEXT NOT NULL,           -- Which NFT was used for access
      server_id TEXT NOT NULL,          -- e.g. 'us-east-1'
      server_ip TEXT NOT NULL,          -- VPN node IP address
      session_key TEXT NOT NULL,        -- Encrypted session key (legacy, deprecated for WG)
      client_ip TEXT NOT NULL,          -- User's IP address (LOGGED)
      client_country TEXT,              -- User's country (from IP)
      device_info TEXT,                 -- Device fingerprint
      connected_at TEXT NOT NULL,
      disconnected_at TEXT,
      bytes_sent INTEGER DEFAULT 0,
      bytes_received INTEGER DEFAULT 0,
      duration_seconds INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active',     -- 'active' | 'disconnected' | 'timeout'
      wg_public_key TEXT,               -- WireGuard client public key
      wg_private_key TEXT,              -- WireGuard client private key (encrypted at rest)
      wg_client_ip TEXT,                -- Assigned WireGuard tunnel IP (10.8.0.x)
      wg_config TEXT,                   -- Full WireGuard config for client
      FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
    )
  `);

  // ============================================================================
  // VPN SERVERS (dynamic node management + WireGuard)
  // ============================================================================
  db.exec(`
    CREATE TABLE IF NOT EXISTS vpn_servers (
      id TEXT PRIMARY KEY,              -- 'us-east-1'
      name TEXT NOT NULL,               -- Display name
      location TEXT NOT NULL,           -- City name
      country_code TEXT NOT NULL,       -- ISO country code
      host TEXT NOT NULL,               -- Public IP or domain
      port INTEGER NOT NULL,            -- 51820 for WireGuard (UDP)
      protocol TEXT NOT NULL,           -- 'wireguard' | 'tcp' (legacy)
      capacity INTEGER DEFAULT 100,     -- Max concurrent users
      current_load INTEGER DEFAULT 0,   -- Active connections
      is_active INTEGER DEFAULT 1,      -- Auto-updated by health check
      is_premium INTEGER DEFAULT 0,     -- 1 = Pro only, 0 = All users
      manually_disabled INTEGER DEFAULT 0, -- 1 = Admin disabled, 0 = Auto health check
      ping_ms INTEGER DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT,
      last_health_check TEXT,
      wg_public_key TEXT,               -- WireGuard server public key
      wg_endpoint TEXT,                 -- WireGuard endpoint (host:port)
      wg_ssh_host TEXT,                 -- SSH host for peer management
      wg_ssh_port INTEGER DEFAULT 22,  -- SSH port
      wg_ssh_user TEXT DEFAULT 'root'   -- SSH username
    )
  `);

  // Migration: Add manually_disabled column if it doesn't exist
  try {
    db.exec(`ALTER TABLE vpn_servers ADD COLUMN manually_disabled INTEGER DEFAULT 0`);
  } catch (err) {
    // Column already exists, ignore
  }

  // Migration: Add WireGuard columns to vpn_sessions
  try {
    db.exec(`ALTER TABLE vpn_sessions ADD COLUMN wg_public_key TEXT`);
    db.exec(`ALTER TABLE vpn_sessions ADD COLUMN wg_private_key TEXT`);
    db.exec(`ALTER TABLE vpn_sessions ADD COLUMN wg_client_ip TEXT`);
    db.exec(`ALTER TABLE vpn_sessions ADD COLUMN wg_config TEXT`);
  } catch (err) {
    // Columns already exist, ignore
  }

  // Migration: Add WireGuard columns to vpn_servers
  try {
    db.exec(`ALTER TABLE vpn_servers ADD COLUMN wg_public_key TEXT`);
    db.exec(`ALTER TABLE vpn_servers ADD COLUMN wg_endpoint TEXT`);
    db.exec(`ALTER TABLE vpn_servers ADD COLUMN wg_ssh_host TEXT`);
    db.exec(`ALTER TABLE vpn_servers ADD COLUMN wg_ssh_port INTEGER DEFAULT 22`);
    db.exec(`ALTER TABLE vpn_servers ADD COLUMN wg_ssh_user TEXT DEFAULT 'root'`);
  } catch (err) {
    // Columns already exist, ignore
  }

  // ============================================================================
  // AUDIT LOGS
  // ============================================================================
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,         -- e.g., 'wallet_connected', 'payment_init'
      wallet TEXT,
      ip_address TEXT,
      user_agent TEXT,
      details TEXT,                     -- JSON
      created_at TEXT NOT NULL
    )
  `);

  // ============================================================================
  // NFT METADATA (SQLite storage, no Arweave)
  // ============================================================================
  db.exec(`
    CREATE TABLE IF NOT EXISTS nft_metadata (
      mint_address TEXT PRIMARY KEY,    -- NFT mint address (unique ID)
      subscription_id TEXT NOT NULL,    -- Links to subscriptions table
      wallet TEXT NOT NULL,             -- Owner wallet
      plan TEXT NOT NULL,               -- 'standard' | 'pro'
      device_limit INTEGER NOT NULL,    -- 2 or 5
      name TEXT NOT NULL,               -- "Akca Network - Standard"
      symbol TEXT NOT NULL,             -- "AKCA"
      description TEXT NOT NULL,
      tier TEXT NOT NULL,               -- 'standard' | 'pro'
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      mint_ip TEXT NOT NULL,            -- IP where NFT was minted
      attributes TEXT NOT NULL,         -- JSON string
      FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
    )
  `);

  // ============================================================================
  // INDEXES
  // ============================================================================
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_payments_wallet ON payments(wallet);
    CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
    CREATE INDEX IF NOT EXISTS idx_payments_created ON payments(created_at);

    CREATE INDEX IF NOT EXISTS idx_sub_wallet ON subscriptions(wallet);
    CREATE INDEX IF NOT EXISTS idx_sub_nft ON subscriptions(nft_mint);
    CREATE INDEX IF NOT EXISTS idx_sub_active ON subscriptions(is_active);
    CREATE INDEX IF NOT EXISTS idx_sub_status ON subscriptions(status);
    CREATE INDEX IF NOT EXISTS idx_sub_expires ON subscriptions(expires_at);

    CREATE INDEX IF NOT EXISTS idx_vpn_wallet ON vpn_sessions(wallet);
    CREATE INDEX IF NOT EXISTS idx_vpn_status ON vpn_sessions(status);
    CREATE INDEX IF NOT EXISTS idx_vpn_connected ON vpn_sessions(connected_at);
    CREATE INDEX IF NOT EXISTS idx_vpn_server ON vpn_sessions(server_id);

    CREATE INDEX IF NOT EXISTS idx_servers_active ON vpn_servers(is_active);
    CREATE INDEX IF NOT EXISTS idx_servers_location ON vpn_servers(location);

    CREATE INDEX IF NOT EXISTS idx_audit_wallet ON audit_logs(wallet);
    CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event_type);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

    CREATE INDEX IF NOT EXISTS idx_meta_wallet ON nft_metadata(wallet);
    CREATE INDEX IF NOT EXISTS idx_meta_subscription ON nft_metadata(subscription_id);
  `);

  // ============================================================================
  // Seed 4 production VPN nodes (only if table is empty)
  // ============================================================================
  const now = new Date().toISOString();
  const countRow = db.prepare('SELECT COUNT(*) AS count FROM vpn_servers').get();
  if ((countRow?.count ?? 0) === 0) {
    const insertServer = db.prepare(`
      INSERT INTO vpn_servers
      (id, name, location, country_code, host, port, protocol, capacity, is_active, is_premium, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    `);

    const servers = [
      ['us-east-1',       'US East Coast', 'New York',     'US', '45.79.123.45', 51820, 'wireguard', 200, 0, now],
      ['eu-west-1',       'Europe West',   'London',       'GB', '178.79.156.89',51820, 'wireguard', 200, 0, now],
      ['asia-pacific-1',  'Asia Pacific',  'Singapore',    'SG', '139.162.34.12',51820, 'wireguard', 150, 1, now], // Pro
      ['us-west-1',       'US West Coast', 'Los Angeles',  'US', '172.105.67.234',51820,'wireguard', 150, 1, now], // Pro
    ];
    servers.forEach(s => insertServer.run(...s));
    console.log(`✅ Inserted ${servers.length} WireGuard VPN nodes (2 standard + 2 pro)`);
  }

  console.log('✅ Database initialized successfully at:', DB_PATH);
  console.log('   Tables: payments, subscriptions, vpn_sessions, vpn_servers, audit_logs, nft_metadata');
  return db;
}

export function getDatabase() {
  return new Database(DB_PATH);
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  initDatabase();
}
