// api/src/utils/wireguard.js
// WireGuard key generation, config generation, and IP management utilities

import { execSync } from 'child_process';
import crypto from 'crypto';

/**
 * Generate WireGuard key pair using system wg command
 * @returns {Promise<{privateKey: string, publicKey: string}>}
 */
export async function generateKeyPair() {
  try {
    // Generate private key: wg genkey
    const privateKey = execSync('wg genkey', { encoding: 'utf8' }).trim();

    // Derive public key: echo <private> | wg pubkey
    const publicKey = execSync(`echo "${privateKey}" | wg pubkey`, {
      encoding: 'utf8',
      shell: '/bin/bash'
    }).trim();

    return { privateKey, publicKey };
  } catch (error) {
    console.error('Error generating WireGuard keys:', error);
    throw new Error('Failed to generate WireGuard keys. Ensure wg command is installed.');
  }
}

/**
 * Assign an available IP address from the WireGuard subnet (10.8.0.0/24)
 * @param {object} db - SQLite database instance
 * @param {string} wallet - User wallet address (for logging)
 * @returns {Promise<string>} Assigned IP (e.g., "10.8.0.42")
 */
export async function assignClientIP(db, wallet) {
  // Query all currently assigned IPs
  const activeSessions = db.prepare(`
    SELECT wg_client_ip
    FROM vpn_sessions
    WHERE wg_client_ip IS NOT NULL
      AND status = 'active'
  `).all();

  const usedIPs = new Set(activeSessions.map(s => s.wg_client_ip));

  // 10.8.0.1 is gateway (server), 10.8.0.2-254 available for clients
  for (let i = 2; i <= 254; i++) {
    const candidateIP = `10.8.0.${i}`;
    if (!usedIPs.has(candidateIP)) {
      console.log(`✅ Assigned WireGuard IP ${candidateIP} to wallet ${wallet}`);
      return candidateIP;
    }
  }

  throw new Error('No available WireGuard IPs (subnet exhausted)');
}

/**
 * Generate WireGuard client configuration file content
 * @param {object} params
 * @param {string} params.clientPrivateKey - Client private key
 * @param {string} params.clientIP - Assigned client IP (e.g., "10.8.0.42")
 * @param {string} params.serverPublicKey - Server public key
 * @param {string} params.serverEndpoint - Server endpoint (host:port)
 * @param {string} params.dns - DNS server (default: 1.1.1.1)
 * @returns {string} WireGuard config content
 */
export function generateClientConfig({
  clientPrivateKey,
  clientIP,
  serverPublicKey,
  serverEndpoint,
  dns = '1.1.1.1'
}) {
  return `[Interface]
PrivateKey = ${clientPrivateKey}
Address = ${clientIP}/24
DNS = ${dns}

[Peer]
PublicKey = ${serverPublicKey}
Endpoint = ${serverEndpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`;
}

/**
 * Generate a unique peer identifier (for logging)
 * @param {string} wallet - User wallet address
 * @param {string} clientIP - Assigned IP
 * @returns {string} Peer ID
 */
export function generatePeerID(wallet, clientIP) {
  const hash = crypto.createHash('sha256')
    .update(`${wallet}-${clientIP}-${Date.now()}`)
    .digest('hex')
    .substring(0, 12);
  return `peer-${hash}`;
}

/**
 * Validate WireGuard public key format
 * @param {string} key - Public key to validate
 * @returns {boolean} True if valid
 */
export function validatePublicKey(key) {
  // WireGuard public keys are 44 characters base64
  const keyRegex = /^[A-Za-z0-9+/]{42}[A-Za-z0-9+/=]{2}$/;
  return keyRegex.test(key);
}

/**
 * Encrypt sensitive data (private keys) for storage
 * @param {string} data - Data to encrypt
 * @param {string} secret - Encryption secret (from env)
 * @returns {string} Encrypted data (base64)
 */
export function encryptPrivateKey(data, secret) {
  const algorithm = 'aes-256-gcm';
  const iv = crypto.randomBytes(16);
  const key = crypto.scryptSync(secret, 'salt', 32);

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(data, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  const authTag = cipher.getAuthTag();

  // Return format: iv:authTag:encrypted
  return `${iv.toString('base64')}:${authTag.toString('base64')}:${encrypted}`;
}

/**
 * Decrypt sensitive data (private keys) from storage
 * @param {string} encryptedData - Encrypted data string (iv:authTag:encrypted)
 * @param {string} secret - Encryption secret (from env)
 * @returns {string} Decrypted data
 */
export function decryptPrivateKey(encryptedData, secret) {
  const algorithm = 'aes-256-gcm';
  const [ivB64, authTagB64, encrypted] = encryptedData.split(':');

  const iv = Buffer.from(ivB64, 'base64');
  const authTag = Buffer.from(authTagB64, 'base64');
  const key = crypto.scryptSync(secret, 'salt', 32);

  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Parse WireGuard server info from database record
 * @param {object} serverRow - Database row from vpn_servers
 * @returns {object} Server info object
 */
export function parseServerInfo(serverRow) {
  return {
    id: serverRow.id,
    name: serverRow.name,
    location: serverRow.location,
    host: serverRow.host,
    port: serverRow.port,
    publicKey: serverRow.wg_public_key,
    endpoint: serverRow.wg_endpoint || `${serverRow.host}:${serverRow.port}`,
    sshHost: serverRow.wg_ssh_host || serverRow.host,
    sshPort: serverRow.wg_ssh_port || 22,
    sshUser: serverRow.wg_ssh_user || 'root',
  };
}

/**
 * Get WireGuard server stats (active peers, bandwidth, etc.)
 * This would query the server via SSH in production
 * @param {string} serverHost - Server SSH host
 * @returns {Promise<object>} Server stats
 */
export async function getServerStats(serverHost) {
  // Placeholder: In production, SSH to server and run: wg show wg0
  return {
    connected: true,
    activePeers: 0,
    totalTx: 0,
    totalRx: 0,
    lastHandshake: null,
  };
}
