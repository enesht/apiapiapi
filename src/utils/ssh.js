// api/src/utils/ssh.js
// SSH utilities for remote WireGuard server peer management

import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * Execute SSH command on remote server
 * @param {object} params
 * @param {string} params.host - SSH host
 * @param {number} params.port - SSH port (default: 22)
 * @param {string} params.user - SSH username (default: 'root')
 * @param {string} params.command - Command to execute
 * @param {string} params.keyPath - Path to SSH private key (optional)
 * @returns {Promise<{stdout: string, stderr: string}>}
 */
export async function executeSSH({ host, port = 22, user = 'root', command, keyPath }) {
  const sshKeyArg = keyPath ? `-i ${keyPath}` : '';
  const sshCommand = `ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${sshKeyArg} -p ${port} ${user}@${host} "${command}"`;

  console.log(`[SSH] Executing on ${host}: ${command}`);

  try {
    const { stdout, stderr } = await execAsync(sshCommand, { timeout: 30000 });
    return { stdout: stdout.trim(), stderr: stderr.trim() };
  } catch (error) {
    console.error(`[SSH] Error executing command on ${host}:`, error.message);
    throw new Error(`SSH command failed: ${error.message}`);
  }
}

/**
 * Add WireGuard peer to remote server
 * @param {object} params
 * @param {string} params.host - Server SSH host
 * @param {number} params.port - SSH port
 * @param {string} params.user - SSH user
 * @param {string} params.clientPublicKey - Client's WireGuard public key
 * @param {string} params.allowedIP - Client's assigned IP (e.g., "10.8.0.42/32")
 * @param {string} params.keyPath - SSH private key path (optional)
 * @returns {Promise<void>}
 */
export async function addWireguardPeer({
  host,
  port = 22,
  user = 'root',
  clientPublicKey,
  allowedIP,
  keyPath
}) {
  // Ensure allowedIP has CIDR notation
  const ipWithCIDR = allowedIP.includes('/') ? allowedIP : `${allowedIP}/32`;

  const command = `wg set wg0 peer ${clientPublicKey} allowed-ips ${ipWithCIDR}`;

  try {
    await executeSSH({ host, port, user, command, keyPath });
    console.log(`✅ Added WireGuard peer ${clientPublicKey} (${ipWithCIDR}) to ${host}`);
  } catch (error) {
    console.error(`❌ Failed to add WireGuard peer to ${host}:`, error.message);
    throw new Error(`Failed to add peer: ${error.message}`);
  }
}

/**
 * Remove WireGuard peer from remote server
 * @param {object} params
 * @param {string} params.host - Server SSH host
 * @param {number} params.port - SSH port
 * @param {string} params.user - SSH user
 * @param {string} params.clientPublicKey - Client's WireGuard public key
 * @param {string} params.keyPath - SSH private key path (optional)
 * @returns {Promise<void>}
 */
export async function removeWireguardPeer({
  host,
  port = 22,
  user = 'root',
  clientPublicKey,
  keyPath
}) {
  const command = `wg set wg0 peer ${clientPublicKey} remove`;

  try {
    await executeSSH({ host, port, user, command, keyPath });
    console.log(`✅ Removed WireGuard peer ${clientPublicKey} from ${host}`);
  } catch (error) {
    console.error(`❌ Failed to remove WireGuard peer from ${host}:`, error.message);
    // Don't throw - peer might already be removed
  }
}

/**
 * Get WireGuard server status (wg show)
 * @param {object} params
 * @param {string} params.host - Server SSH host
 * @param {number} params.port - SSH port
 * @param {string} params.user - SSH user
 * @param {string} params.keyPath - SSH private key path (optional)
 * @returns {Promise<object>} Server status
 */
export async function getWireguardStatus({
  host,
  port = 22,
  user = 'root',
  keyPath
}) {
  const command = 'wg show wg0';

  try {
    const { stdout } = await executeSSH({ host, port, user, command, keyPath });
    return parseWireguardStatus(stdout);
  } catch (error) {
    console.error(`❌ Failed to get WireGuard status from ${host}:`, error.message);
    return {
      interface: 'wg0',
      publicKey: null,
      listeningPort: null,
      peers: [],
      error: error.message
    };
  }
}

/**
 * Parse `wg show wg0` output
 * @param {string} output - Command output
 * @returns {object} Parsed status
 */
function parseWireguardStatus(output) {
  const lines = output.split('\n');
  const status = {
    interface: 'wg0',
    publicKey: null,
    listeningPort: null,
    peers: []
  };

  let currentPeer = null;

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed.startsWith('public key:')) {
      status.publicKey = trimmed.split(':')[1].trim();
    } else if (trimmed.startsWith('listening port:')) {
      status.listeningPort = parseInt(trimmed.split(':')[1].trim());
    } else if (trimmed.startsWith('peer:')) {
      if (currentPeer) {
        status.peers.push(currentPeer);
      }
      currentPeer = {
        publicKey: trimmed.split(':')[1].trim(),
        endpoint: null,
        allowedIPs: [],
        latestHandshake: null,
        transfer: { rx: 0, tx: 0 }
      };
    } else if (currentPeer) {
      if (trimmed.startsWith('endpoint:')) {
        currentPeer.endpoint = trimmed.split(':').slice(1).join(':').trim();
      } else if (trimmed.startsWith('allowed ips:')) {
        currentPeer.allowedIPs = trimmed.split(':')[1].trim().split(',').map(ip => ip.trim());
      } else if (trimmed.startsWith('latest handshake:')) {
        currentPeer.latestHandshake = trimmed.split(':').slice(1).join(':').trim();
      } else if (trimmed.startsWith('transfer:')) {
        const parts = trimmed.split(':')[1].trim().split(' ');
        currentPeer.transfer = {
          rx: parts[0],
          tx: parts[2]
        };
      }
    }
  }

  if (currentPeer) {
    status.peers.push(currentPeer);
  }

  return status;
}

/**
 * Persist WireGuard configuration (save to /etc/wireguard/wg0.conf)
 * @param {object} params
 * @param {string} params.host - Server SSH host
 * @param {number} params.port - SSH port
 * @param {string} params.user - SSH user
 * @param {string} params.keyPath - SSH private key path (optional)
 * @returns {Promise<void>}
 */
export async function saveWireguardConfig({
  host,
  port = 22,
  user = 'root',
  keyPath
}) {
  const command = 'wg-quick save wg0';

  try {
    await executeSSH({ host, port, user, command, keyPath });
    console.log(`✅ Saved WireGuard config on ${host}`);
  } catch (error) {
    console.error(`❌ Failed to save WireGuard config on ${host}:`, error.message);
    // Non-critical error, don't throw
  }
}

/**
 * Check if WireGuard is running on server
 * @param {object} params
 * @param {string} params.host - Server SSH host
 * @param {number} params.port - SSH port
 * @param {string} params.user - SSH user
 * @param {string} params.keyPath - SSH private key path (optional)
 * @returns {Promise<boolean>} True if running
 */
export async function isWireguardRunning({
  host,
  port = 22,
  user = 'root',
  keyPath
}) {
  const command = 'systemctl is-active wg-quick@wg0';

  try {
    const { stdout } = await executeSSH({ host, port, user, command, keyPath });
    return stdout.trim() === 'active';
  } catch (error) {
    return false;
  }
}

/**
 * Get SSH key path from environment or default location
 * @returns {string|null} SSH key path
 */
export function getSSHKeyPath() {
  // Priority: env var > default location
  return process.env.WG_SSH_KEY_PATH || process.env.SSH_KEY_PATH || null;
}
