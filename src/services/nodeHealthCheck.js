// api/src/services/nodeHealthCheck.js
import { createConnection } from 'net';
import { getDatabase } from '../db/init.js';
import { isWireguardRunning, getSSHKeyPath } from '../utils/ssh.js';

const HEALTH_CHECK_INTERVAL = 30000; // 30 seconds
const CONNECTION_TIMEOUT = 5000; // 5 seconds

/**
 * Test TCP connection to a VPN node
 * @param {string} host - Node host/IP
 * @param {number} port - Node port
 * @returns {Promise<boolean>} - true if connected, false if failed
 */
function testNodeConnection(host, port) {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port, timeout: CONNECTION_TIMEOUT });

    let resolved = false;

    const cleanup = () => {
      if (!resolved) {
        resolved = true;
        socket.destroy();
      }
    };

    socket.on('connect', () => {
      cleanup();
      resolve(true);
    });

    socket.on('error', () => {
      cleanup();
      resolve(false);
    });

    socket.on('timeout', () => {
      cleanup();
      resolve(false);
    });

    // Fallback timeout
    setTimeout(() => {
      cleanup();
      resolve(false);
    }, CONNECTION_TIMEOUT + 1000);
  });
}

/**
 * Check health of all VPN nodes
 */
async function checkAllNodes() {
  const db = getDatabase();
  const now = new Date().toISOString();

  try {
    // Get all nodes that are NOT manually disabled
    const nodes = db.prepare(`
      SELECT id, name, host, port, protocol, wg_ssh_host, wg_ssh_port, wg_ssh_user
      FROM vpn_servers
      WHERE manually_disabled = 0
    `).all();

    if (nodes.length === 0) {
      console.log('[Health Check] No nodes to check (all manually disabled)');
      return;
    }

    console.log(`[Health Check] Testing ${nodes.length} nodes...`);

    // Test each node
    for (const node of nodes) {
      let isConnected = false;

      // WireGuard uses UDP - check via SSH if WireGuard service is active
      if (node.protocol === 'wireguard') {
        try {
          const sshHost = node.wg_ssh_host || node.host;
          const sshPort = node.wg_ssh_port || 22;
          const sshUser = node.wg_ssh_user || 'root';
          const keyPath = getSSHKeyPath();

          isConnected = await isWireguardRunning({
            host: sshHost,
            port: sshPort,
            user: sshUser,
            keyPath
          });
        } catch (error) {
          console.error(`[Health Check] WireGuard check failed for ${node.id}:`, error.message);
          isConnected = false;
        }
      } else {
        // Legacy TCP/UDP nodes - test TCP connection
        isConnected = await testNodeConnection(node.host, node.port);
      }

      // Update database
      db.prepare(`
        UPDATE vpn_servers
        SET is_active = ?, last_health_check = ?
        WHERE id = ?
      `).run(isConnected ? 1 : 0, now, node.id);

      const status = isConnected ? 'connected ✓' : 'disconnected ✗';
      const emoji = isConnected ? '🟢' : '🔴';
      const protocolInfo = node.protocol === 'wireguard' ? ' (WireGuard via SSH)' : '';
      console.log(`[Health Check] ${emoji} ${node.id} (${node.host}:${node.port}): ${status}${protocolInfo}`);
    }
  } catch (error) {
    console.error('[Health Check] Error:', error.message);
  }
}

/**
 * Start health check service
 */
export function startHealthCheck() {
  console.log(`✅ Health check service started (interval: ${HEALTH_CHECK_INTERVAL / 1000}s)`);

  // Run immediately on start
  checkAllNodes();

  // Then run every 30 seconds
  setInterval(checkAllNodes, HEALTH_CHECK_INTERVAL);
}

/**
 * Manual health check for a specific node (for admin panel "Test Connection" button)
 */
export async function checkNodeHealth(nodeId) {
  const db = getDatabase();
  const now = new Date().toISOString();

  try {
    const node = db.prepare(`
      SELECT id, name, host, port, protocol, wg_ssh_host, wg_ssh_port, wg_ssh_user
      FROM vpn_servers
      WHERE id = ?
    `).get(nodeId);

    if (!node) {
      return { ok: false, error: 'Node not found' };
    }

    let isConnected = false;

    // Check based on protocol type
    if (node.protocol === 'wireguard') {
      try {
        const sshHost = node.wg_ssh_host || node.host;
        const sshPort = node.wg_ssh_port || 22;
        const sshUser = node.wg_ssh_user || 'root';
        const keyPath = getSSHKeyPath();

        isConnected = await isWireguardRunning({
          host: sshHost,
          port: sshPort,
          user: sshUser,
          keyPath
        });
      } catch (error) {
        console.error(`[Manual Check] WireGuard check failed for ${node.id}:`, error.message);
        isConnected = false;
      }
    } else {
      // Legacy TCP/UDP nodes - test TCP connection
      isConnected = await testNodeConnection(node.host, node.port);
    }

    // Update database
    db.prepare(`
      UPDATE vpn_servers
      SET is_active = ?, last_health_check = ?
      WHERE id = ?
    `).run(isConnected ? 1 : 0, now, node.id);

    return {
      ok: true,
      connected: isConnected,
      host: node.host,
      port: node.port,
      protocol: node.protocol
    };
  } catch (error) {
    return {
      ok: false,
      error: error.message
    };
  }
}
