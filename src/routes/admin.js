import express from 'express';
import { getDatabase } from '../db/init.js';
import { getClientIp, logAuditEvent } from '../utils/ip.js';

const router = express.Router();

/**
 * Simple admin authentication middleware
 * In production, use JWT or session-based auth
 */
function requireAdmin(req, res, next) {
  const adminKey = req.headers['x-admin-key'];

  if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Invalid admin credentials'
    });
  }

  next();
}

/**
 * GET /admin/nodes
 * List all VPN nodes
 */
router.get('/nodes', requireAdmin, (req, res) => {
  try {
    const db = getDatabase();

    const nodes = db.prepare(`
      SELECT * FROM vpn_servers
      ORDER BY is_premium DESC, created_at ASC
    `).all();

    res.json({
      ok: true,
      nodes,
      count: nodes.length
    });
  } catch (error) {
    console.error('[Admin] List nodes error:', error);
    res.status(500).json({
      error: 'Failed to list nodes',
      message: error.message
    });
  }
});

/**
 * POST /admin/nodes
 * Add a new VPN node
 */
router.post('/nodes', requireAdmin, (req, res) => {
  try {
    const {
      id,
      name,
      location,
      country_code,
      host,
      port = 51820,
      protocol = 'wireguard',
      capacity = 100,
      is_premium = 0,
      wg_public_key,
      wg_endpoint,
      wg_ssh_host,
      wg_ssh_port = 22,
      wg_ssh_user = 'root'
    } = req.body;

    // DEBUG: Log received WireGuard fields
    console.log('[Admin] POST /nodes - WireGuard fields:', {
      wg_public_key,
      wg_endpoint,
      wg_ssh_host,
      wg_ssh_port,
      wg_ssh_user
    });

    if (!id || !name || !location || !country_code || !host) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['id', 'name', 'location', 'country_code', 'host']
      });
    }

    const db = getDatabase();
    const now = new Date().toISOString();
    const clientIp = getClientIp(req);

    // Check if node ID already exists
    const existing = db.prepare(`
      SELECT id FROM vpn_servers WHERE id = ?
    `).get(id);

    if (existing) {
      return res.status(409).json({
        error: 'Node already exists',
        message: `Node with ID '${id}' already exists`
      });
    }

    // Insert new node
    db.prepare(`
      INSERT INTO vpn_servers (
        id, name, location, country_code, host, port,
        protocol, capacity, is_active, is_premium,
        wg_public_key, wg_endpoint, wg_ssh_host, wg_ssh_port, wg_ssh_user,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      name,
      location,
      country_code,
      host,
      port,
      protocol,
      capacity,
      1, // is_active
      is_premium,
      wg_public_key,
      wg_endpoint,
      wg_ssh_host,
      wg_ssh_port,
      wg_ssh_user,
      now
    );

    // Log audit event
    logAuditEvent(db, 'admin', 'add_vpn_node', clientIp, {
      node_id: id,
      host
    });

    console.log(`[Admin] Node added: ${id} (${host}:${port})`);

    res.json({
      ok: true,
      message: 'Node added successfully',
      node_id: id
    });
  } catch (error) {
    console.error('[Admin] Add node error:', error);
    res.status(500).json({
      error: 'Failed to add node',
      message: error.message
    });
  }
});

/**
 * PUT /admin/nodes/:id
 * Update a VPN node
 */
router.put('/nodes/:id', requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    const db = getDatabase();
    const clientIp = getClientIp(req);

    // Check if node exists
    const node = db.prepare(`
      SELECT * FROM vpn_servers WHERE id = ?
    `).get(id);

    if (!node) {
      return res.status(404).json({
        error: 'Node not found',
        message: `Node with ID '${id}' does not exist`
      });
    }

    // Build update query dynamically
    const allowedFields = [
      'name', 'location', 'country_code', 'host', 'port',
      'protocol', 'capacity', 'is_active', 'is_premium', 'manually_disabled',
      'wg_public_key', 'wg_endpoint', 'wg_ssh_host', 'wg_ssh_port', 'wg_ssh_user'
    ];

    const updateFields = [];
    const updateValues = [];

    for (const field of allowedFields) {
      if (updates[field] !== undefined) {
        updateFields.push(`${field} = ?`);
        updateValues.push(updates[field]);
      }
    }

    if (updateFields.length === 0) {
      return res.status(400).json({
        error: 'No valid fields to update'
      });
    }

    // Add updated_at
    updateFields.push('updated_at = ?');
    updateValues.push(new Date().toISOString());

    // Add node ID for WHERE clause
    updateValues.push(id);

    // Execute update
    db.prepare(`
      UPDATE vpn_servers
      SET ${updateFields.join(', ')}
      WHERE id = ?
    `).run(...updateValues);

    // Log audit event
    logAuditEvent(db, 'admin', 'update_vpn_node', clientIp, {
      node_id: id,
      updates
    });

    console.log(`[Admin] Node updated: ${id}`);

    res.json({
      ok: true,
      message: 'Node updated successfully',
      node_id: id
    });
  } catch (error) {
    console.error('[Admin] Update node error:', error);
    res.status(500).json({
      error: 'Failed to update node',
      message: error.message
    });
  }
});

/**
 * DELETE /admin/nodes/:id
 * Delete a VPN node
 */
router.delete('/nodes/:id', requireAdmin, (req, res) => {
  try {
    const { id } = req.params;
    const db = getDatabase();
    const clientIp = getClientIp(req);

    // Check if node exists
    const node = db.prepare(`
      SELECT * FROM vpn_servers WHERE id = ?
    `).get(id);

    if (!node) {
      return res.status(404).json({
        error: 'Node not found',
        message: `Node with ID '${id}' does not exist`
      });
    }

    // Delete node
    db.prepare(`
      DELETE FROM vpn_servers WHERE id = ?
    `).run(id);

    // Log audit event
    logAuditEvent(db, 'admin', 'delete_vpn_node', clientIp, {
      node_id: id,
      host: node.host
    });

    console.log(`[Admin] Node deleted: ${id}`);

    res.json({
      ok: true,
      message: 'Node deleted successfully',
      node_id: id
    });
  } catch (error) {
    console.error('[Admin] Delete node error:', error);
    res.status(500).json({
      error: 'Failed to delete node',
      message: error.message
    });
  }
});

/**
 * POST /admin/nodes/:id/health
 * Update node health status (called by node health check script)
 */
router.post('/nodes/:id/health', (req, res) => {
  try {
    const { id } = req.params;
    const { status, load, latency_ms } = req.body;

    const db = getDatabase();
    const now = new Date().toISOString();

    // Update node status
    db.prepare(`
      UPDATE vpn_servers
      SET
        is_active = ?,
        current_load = ?,
        updated_at = ?
      WHERE id = ?
    `).run(
      status === 'online' ? 1 : 0,
      load || 0,
      now,
      id
    );

    console.log(`[Node Health] ${id}: ${status} (load: ${load || 0}%)`);

    res.json({ ok: true, message: 'Health status updated' });
  } catch (error) {
    console.error('[Node Health] Update error:', error);
    res.status(500).json({
      error: 'Failed to update health status',
      message: error.message
    });
  }
});

/**
 * GET /admin/stats
 * Get system statistics
 */
router.get('/stats', requireAdmin, (req, res) => {
  try {
    const db = getDatabase();

    // Total users
    const totalUsers = db.prepare(`
      SELECT COUNT(DISTINCT wallet) as count FROM subscriptions
    `).get();

    // Active subscriptions
    const activeSubscriptions = db.prepare(`
      SELECT COUNT(*) as count FROM subscriptions
      WHERE is_active = 1 AND datetime(expires_at) > datetime('now')
    `).get();

    // Total revenue (USD)
    const totalRevenue = db.prepare(`
      SELECT SUM(amount_usd) as total FROM payments
      WHERE status = 'confirmed'
    `).get();

    // Active VPN sessions
    const activeSessions = db.prepare(`
      SELECT COUNT(*) as count FROM vpn_sessions
      WHERE status = 'active'
    `).get();

    // Total nodes
    const totalNodes = db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active
      FROM vpn_servers
    `).get();

    // Recent payments
    const recentPayments = db.prepare(`
      SELECT
        wallet, plan, amount_usd, amount_sol, status, created_at
      FROM payments
      ORDER BY created_at DESC
      LIMIT 10
    `).all();

    res.json({
      ok: true,
      stats: {
        users: {
          total: totalUsers.count,
        },
        subscriptions: {
          active: activeSubscriptions.count,
        },
        revenue: {
          total_usd: totalRevenue.total || 0,
        },
        vpn: {
          active_sessions: activeSessions.count,
          total_nodes: totalNodes.total,
          active_nodes: totalNodes.active,
        },
      },
      recent_payments: recentPayments,
    });
  } catch (error) {
    console.error('[Admin] Stats error:', error);
    res.status(500).json({
      error: 'Failed to get stats',
      message: error.message
    });
  }
});

/**
 * GET /admin/users
 * List all users with subscription info
 */
router.get('/users', requireAdmin, (req, res) => {
  try {
    const db = getDatabase();

    const users = db.prepare(`
      SELECT
        wallet,
        COUNT(DISTINCT id) as nft_count,
        SUM(price_usd) as total_spent,
        MAX(created_at) as last_purchase,
        GROUP_CONCAT(DISTINCT plan) as plans
      FROM subscriptions
      GROUP BY wallet
      ORDER BY last_purchase DESC
    `).all();

    res.json({
      ok: true,
      users,
      count: users.length
    });
  } catch (error) {
    console.error('[Admin] List users error:', error);
    res.status(500).json({
      error: 'Failed to list users',
      message: error.message
    });
  }
});

/**
 * GET /admin/users/:wallet
 * Get user details
 */
router.get('/users/:wallet', requireAdmin, (req, res) => {
  try {
    const { wallet } = req.params;
    const db = getDatabase();

    // Get subscriptions
    const subscriptions = db.prepare(`
      SELECT * FROM subscriptions
      WHERE wallet = ?
      ORDER BY created_at DESC
    `).all(wallet);

    // Get payments
    const payments = db.prepare(`
      SELECT * FROM payments
      WHERE wallet = ?
      ORDER BY created_at DESC
    `).all(wallet);

    // Get VPN sessions
    const sessions = db.prepare(`
      SELECT * FROM vpn_sessions
      WHERE wallet = ?
      ORDER BY connected_at DESC
      LIMIT 20
    `).all(wallet);

    res.json({
      ok: true,
      wallet,
      subscriptions,
      payments,
      sessions
    });
  } catch (error) {
    console.error('[Admin] Get user error:', error);
    res.status(500).json({
      error: 'Failed to get user details',
      message: error.message
    });
  }
});

/**
 * GET /admin/nfts
 * List all NFTs
 */
router.get('/nfts', requireAdmin, (req, res) => {
  try {
    const db = getDatabase();

    const nfts = db.prepare(`
      SELECT
        s.id,
        s.wallet,
        s.plan,
        s.nft_mint,
        s.created_at,
        s.expires_at,
        s.is_active,
        s.price_usd,
        s.price_sol,
        n.name,
        n.symbol,
        n.description
      FROM subscriptions s
      LEFT JOIN nft_metadata n ON s.nft_mint = n.mint_address
      WHERE s.nft_mint IS NOT NULL
      ORDER BY s.created_at DESC
    `).all();

    res.json({
      ok: true,
      nfts,
      count: nfts.length
    });
  } catch (error) {
    console.error('[Admin] List NFTs error:', error);
    res.status(500).json({
      error: 'Failed to list NFTs',
      message: error.message
    });
  }
});

/**
 * GET /admin/payments
 * List all payments
 */
router.get('/payments', requireAdmin, (req, res) => {
  try {
    const db = getDatabase();
    const { status, plan } = req.query;

    let query = 'SELECT * FROM payments WHERE 1=1';
    const params = [];

    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }

    if (plan) {
      query += ' AND plan = ?';
      params.push(plan);
    }

    query += ' ORDER BY created_at DESC LIMIT 100';

    const payments = db.prepare(query).all(...params);

    // Calculate total revenue
    const revenue = db.prepare(`
      SELECT
        SUM(amount_usd) as total_usd,
        SUM(amount_sol) as total_sol,
        COUNT(*) as count
      FROM payments
      WHERE status = 'confirmed'
    `).get();

    res.json({
      ok: true,
      payments,
      count: payments.length,
      revenue
    });
  } catch (error) {
    console.error('[Admin] List payments error:', error);
    res.status(500).json({
      error: 'Failed to list payments',
      message: error.message
    });
  }
});

/**
 * GET /admin/logs
 * List audit logs
 */
router.get('/logs', requireAdmin, (req, res) => {
  try {
    const db = getDatabase();
    const { event_type, wallet, ip } = req.query;

    let query = 'SELECT * FROM audit_logs WHERE 1=1';
    const params = [];

    if (event_type) {
      query += ' AND event_type = ?';
      params.push(event_type);
    }

    if (wallet) {
      query += ' AND wallet LIKE ?';
      params.push(`%${wallet}%`);
    }

    if (ip) {
      query += ' AND ip_address LIKE ?';
      params.push(`%${ip}%`);
    }

    query += ' ORDER BY created_at DESC LIMIT 100';

    const logs = db.prepare(query).all(...params);

    // Get event types for filter
    const eventTypes = db.prepare(`
      SELECT DISTINCT event_type FROM audit_logs
      ORDER BY event_type
    `).all();

    res.json({
      ok: true,
      logs,
      count: logs.length,
      event_types: eventTypes.map(e => e.event_type)
    });
  } catch (error) {
    console.error('[Admin] List logs error:', error);
    res.status(500).json({
      error: 'Failed to list logs',
      message: error.message
    });
  }
});

export default router;
