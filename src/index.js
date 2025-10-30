import 'dotenv/config';
import express from 'express';
import rateLimit from 'express-rate-limit';
import { v4 as uuidv4 } from 'uuid';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { initDatabase, getDatabase } from './db/init.js';

// Get package.json version
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'));
const API_VERSION = packageJson.version;
import { verifySignature } from './utils/auth.js';
import { getSubscriptionPlans, usdToSol } from './utils/pricing.js';
import {
  verifyPaymentTransaction,
  mintAccessNFT,
  getWalletNFTs,
  checkWalletAccess,
} from './utils/solana.js';
import { ipTrackingMiddleware, getClientIp, logAuditEvent } from './utils/ip.js';
import { generateToken, verifyToken, authenticateToken } from './utils/jwt.js';
import adminRoutes from './routes/admin.js';
import { startHealthCheck } from './services/nodeHealthCheck.js';
import {
  assignClientIP,
  parseServerInfo,
  validatePublicKey
} from './utils/wireguard.js';
import {
  addWireguardPeer,
  removeWireguardPeer,
  getSSHKeyPath
} from './utils/ssh.js';

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy - CloudFront/Load Balancer için gerekli
app.set('trust proxy', true);

// CORS Configuration - ALL settings from .env
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || '';
const ALLOW_CLOUDFRONT = process.env.ALLOW_CLOUDFRONT === 'true';

if (!ALLOWED_ORIGINS) {
  console.warn('⚠️  WARNING: ALLOWED_ORIGINS not set in .env - CORS will block all requests!');
}

const allowedOrigins = ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(o => o);

console.log('🔒 CORS Configuration:');
console.log('   Allowed Origins:', allowedOrigins);
console.log('   Allow CloudFront:', ALLOW_CLOUDFRONT);

// Custom CORS middleware to avoid duplicate headers
app.use((req, res, next) => {
  const origin = req.headers.origin;

  console.log('[CORS] Incoming origin:', origin);

  // Allow requests with no origin (like mobile apps or curl requests)
  if (!origin) {
    console.log('[CORS] ✅ No origin header - allowing request');
    return next();
  }

  // Check if origin is in allowed list
  const isAllowed = allowedOrigins.indexOf(origin) !== -1;

  // Check if CloudFront domains are allowed (*.cloudfront.net)
  const isCloudFront = ALLOW_CLOUDFRONT && origin.endsWith('.cloudfront.net');

  if (isAllowed || isCloudFront) {
    console.log('[CORS] ✅ Origin allowed:', origin);

    // Set CORS headers manually (only if not already set)
    if (!res.getHeader('Access-Control-Allow-Origin')) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Token, X-Admin-Key');
    }

    // Handle preflight
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }

    next();
  } else {
    console.log('[CORS] ❌ Origin NOT allowed:', origin);
    console.log('[CORS] Allowed origins:', allowedOrigins);
    console.log('[CORS] CloudFront allowed:', ALLOW_CLOUDFRONT);
    res.status(403).json({
      ok: false,
      error: 'Not allowed by CORS'
    });
  }
});

// Body parser with size limit
app.use(express.json({ limit: '100kb' }));
app.use(ipTrackingMiddleware);

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 requests per window
  message: { ok: false, error: 'Too many authentication attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const paymentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 payment attempts per hour
  message: { ok: false, error: 'Too many payment attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const nftLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 NFT mints per hour
  message: { ok: false, error: 'Too many NFT minting attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const vpnLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 30, // 30 VPN requests per 5 minutes
  message: { ok: false, error: 'Too many VPN requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Initialize database
initDatabase();

// Mount admin routes
app.use('/admin', adminRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    version: API_VERSION,
    timestamp: new Date().toISOString(),
    healthcheck: 'ssh-wireguard-enabled'
  });
});

// ============================================================================
// AUTH ROUTES
// ============================================================================

/**
 * POST /auth/login
 * Verify wallet signature
 */
app.post('/auth/login', authLimiter, (req, res) => {
  try {
    const { walletAddress, message, signature } = req.body;

    if (!walletAddress || !message || !signature) {
      return res.status(400).json({
        ok: false,
        error: 'Missing required fields: walletAddress, message, signature',
      });
    }

    const isValid = verifySignature(message, signature, walletAddress);

    if (!isValid) {
      return res.status(401).json({
        ok: false,
        error: 'Invalid signature',
      });
    }

    res.json({
      ok: true,
      wallet: walletAddress,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

/**
 * POST /auth/create-session
 * Create JWT session after wallet signature verification
 * Used by web app to generate token for Electron app
 */
app.post('/auth/create-session', authLimiter, async (req, res) => {
  try {
    // ✅ YENİ: Request body'yi logla
    console.log('[/auth/create-session] Incoming request:', {
      walletAddress: req.body.walletAddress,
      message: req.body.message ? 'present' : 'missing',
      signature: req.body.signature ? 'present' : 'missing',
      headers: {
        'content-type': req.headers['content-type'],
        'accept': req.headers['accept'],
        'origin': req.headers['origin']
      }
    });

    const { walletAddress, message, signature } = req.body;

    if (!walletAddress || !message || !signature) {
      console.log('[/auth/create-session] Missing fields:', {
        walletAddress, hasMessage: !!message, hasSignature: !!signature
      });
      return res.status(400).json({
        ok: false,
        error: 'Missing required fields: walletAddress, message, signature',
      });
    }

    // Verify signature
    console.log('[/auth/create-session] Verifying signature for wallet:', walletAddress);
    const isValid = verifySignature(message, signature, walletAddress);

    if (!isValid) {
      console.log('[/auth/create-session] Invalid signature for wallet:', walletAddress);
      return res.status(401).json({
        ok: false,
        error: 'Invalid signature',
      });
    }

    console.log('[/auth/create-session] Signature verified, fetching NFTs...');

    // Get user's NFTs (with fallback to empty array on error)
    let nfts = [];
    try {
      nfts = await getWalletNFTs(walletAddress);
      console.log('[/auth/create-session] NFTs fetched:', nfts.length);
    } catch (nftError) {
      console.error('[/auth/create-session] Error fetching NFTs, continuing with empty array:', nftError.message);
      // Continue with empty NFT array - user can still authenticate
    }

    // Generate JWT token
    const token = generateToken(walletAddress, nfts);
    console.log('[/auth/create-session] Token generated successfully');

    // Log audit event
    const db = getDatabase();
    const clientIp = getClientIp(req);
    logAuditEvent(db, walletAddress, 'session_created', clientIp, {
      nft_count: nfts.length,
      source: 'web',
    });

    console.log('[/auth/create-session] Success! Returning response');
    res.json({
      ok: true,
      token,
      wallet: walletAddress,
      nfts_count: nfts.length,
    });
  } catch (error) {
    // ✅ YENİ: Detaylı error logging ve JSON response
    console.error('[/auth/create-session] ERROR:', {
      message: error.message,
      stack: error.stack,
      name: error.name
    });

    // ✅ YENİ: Her zaman JSON döndür (HTML değil)
    res.status(500).json({
      ok: false,
      error: 'internal',
      detail: error.message
    });
  }
});

/**
 * POST /auth/verify-session
 * Verify JWT token and return user data
 * Used by Electron app after receiving token from web
 */
app.post('/auth/verify-session', authLimiter, (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        ok: false,
        error: 'Missing token',
      });
    }

    // Verify and decode token
    const decoded = verifyToken(token);

    res.json({
      ok: true,
      wallet: decoded.wallet,
      nfts: decoded.nfts,
      issued_at: new Date(decoded.iat * 1000).toISOString(),
    });
  } catch (error) {
    console.error('Verify session error:', error);
    res.status(401).json({
      ok: false,
      error: error.message,
    });
  }
});

// ============================================================================
// NFT ROUTES
// ============================================================================

/**
 * GET /nft/owned
 * Check which NFTs a wallet owns
 */
app.get('/nft/owned', async (req, res) => {
  try {
    const { wallet } = req.query;

    if (!wallet) {
      return res.status(400).json({
        ok: false,
        error: 'Missing wallet parameter',
      });
    }

    const nfts = await getWalletNFTs(wallet);
    const hasAccessNft = nfts.length > 0;

    res.json({
      ok: true,
      hasAccessNft,
      nfts: nfts.map(nft => ({
        mint: nft.mint,
        name: nft.name,
        symbol: nft.symbol,
        metadata_uri: nft.uri,
        attributes: nft.json?.attributes || [],
      })),
    });
  } catch (error) {
    console.error('Error checking NFT ownership:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

/**
 * POST /nft/mint
 * Mint Access NFT (requires paid status)
 */
app.post('/nft/mint', nftLimiter, async (req, res) => {
  try {
    const { wallet, planId, reference } = req.body;

    if (!wallet || !planId || !reference) {
      return res.status(400).json({
        ok: false,
        error: 'Missing required fields: wallet, planId, reference',
      });
    }

    // Check if payment exists and is paid
    const db = getDatabase();
    const payment = db
      .prepare('SELECT * FROM payments WHERE id = ? AND wallet = ?')
      .get(reference, wallet);

    if (!payment) {
      return res.status(404).json({
        ok: false,
        error: 'Payment not found',
      });
    }

    if (payment.status !== 'confirmed' && payment.status !== 'paid') {
      return res.status(400).json({
        ok: false,
        error: 'Payment not confirmed',
      });
    }

    // Check if already minted for this payment (by tx_signature)
    const existingSub = db
      .prepare('SELECT * FROM subscriptions WHERE wallet = ? AND tx_signature = ?')
      .get(wallet, payment.tx_signature);

    if (existingSub && existingSub.nft_mint) {
      console.log('NFT already minted, returning existing NFT:', existingSub.nft_mint);
      return res.json({
        ok: true,
        nftMint: existingSub.nft_mint,
        subscription_id: existingSub.id,
        akca_ref_id: existingSub.id,
        expires_at: existingSub.expires_at,
        message: 'NFT was already minted for this payment',
      });
    }

    // Get plan details
    const plans = await getSubscriptionPlans();
    const plan = plans.plans.find(p => p.id === planId);

    if (!plan) {
      return res.status(400).json({
        ok: false,
        error: 'Invalid plan ID',
      });
    }

    // Get client IP
    const clientIp = getClientIp(req);

    // Check if there's a pending subscription for this payment
    let subscriptionId;
    const pendingSub = db.prepare(`
      SELECT * FROM subscriptions
      WHERE wallet = ? AND tx_signature = ? AND status = 'pending'
    `).get(wallet, payment.tx_signature);

    if (pendingSub) {
      // Reuse existing pending subscription
      subscriptionId = pendingSub.id;
      console.log(`[NFT Mint] Reusing existing pending subscription: ${subscriptionId}`);
    } else {
      // Create new subscription record
      subscriptionId = uuidv4();
      const now = new Date().toISOString();
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

      db.prepare(`
        INSERT INTO subscriptions (id, wallet, plan, status, created_at, expires_at, price_usd, price_sol, tx_signature, mint_ip_address, device_limit)
        VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)
      `).run(
        subscriptionId,
        wallet,
        planId,
        now,
        expiresAt,
        plan.price_usd,
        plan.price_sol,
        payment.tx_signature,
        clientIp,
        plan.device_limit
      );
    }

    // Mint NFT
    console.log(`Minting NFT for wallet ${wallet}, plan ${planId}...`);
    const nftResult = await mintAccessNFT(
      wallet,
      planId,
      plan.price_usd,
      plan.price_sol,
      clientIp,
      subscriptionId
    );

    // Update subscription with NFT mint address
    db.prepare(`
      UPDATE subscriptions
      SET nft_mint = ?, status = 'active'
      WHERE id = ?
    `).run(nftResult.mint, subscriptionId);

    // Log audit event
    logAuditEvent(db, wallet, 'nft_minted', clientIp, {
      subscription_id: subscriptionId,
      nft_mint: nftResult.mint,
      plan: planId
    });

    res.json({
      ok: true,
      nftMint: nftResult.mint,
      subscription_id: nftResult.subscription_id,
      akca_ref_id: nftResult.akca_ref_id,
      expires_at: nftResult.expires_at,
      nft_details: nftResult.nft_details
    });
  } catch (error) {
    console.error('Error minting NFT:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

// ============================================================================
// PRICING ROUTES
// ============================================================================

/**
 * GET /pricing
 * Get subscription plans with SOL conversion
 */
app.get('/pricing', async (req, res) => {
  try {
    const pricing = await getSubscriptionPlans();
    res.json({
      ok: true,
      ...pricing,
    });
  } catch (error) {
    console.error('Error fetching pricing:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

// ============================================================================
// PURCHASE ROUTES
// ============================================================================

/**
 * POST /purchase/init
 * Initialize a payment request
 */
app.post('/purchase/init', paymentLimiter, async (req, res) => {
  try {
    const { wallet, planId } = req.body;

    if (!wallet || !planId) {
      return res.status(400).json({
        ok: false,
        error: 'Missing required fields: wallet, planId',
      });
    }

    // Get plan details
    const pricing = await getSubscriptionPlans();
    const plan = pricing.plans.find(p => p.id === planId);

    if (!plan) {
      return res.status(400).json({
        ok: false,
        error: 'Invalid plan ID',
      });
    }

    // Create payment record
    const reference = uuidv4();
    const now = new Date().toISOString();
    const clientIp = getClientIp(req);

    const db = getDatabase();
    db.prepare(`
      INSERT INTO payments (id, wallet, plan, amount_sol, amount_usdt, amount_usd, status, ip_address, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
    `).run(reference, wallet, planId, plan.price_sol, 0, plan.price_usd, clientIp, now);

    // Log audit event
    logAuditEvent(db, wallet, 'payment_init', clientIp, { plan: planId, amount: plan.price_usd });

    res.json({
      ok: true,
      reference,
      to: process.env.AKCA_TREASURY_PUBLIC_KEY,
      amount_sol: plan.price_sol,
      total_sol: plan.total_sol,
      mint_fee_sol: plan.mint_fee_sol,
      plan,
    });
  } catch (error) {
    console.error('Error initializing purchase:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

/**
 * POST /purchase/confirm
 * Confirm payment transaction on-chain
 */
app.post('/purchase/confirm', paymentLimiter, async (req, res) => {
  try {
    const { wallet, reference, txSignature } = req.body;

    if (!wallet || !reference || !txSignature) {
      return res.status(400).json({
        ok: false,
        error: 'Missing required fields: wallet, reference, txSignature',
      });
    }

    // Get payment record
    const db = getDatabase();
    const payment = db
      .prepare('SELECT * FROM payments WHERE id = ? AND wallet = ?')
      .get(reference, wallet);

    if (!payment) {
      return res.status(404).json({
        ok: false,
        error: 'Payment not found',
      });
    }

    if (payment.status === 'paid') {
      return res.json({
        ok: true,
        status: 'already_paid',
        message: 'Payment already confirmed',
      });
    }

    // Verify transaction on-chain
    console.log(`Verifying transaction ${txSignature}...`);
    const verification = await verifyPaymentTransaction(
      txSignature,
      wallet,
      process.env.AKCA_TREASURY_PUBLIC_KEY,
      payment.amount_sol
    );

    if (!verification.valid) {
      return res.status(400).json({
        ok: false,
        error: verification.error || 'Transaction verification failed',
      });
    }

    // Update payment status
    const confirmedAt = new Date().toISOString();
    db.prepare(`
      UPDATE payments
      SET status = 'confirmed', tx_signature = ?, confirmed_at = ?
      WHERE id = ?
    `).run(txSignature, confirmedAt, reference);

    // Log audit event
    const clientIp = getClientIp(req);
    logAuditEvent(db, wallet, 'payment_confirmed', clientIp, {
      reference,
      tx_signature: txSignature,
      amount_sol: verification.amount
    });

    res.json({
      ok: true,
      status: 'confirmed',
      reference,
      tx_signature: txSignature,
      verified_amount: verification.amount,
    });
  } catch (error) {
    console.error('Error confirming payment:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

// ============================================================================
// ACCESS CONTROL ROUTES
// ============================================================================

/**
 * GET /access/check
 * Check if wallet has access
 */
app.get('/access/check', async (req, res) => {
  try {
    const { wallet } = req.query;

    if (!wallet) {
      return res.status(400).json({
        ok: false,
        error: 'Missing wallet parameter',
      });
    }

    // Check database first
    const db = getDatabase();
    const sub = db
      .prepare(`
        SELECT * FROM subscriptions
        WHERE wallet = ?
        ORDER BY created_at DESC
        LIMIT 1
      `)
      .get(wallet);

    if (!sub) {
      return res.json({
        ok: true,
        authorized: false,
        message: 'No active subscription found',
      });
    }

    // Check expiration
    const now = new Date();
    const expiresAt = new Date(sub.expires_at);

    if (expiresAt <= now) {
      return res.json({
        ok: true,
        authorized: false,
        message: 'Subscription expired',
        expires_at: sub.expires_at,
      });
    }

    res.json({
      ok: true,
      authorized: true,
      active_plan: sub.plan,
      nft_mint: sub.nft_mint,
      expires_at: sub.expires_at,
    });
  } catch (error) {
    console.error('Error checking access:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

/**
 * GET /vpn/nodes
 * Get available VPN nodes based on user's plan
 */
app.get('/vpn/nodes', (req, res) => {
  try {
    const { wallet } = req.query;

    if (!wallet) {
      return res.status(400).json({
        ok: false,
        error: 'Missing wallet parameter',
      });
    }

    const db = getDatabase();

    // Get user's subscription
    const sub = db.prepare(`
      SELECT * FROM subscriptions
      WHERE wallet = ? AND is_active = 1
      ORDER BY created_at DESC
      LIMIT 1
    `).get(wallet);

    let nodes;
    if (!sub) {
      // No subscription, return basic nodes only
      nodes = db.prepare(`
        SELECT id, name, location, country_code, host, port, protocol
        FROM vpn_servers
        WHERE is_active = 1 AND is_premium = 0
        ORDER BY current_load ASC
      `).all();
    } else if (sub.plan === 'pro') {
      // Pro plan gets all nodes
      nodes = db.prepare(`
        SELECT id, name, location, country_code, host, port, protocol, is_premium
        FROM vpn_servers
        WHERE is_active = 1
        ORDER BY is_premium DESC, current_load ASC
      `).all();
    } else {
      // Standard plan gets basic nodes only
      nodes = db.prepare(`
        SELECT id, name, location, country_code, host, port, protocol
        FROM vpn_servers
        WHERE is_active = 1 AND is_premium = 0
        ORDER BY current_load ASC
      `).all();
    }

    res.json({
      ok: true,
      nodes,
      user_plan: sub?.plan || 'none',
    });
  } catch (error) {
    console.error('Error getting VPN nodes:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

/**
 * POST /vpn/connect
 * Create WireGuard VPN session with config generation
 */
app.post('/vpn/connect', vpnLimiter, async (req, res) => {
  try {
    const { wallet, node_id } = req.body;

    if (!wallet || !node_id) {
      return res.status(400).json({
        ok: false,
        error: 'Missing required fields: wallet, node_id',
      });
    }

    const db = getDatabase();
    const clientIp = getClientIp(req);

    // Check if user has active subscription
    const sub = db.prepare(`
      SELECT * FROM subscriptions
      WHERE wallet = ? AND is_active = 1 AND datetime(expires_at) > datetime('now')
      ORDER BY created_at DESC
      LIMIT 1
    `).get(wallet);

    if (!sub) {
      return res.status(403).json({
        ok: false,
        error: 'No active subscription found',
      });
    }

    // Clean up stale sessions (older than 5 minutes without heartbeat)
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    db.prepare(`
      UPDATE vpn_sessions
      SET status = 'disconnected', disconnected_at = ?
      WHERE wallet = ? AND status = 'active' AND connected_at < ?
    `).run(new Date().toISOString(), wallet, fiveMinutesAgo);

    // Check device limit
    const activeSessions = db.prepare(`
      SELECT COUNT(*) as count FROM vpn_sessions
      WHERE wallet = ? AND status = 'active' AND disconnected_at IS NULL
    `).get(wallet);

    if (activeSessions.count >= sub.device_limit) {
      return res.status(429).json({
        ok: false,
        error: `Device limit reached (${sub.device_limit} devices)`,
        device_limit: sub.device_limit,
        active_sessions: activeSessions.count
      });
    }

    // Get node details
    const node = db.prepare(`
      SELECT * FROM vpn_servers WHERE id = ? AND is_active = 1
    `).get(node_id);

    if (!node) {
      return res.status(404).json({
        ok: false,
        error: 'Node not found or inactive',
      });
    }

    // Check if user's plan allows this node
    if (node.is_premium === 1 && sub.plan !== 'pro') {
      return res.status(403).json({
        ok: false,
        error: 'Premium node requires Pro plan',
      });
    }

    // ===== WireGuard Setup =====

    // 1. Get client public key from request (client generates keys locally)
    const { client_public_key } = req.body;

    if (!client_public_key) {
      return res.status(400).json({
        ok: false,
        error: 'Missing client_public_key. Client must generate WireGuard keys locally.'
      });
    }

    // Validate public key format
    if (!validatePublicKey(client_public_key)) {
      return res.status(400).json({
        ok: false,
        error: 'Invalid WireGuard public key format'
      });
    }

    // 2. Assign client IP from available pool
    const clientVpnIP = await assignClientIP(db, wallet);

    // 3. Parse server info
    const serverInfo = parseServerInfo(node);

    // 4. Add peer to WireGuard server via SSH
    const sshKeyPath = getSSHKeyPath();
    try {
      await addWireguardPeer({
        host: serverInfo.sshHost,
        port: serverInfo.sshPort,
        user: serverInfo.sshUser,
        clientPublicKey: client_public_key,
        allowedIP: clientVpnIP,
        keyPath: sshKeyPath
      });
      console.log(`✅ Added WireGuard peer ${client_public_key} to ${serverInfo.sshHost}`);
    } catch (sshError) {
      console.error('⚠️  Failed to add peer to server:', sshError.message);
      console.error('⚠️  Client will receive config but may not connect until peer is added manually');
    }

    // 5. Create VPN session record (NO private key stored!)
    const sessionId = uuidv4();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO vpn_sessions (
        id, wallet, subscription_id, nft_mint, server_id, server_ip,
        session_key, client_ip, connected_at, status,
        wg_public_key, wg_client_ip
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
    `).run(
      sessionId,
      wallet,
      sub.id,
      sub.nft_mint,
      node.id,
      node.host,
      'WIREGUARD_SESSION', // Legacy field, no longer used
      clientIp,
      now,
      client_public_key,
      clientVpnIP
    );

    // 6. Log audit event
    logAuditEvent(db, wallet, 'vpn_connected_wireguard', clientIp, {
      session_id: sessionId,
      node_id: node.id,
      node_location: node.location,
      wg_client_ip: clientVpnIP,
      wg_public_key: client_public_key
    });

    // 7. Return server config to client (client builds full config locally)
    res.json({
      ok: true,
      session_id: sessionId,
      protocol: 'wireguard',
      node: {
        id: node.id,
        name: node.name,
        location: node.location,
        host: node.host,
        port: node.port,
        protocol: node.protocol,
      },
      wireguard: {
        // Server info only - client has private key already
        server_public_key: serverInfo.publicKey || 'SERVER_PUBLIC_KEY_PLACEHOLDER',
        server_endpoint: serverInfo.endpoint,
        client_ip: clientVpnIP,
        dns: '1.1.1.1',
        allowed_ips: '0.0.0.0/0, ::/0',
        persistent_keepalive: 25
      },
      device_limit: sub.device_limit,
      active_sessions: activeSessions.count + 1,
    });
  } catch (error) {
    console.error('Error connecting to WireGuard VPN:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

/**
 * POST /vpn/heartbeat
 * Update session last heartbeat time
 */
app.post('/vpn/heartbeat', vpnLimiter, (req, res) => {
  try {
    const { wallet, session_id } = req.body;

    if (!wallet || !session_id) {
      return res.status(400).json({
        ok: false,
        error: 'Missing required fields: wallet, session_id',
      });
    }

    const db = getDatabase();
    const now = new Date().toISOString();

    // Update connected_at to act as "last heartbeat" timestamp
    const result = db.prepare(`
      UPDATE vpn_sessions
      SET connected_at = ?
      WHERE id = ? AND wallet = ? AND status = 'active'
    `).run(now, session_id, wallet);

    if (result.changes === 0) {
      return res.status(404).json({
        ok: false,
        error: 'Session not found or already disconnected',
      });
    }

    res.json({
      ok: true,
      message: 'Heartbeat received',
    });
  } catch (error) {
    console.error('Error processing heartbeat:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

/**
 * POST /vpn/disconnect
 * Disconnect WireGuard VPN session and remove peer from server
 */
app.post('/vpn/disconnect', vpnLimiter, async (req, res) => {
  try {
    const { wallet, session_id } = req.body;

    if (!wallet || !session_id) {
      return res.status(400).json({
        ok: false,
        error: 'Missing required fields: wallet, session_id',
      });
    }

    const db = getDatabase();
    const clientIp = getClientIp(req);
    const now = new Date().toISOString();

    // Get session details (need WG public key and server info)
    const session = db.prepare(`
      SELECT vpn_sessions.*, vpn_servers.host as server_host,
             vpn_servers.wg_ssh_host, vpn_servers.wg_ssh_port, vpn_servers.wg_ssh_user
      FROM vpn_sessions
      LEFT JOIN vpn_servers ON vpn_sessions.server_id = vpn_servers.id
      WHERE vpn_sessions.id = ? AND vpn_sessions.wallet = ?
    `).get(session_id, wallet);

    if (!session) {
      return res.status(404).json({
        ok: false,
        error: 'Session not found',
      });
    }

    // Remove peer from WireGuard server if public key exists
    if (session.wg_public_key) {
      const sshKeyPath = getSSHKeyPath();
      try {
        await removeWireguardPeer({
          host: session.wg_ssh_host || session.server_host,
          port: session.wg_ssh_port || 22,
          user: session.wg_ssh_user || 'root',
          clientPublicKey: session.wg_public_key,
          keyPath: sshKeyPath
        });
        console.log(`✅ Removed WireGuard peer ${session.wg_public_key} from ${session.server_host}`);
      } catch (sshError) {
        console.error('⚠️  Failed to remove peer from server:', sshError.message);
        // Continue anyway - session will be marked disconnected
      }
    }

    // Update session status
    db.prepare(`
      UPDATE vpn_sessions
      SET status = 'disconnected', disconnected_at = ?
      WHERE id = ? AND wallet = ?
    `).run(now, session_id, wallet);

    // Log audit event
    logAuditEvent(db, wallet, 'vpn_disconnected_wireguard', clientIp, {
      session_id,
      wg_public_key: session.wg_public_key,
      wg_client_ip: session.wg_client_ip
    });

    res.json({
      ok: true,
      message: 'WireGuard session disconnected',
    });
  } catch (error) {
    console.error('Error disconnecting WireGuard VPN:', error);
    res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
});

// ============================================================================
// NFT METADATA & IMAGE ROUTES (Off-chain storage)
// ============================================================================

/**
 * GET /nft/metadata/:mintAddress
 * Serve NFT metadata JSON (Metaplex standard)
 */
app.get('/nft/metadata/:mintAddress', (req, res) => {
  try {
    const { mintAddress } = req.params;

    const db = getDatabase();
    const nftMeta = db.prepare(`
      SELECT * FROM nft_metadata WHERE mint_address = ?
    `).get(mintAddress);

    if (!nftMeta) {
      return res.status(404).json({
        error: 'NFT metadata not found'
      });
    }

    // Parse attributes from JSON string
    const attributes = JSON.parse(nftMeta.attributes);

    // Get API base URL
    const apiBaseUrl = process.env.API_BASE_URL || `http://localhost:${PORT}`;

    // Return Metaplex-compatible metadata
    const metadata = {
      name: nftMeta.name,
      symbol: nftMeta.symbol,
      description: nftMeta.description,
      image: `${apiBaseUrl}/nft/image/${nftMeta.plan}.png`,
      attributes,
      properties: {
        files: [
          {
            uri: `${apiBaseUrl}/nft/image/${nftMeta.plan}.png`,
            type: 'image/png'
          }
        ],
        category: 'image',
        creators: [
          {
            address: process.env.AKCA_TREASURY_PUBLIC_KEY,
            share: 100
          }
        ]
      }
    };

    res.json(metadata);
  } catch (error) {
    console.error('Error serving NFT metadata:', error);
    res.status(500).json({
      error: 'Failed to serve metadata'
    });
  }
});

/**
 * GET /nft/image/:plan.png
 * Serve NFT badge image (simple SVG placeholder)
 */
app.get('/nft/image/:plan.png', (req, res) => {
  const { plan } = req.params;

  // Define colors for each plan
  const colors = {
    standard: { bg: '#4F46E5', text: '#FFFFFF' },
    pro: { bg: '#EC4899', text: '#FFFFFF' }
  };

  const color = colors[plan] || { bg: '#6366F1', text: '#FFFFFF' };
  const planName = plan === 'pro' ? 'Pro' : 'Standard';

  // Generate SVG badge
  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg width="400" height="400" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:${color.bg};stop-opacity:1" />
      <stop offset="100%" style="stop-color:${color.bg}dd;stop-opacity:1" />
    </linearGradient>
  </defs>

  <!-- Background -->
  <rect width="400" height="400" fill="url(#grad)" rx="20"/>

  <!-- Border -->
  <rect x="10" y="10" width="380" height="380" fill="none" stroke="${color.text}" stroke-width="2" rx="15" opacity="0.3"/>

  <!-- Logo Circle -->
  <circle cx="200" cy="140" r="60" fill="${color.text}" opacity="0.2"/>
  <circle cx="200" cy="140" r="45" fill="none" stroke="${color.text}" stroke-width="3"/>

  <!-- VPN Icon -->
  <path d="M 180 130 L 200 110 L 220 130" fill="none" stroke="${color.text}" stroke-width="4" stroke-linecap="round"/>
  <path d="M 180 150 L 200 170 L 220 150" fill="none" stroke="${color.text}" stroke-width="4" stroke-linecap="round"/>
  <line x1="200" y1="110" x2="200" y2="170" stroke="${color.text}" stroke-width="4" stroke-linecap="round"/>

  <!-- Text -->
  <text x="200" y="240" font-family="Arial, sans-serif" font-size="32" font-weight="bold" fill="${color.text}" text-anchor="middle">AKCA NETWORK</text>
  <text x="200" y="280" font-family="Arial, sans-serif" font-size="24" fill="${color.text}" text-anchor="middle" opacity="0.9">${planName} Access Pass</text>

  <!-- Bottom decoration -->
  <rect x="100" y="320" width="200" height="2" fill="${color.text}" opacity="0.3"/>
  <text x="200" y="350" font-family="Arial, sans-serif" font-size="16" fill="${color.text}" text-anchor="middle" opacity="0.7">VPN Access NFT</text>
</svg>`;

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=31536000'); // Cache for 1 year
  res.send(svg);
});

// Export app for Lambda
export { app };

// Start server (sadece local development için)
if (process.env.NODE_ENV !== 'production' || !process.env.AWS_LAMBDA_FUNCTION_NAME) {
  app.listen(PORT, () => {
    console.log(`✅ Akca Network API v${API_VERSION} running on http://localhost:${PORT}`);
    console.log(`   Environment: ${process.env.SOLANA_CLUSTER || 'devnet'}`);
    console.log(`   Treasury: ${process.env.AKCA_TREASURY_PUBLIC_KEY || 'NOT CONFIGURED'}`);
    console.log(`   NFT Metadata: ${process.env.API_BASE_URL || `http://localhost:${PORT}`}/nft/metadata/{mint}`);
    console.log(`   Health Check: SSH-based WireGuard monitoring enabled`);

    // Start VPN node health check service
    startHealthCheck();
  });
}
