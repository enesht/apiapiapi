import jwt from 'jsonwebtoken';

// CRITICAL: JWT_SECRET must be set in environment variables
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('CRITICAL: JWT_SECRET environment variable must be configured for security');
}
const JWT_EXPIRY = '24h'; // Token expires in 24 hours

/**
 * Generate JWT token for authenticated session
 * @param {string} wallet - Wallet address
 * @param {Array} nfts - User's NFTs (optional)
 * @returns {string} JWT token
 */
export function generateToken(wallet, nfts = []) {
  const payload = {
    wallet,
    nfts: nfts.map(nft => ({
      mint: nft.mint,
      name: nft.name,
      plan: nft.json?.attributes?.find(a => a.trait_type === 'Plan')?.value,
      expires_at: nft.json?.attributes?.find(a => a.trait_type === 'Expires At')?.value,
    })),
    iat: Math.floor(Date.now() / 1000),
  };

  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

/**
 * Verify and decode JWT token
 * @param {string} token - JWT token
 * @returns {Object} Decoded payload
 * @throws {Error} If token is invalid or expired
 */
export function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Token expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid token');
    }
    throw error;
  }
}

/**
 * Middleware to verify JWT token from Authorization header
 */
export function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      ok: false,
      error: 'No token provided',
    });
  }

  try {
    const decoded = verifyToken(token);
    req.user = decoded; // Attach decoded payload to request
    next();
  } catch (error) {
    return res.status(403).json({
      ok: false,
      error: error.message,
    });
  }
}
