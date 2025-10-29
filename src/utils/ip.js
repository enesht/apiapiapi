import fetch from 'node-fetch';

/**
 * Extract client IP address from request
 * @param {Request} req - Express request object
 * @returns {string} - Client IP address
 */
export function getClientIp(req) {
  // Check X-Forwarded-For header (from reverse proxy)
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    // X-Forwarded-For can contain multiple IPs, take the first one
    return forwarded.split(',')[0].trim();
  }

  // Check X-Real-IP header
  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    return realIp;
  }

  // Fallback to connection remote address
  return req.connection?.remoteAddress || req.socket?.remoteAddress || 'unknown';
}

/**
 * Get country information from IP address
 * @param {string} ip - IP address
 * @returns {Promise<{country: string, countryCode: string, city: string, region: string}>}
 */
export async function getCountryFromIp(ip) {
  try {
    // Skip for localhost/private IPs
    if (ip === 'unknown' || ip.startsWith('127.') || ip.startsWith('192.168.') || ip.startsWith('10.')) {
      return {
        country: 'Unknown',
        countryCode: 'XX',
        city: 'Unknown',
        region: 'Unknown'
      };
    }

    // Use ip-api.com (free, no API key needed)
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=country,countryCode,city,regionName`, {
      timeout: 5000
    });

    if (!response.ok) {
      throw new Error(`IP API error: ${response.status}`);
    }

    const data = await response.json();

    return {
      country: data.country || 'Unknown',
      countryCode: data.countryCode || 'XX',
      city: data.city || 'Unknown',
      region: data.regionName || 'Unknown'
    };
  } catch (error) {
    console.warn(`[IP Lookup] Failed to get country for IP ${ip}:`, error.message);
    return {
      country: 'Unknown',
      countryCode: 'XX',
      city: 'Unknown',
      region: 'Unknown'
    };
  }
}

/**
 * Log an audit event
 * @param {Object} db - Database instance
 * @param {string} wallet - Wallet address
 * @param {string} action - Action performed
 * @param {string} ip - IP address
 * @param {Object} details - Additional details
 */
export function logAuditEvent(db, wallet, action, ip, details = {}) {
  try {
    const now = new Date().toISOString();
    const detailsJson = JSON.stringify(details);

    db.prepare(`
      INSERT INTO audit_logs (wallet, event_type, ip_address, details, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(wallet, action, ip, detailsJson, now);

    console.log(`[Audit] ${action} by ${wallet} from ${ip}`);
  } catch (error) {
    console.error('[Audit] Failed to log event:', error.message);
    // Don't throw - audit logging shouldn't break main flow
  }
}

/**
 * Middleware to add IP tracking to all requests
 */
export function ipTrackingMiddleware(req, res, next) {
  req.clientIp = getClientIp(req);
  console.log(`[Request] ${req.method} ${req.path} from ${req.clientIp}`);
  next();
}

/**
 * Check if IP is rate limited
 * @param {Object} db - Database instance
 * @param {string} ip - IP address
 * @param {string} action - Action type
 * @param {number} limit - Max requests per hour
 * @returns {boolean} - True if rate limited
 */
export function isRateLimited(db, ip, action, limit = 10) {
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();

    const count = db.prepare(`
      SELECT COUNT(*) as count
      FROM audit_logs
      WHERE ip_address = ? AND event_type = ? AND created_at > ?
    `).get(ip, action, oneHourAgo);

    return count.count >= limit;
  } catch (error) {
    console.error('[Rate Limit] Check failed:', error.message);
    return false; // Fail open
  }
}
