import fetch from 'node-fetch';

const COINGECKO_API = 'https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd';
const FALLBACK_SOL_PRICE = 150; // Fallback if API fails
const CACHE_DURATION = 60000; // 1 minute cache

let cachedPrice = null;
let cacheTimestamp = 0;

/**
 * Get current SOL price in USD
 * @returns {Promise<{price: number, source: string}>}
 */
export async function getSolPrice() {
  const now = Date.now();

  // Return cached price if still valid
  if (cachedPrice && (now - cacheTimestamp) < CACHE_DURATION) {
    return { price: cachedPrice, source: 'cache' };
  }

  try {
    const response = await fetch(COINGECKO_API, {
      timeout: 5000,
    });

    if (!response.ok) {
      throw new Error(`CoinGecko API error: ${response.status}`);
    }

    const data = await response.json();
    const price = data?.solana?.usd;

    if (typeof price === 'number' && price > 0) {
      cachedPrice = price;
      cacheTimestamp = now;
      return { price, source: 'coingecko' };
    }

    throw new Error('Invalid price data from API');
  } catch (error) {
    console.warn('Failed to fetch SOL price from CoinGecko:', error.message);
    console.warn(`Using fallback price: $${FALLBACK_SOL_PRICE}`);

    // Use fallback price
    cachedPrice = FALLBACK_SOL_PRICE;
    cacheTimestamp = now;
    return { price: FALLBACK_SOL_PRICE, source: 'fallback' };
  }
}

/**
 * Convert USD amount to SOL
 * @param {number} usdAmount - Amount in USD
 * @returns {Promise<number>} - Amount in SOL
 */
export async function usdToSol(usdAmount) {
  const { price } = await getSolPrice();
  return usdAmount / price;
}

/**
 * Get subscription plans with SOL conversion
 * @returns {Promise<Array>} - Array of plan objects
 */
export async function getSubscriptionPlans() {
  const { price: solPrice, source } = await getSolPrice();
  const mintFee = 0.01; // ~0.01 SOL for mint fee

  const plans = [
    {
      id: 'standard',
      name: 'Standard',
      price_usd: 19.99,
      duration_days: 30,
      device_limit: 2,
      features: ['Secure VPN access', '2 simultaneous devices', 'Standard speed', 'Basic nodes'],
    },
    {
      id: 'pro',
      name: 'Pro',
      price_usd: 29.99,
      duration_days: 30,
      device_limit: 5,
      features: ['Premium VPN access', '5 simultaneous devices', 'High speed', 'All nodes', 'Priority support'],
    },
  ];

  // Add SOL conversion to each plan
  const plansWithSol = plans.map(plan => ({
    ...plan,
    price_sol: Number((plan.price_usd / solPrice).toFixed(4)),
    mint_fee_sol: mintFee,
    total_sol: Number(((plan.price_usd / solPrice) + mintFee).toFixed(4)),
  }));

  return {
    plans: plansWithSol,
    sol_price_usd: solPrice,
    price_source: source,
    mint_fee_sol: mintFee,
  };
}
