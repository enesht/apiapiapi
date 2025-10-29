import {
  Connection,
  PublicKey,
  Keypair,
  SystemProgram,
  LAMPORTS_PER_SOL,
} from '@solana/web3.js';
import { Metaplex, keypairIdentity } from '@metaplex-foundation/js';
import bs58 from 'bs58';
import { v4 as uuidv4 } from 'uuid';

/**
 * Initialize Solana connection with optimized settings for devnet
 */
export function getConnection() {
  const rpcUrl = process.env.RPC_URL || 'https://api.devnet.solana.com';
  return new Connection(rpcUrl, {
    commitment: 'confirmed',
    confirmTransactionInitialTimeout: 90000,
  });
}

/**
 * Get treasury keypair from environment variable
 */
export function getTreasuryKeypair() {
  const secretKey = process.env.AKCA_TREASURY_SECRET_KEY;

  if (!secretKey) {
    throw new Error('AKCA_TREASURY_SECRET_KEY not configured');
  }

  try {
    // Try base58 format first (Phantom wallet export format)
    const decoded = bs58.decode(secretKey);
    return Keypair.fromSecretKey(decoded);
  } catch {
    try {
      // Try JSON array format [1,2,3,...]
      const keyArray = JSON.parse(secretKey);
      return Keypair.fromSecretKey(Uint8Array.from(keyArray));
    } catch (error) {
      throw new Error('Invalid AKCA_TREASURY_SECRET_KEY format. Must be base58 or JSON array.');
    }
  }
}

/**
 * Initialize Metaplex instance (without Bundlr/Arweave storage)
 */
export function getMetaplex() {
  const connection = getConnection();
  const treasury = getTreasuryKeypair();

  return Metaplex.make(connection)
    .use(keypairIdentity(treasury));
}

/**
 * Verify a payment transaction on-chain
 * @param {string} txSignature - Transaction signature
 * @param {string} expectedFrom - Expected sender wallet
 * @param {string} expectedTo - Expected recipient wallet
 * @param {number} expectedAmount - Expected amount in SOL
 * @returns {Promise<{valid: boolean, amount?: number, error?: string}>}
 */
export async function verifyPaymentTransaction(
  txSignature,
  expectedFrom,
  expectedTo,
  expectedAmount
) {
  try {
    const connection = getConnection();

    console.log(`[Payment Verify] Checking transaction: ${txSignature}`);

    // Get transaction details
    const tx = await connection.getTransaction(txSignature, {
      maxSupportedTransactionVersion: 0,
    });

    if (!tx) {
      return { valid: false, error: 'Transaction not found' };
    }

    if (tx.meta?.err) {
      return { valid: false, error: 'Transaction failed on-chain' };
    }

    // Parse transaction to find SOL transfer
    const { transaction } = tx;
    const accountKeys = transaction.message.getAccountKeys();
    const instructions = transaction.message.compiledInstructions;

    let transferFound = false;
    let actualAmount = 0;

    for (const instruction of instructions) {
      const programId = accountKeys.get(instruction.programIdIndex);

      // Check if this is a System Program transfer
      if (programId?.equals(SystemProgram.programId)) {
        const accounts = instruction.accountKeyIndexes.map(i => accountKeys.get(i));

        // SystemProgram transfer has: from, to as first two accounts
        if (accounts.length >= 2) {
          const from = accounts[0];
          const to = accounts[1];

          if (
            from?.toBase58() === expectedFrom &&
            to?.toBase58() === expectedTo
          ) {
            // Decode transfer amount from instruction data
            // System Program transfer instruction: [2, 0, 0, 0, ...amount (8 bytes little-endian)]
            if (instruction.data.length >= 12 && instruction.data[0] === 2) {
              const amountBuffer = instruction.data.slice(4, 12);
              const lamports = Number(
                BigInt.asUintN(64,
                  amountBuffer.reduce((acc, byte, i) => acc + BigInt(byte) * (2n ** BigInt(i * 8)), 0n)
                )
              );
              actualAmount = lamports / LAMPORTS_PER_SOL;
              transferFound = true;
              break;
            }
          }
        }
      }
    }

    if (!transferFound) {
      return { valid: false, error: 'No matching transfer found in transaction' };
    }

    // Allow small tolerance for floating point differences
    const tolerance = 0.0001;
    if (Math.abs(actualAmount - expectedAmount) > tolerance) {
      return {
        valid: false,
        error: `Amount mismatch: expected ${expectedAmount} SOL, got ${actualAmount} SOL`,
        amount: actualAmount,
      };
    }

    console.log(`[Payment Verify] ✅ Valid payment: ${actualAmount} SOL`);
    return { valid: true, amount: actualAmount };
  } catch (error) {
    console.error('[Payment Verify] Error:', error);
    console.error('[Payment Verify] Stack:', error.stack);
    return { valid: false, error: error.message };
  }
}

/**
 * Mint a Metaplex NFT with off-chain metadata (no Arweave)
 * @param {string} userWallet - User's wallet address
 * @param {string} plan - Subscription plan ID
 * @param {number} priceUsd - Price in USD
 * @param {number} priceSol - Price in SOL
 * @param {string} mintIp - IP address where mint was initiated
 * @param {string} subscriptionId - Subscription ID from database
 * @returns {Promise<{mint: string, subscription_id: string, akca_ref_id: string, expires_at: string}>}
 */
export async function mintAccessNFT(userWallet, plan, priceUsd, priceSol, mintIp, subscriptionId) {
  const treasury = getTreasuryKeypair();
  const connection = getConnection();
  const metaplex = getMetaplex();

  try {
    console.log(`[NFT Mint] Creating Metaplex NFT (off-chain metadata) for: ${userWallet}, plan: ${plan}`);

    // Check treasury balance
    const balance = await connection.getBalance(treasury.publicKey);
    const balanceSol = balance / LAMPORTS_PER_SOL;
    console.log(`[NFT Mint] Treasury balance: ${balanceSol.toFixed(4)} SOL`);

    if (balanceSol < 0.02) {
      throw new Error(`Insufficient treasury balance: ${balanceSol} SOL (need at least 0.02 SOL for NFT mint)`);
    }

    // Generate unique reference ID
    const akca_ref_id = uuidv4();

    // Calculate expiration date (30 days from now)
    const now = new Date();
    const expiresAt = new Date(now);
    expiresAt.setDate(expiresAt.getDate() + 30);

    // Define plan display names and device limits
    const planConfig = {
      standard: { name: 'Standard', devices: 2, color: '#4F46E5' },
      pro: { name: 'Pro', devices: 5, color: '#EC4899' }
    };
    const config = planConfig[plan] || { name: plan, devices: 1, color: '#6366F1' };

    console.log('[NFT Mint] Step 1/3: Preparing metadata...');

    // Get API base URL from environment
    const apiBaseUrl = process.env.API_BASE_URL || 'http://localhost:3000';

    // Create NFT metadata following Metaplex standard
    const metadata = {
      name: `Akca Network - ${config.name}`,
      symbol: 'AKCA',
      description: `Akca Network VPN Access Pass - ${config.name} subscription. Provides secure VPN access for up to ${config.devices} simultaneous devices. Valid until ${expiresAt.toLocaleDateString()}.`,
      image: `${apiBaseUrl}/nft/image/${plan}.png`,
      attributes: [
        {
          trait_type: 'Plan',
          value: config.name
        },
        {
          trait_type: 'Device Limit',
          value: config.devices
        },
        {
          trait_type: 'Creator Wallet',
          value: userWallet
        },
        {
          trait_type: 'Created At',
          value: now.toISOString()
        },
        {
          trait_type: 'Expires At',
          value: expiresAt.toISOString()
        },
        {
          trait_type: 'Akca Reference ID',
          value: akca_ref_id
        },
        {
          trait_type: 'Subscription ID',
          value: subscriptionId
        },
        {
          trait_type: 'Price USD',
          value: priceUsd.toString()
        },
        {
          trait_type: 'Price SOL',
          value: priceSol.toString()
        },
        {
          trait_type: 'Status',
          value: 'Active'
        }
      ],
      properties: {
        files: [
          {
            uri: `${apiBaseUrl}/nft/image/${plan}.png`,
            type: 'image/png'
          }
        ],
        category: 'image',
        creators: [
          {
            address: treasury.publicKey.toBase58(),
            share: 100
          }
        ]
      }
    };

    // Store metadata in database first (for serving via API)
    const { getDatabase } = await import('../db/init.js');
    const db = getDatabase();

    // Generate a unique mint address placeholder (will be updated after minting)
    const tempMintId = uuidv4();

    db.prepare(`
      INSERT INTO nft_metadata (
        mint_address, subscription_id, wallet, plan, device_limit,
        name, symbol, description, tier, expires_at, created_at, mint_ip, attributes
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      tempMintId,
      subscriptionId,
      userWallet,
      plan,
      config.devices,
      metadata.name,
      metadata.symbol,
      metadata.description,
      plan === 'pro' ? 'premium' : 'basic',
      expiresAt.toISOString(),
      now.toISOString(),
      mintIp,
      JSON.stringify(metadata.attributes)
    );

    console.log(`[NFT Mint] ✅ Metadata stored in database`);

    // Create metadata URI pointing to our API
    const metadataUri = `${apiBaseUrl}/nft/metadata/${tempMintId}`;
    console.log(`[NFT Mint] Metadata URI: ${metadataUri}`);

    console.log('[NFT Mint] Step 2/3: Creating NFT on-chain...');

    // Create the NFT using Metaplex
    const { nft } = await metaplex.nfts().create({
      uri: metadataUri,
      name: metadata.name,
      symbol: metadata.symbol,
      sellerFeeBasisPoints: 0, // 0% royalty
      isMutable: false, // Immutable NFT
      maxSupply: 1, // Only 1 copy
      tokenOwner: new PublicKey(userWallet), // Mint directly to user
      creators: [
        {
          address: treasury.publicKey,
          share: 100,
          verified: true
        }
      ]
    });

    const mintAddress = nft.address.toBase58();
    console.log(`[NFT Mint] ✅ NFT minted on-chain: ${mintAddress}`);

    console.log('[NFT Mint] Step 3/3: Updating database with real mint address...');

    // Update the database with the real mint address
    db.prepare(`
      UPDATE nft_metadata
      SET mint_address = ?
      WHERE mint_address = ?
    `).run(mintAddress, tempMintId);

    console.log(`[NFT Mint] ✅ SUCCESS!`);
    console.log(`[NFT Mint]    Mint: ${mintAddress}`);
    console.log(`[NFT Mint]    Owner: ${userWallet}`);
    console.log(`[NFT Mint]    Metadata URI: ${metadataUri.replace(tempMintId, mintAddress)}`);
    console.log(`[NFT Mint]    Reference ID: ${akca_ref_id}`);
    console.log(`[NFT Mint]    Devices: ${config.devices}`);
    console.log(`[NFT Mint]    Expires: ${expiresAt.toISOString()}`);

    return {
      mint: mintAddress,
      subscription_id: subscriptionId,
      akca_ref_id,
      expires_at: expiresAt.toISOString(),
      metadata_uri: `${apiBaseUrl}/nft/metadata/${mintAddress}`,
      nft_details: {
        name: metadata.name,
        symbol: metadata.symbol,
        device_limit: config.devices,
        attributes: metadata.attributes,
        image: metadata.image
      }
    };
  } catch (error) {
    console.error('[NFT Mint] ❌ ERROR:', error);

    if (error.message) {
      console.error('[NFT Mint] Error message:', error.message);
    }

    // User-friendly error messages
    if (error.message?.includes('0x1')) {
      throw new Error('Insufficient funds in treasury wallet');
    }

    if (error.message?.includes('blockhash')) {
      throw new Error('Transaction expired, please retry');
    }

    throw new Error(`NFT mint failed: ${error.message || 'Unknown error'}`);
  }
}


/**
 * Get all Metaplex NFTs owned by a wallet
 * @param {string} walletAddress - Wallet address to check
 * @returns {Promise<Array>} - Array of NFT objects
 */
export async function getWalletNFTs(walletAddress) {
  try {
    const metaplex = getMetaplex();

    console.log(`[Get NFTs] Fetching Metaplex NFTs for wallet: ${walletAddress}`);

    // Get all NFTs owned by the wallet
    const owner = new PublicKey(walletAddress);
    const nfts = await metaplex.nfts().findAllByOwner({ owner });

    console.log(`[Get NFTs] Found ${nfts.length} total NFTs on-chain`);

    // Filter for Akca NFTs (symbol = "AKCA")
    const akcaNfts = nfts.filter(nft => nft.symbol === 'AKCA');
    console.log(`[Get NFTs] Found ${akcaNfts.length} Akca NFTs`);

    // Load metadata from database (off-chain storage)
    const { getDatabase } = await import('../db/init.js');
    const db = getDatabase();

    const nftsWithMetadata = await Promise.all(
      akcaNfts.map(async (nft) => {
        try {
          const mintAddress = nft.address.toBase58();

          // Load full NFT data from Metaplex
          const fullNft = await metaplex.nfts().load({ metadata: nft });

          // Get off-chain metadata from database
          const dbMetadata = db.prepare(`
            SELECT attributes FROM nft_metadata WHERE mint_address = ?
          `).get(mintAddress);

          let attributes = [];
          if (dbMetadata && dbMetadata.attributes) {
            try {
              attributes = JSON.parse(dbMetadata.attributes);
              console.log(`[Get NFTs] Loaded attributes for ${mintAddress} from database:`, attributes.length, 'traits');
            } catch (parseError) {
              console.error(`[Get NFTs] Error parsing attributes for ${mintAddress}:`, parseError.message);
            }
          } else {
            console.warn(`[Get NFTs] No database metadata found for ${mintAddress}`);
          }

          return {
            mint: mintAddress,
            name: fullNft.name,
            symbol: fullNft.symbol,
            uri: fullNft.uri,
            json: {
              ...fullNft.json,
              attributes, // Use database attributes instead of on-chain
            },
            updateAuthority: fullNft.updateAuthorityAddress.toBase58(),
            creators: fullNft.creators,
          };
        } catch (error) {
          console.error(`[Get NFTs] Error loading NFT ${nft.address.toBase58()}:`, error.message);
          return null;
        }
      })
    );

    // Filter out any failed loads
    const validNfts = nftsWithMetadata.filter(nft => nft !== null);

    console.log(`[Get NFTs] Successfully loaded ${validNfts.length} Akca NFTs with metadata`);

    return validNfts;
  } catch (error) {
    console.error('[Get NFTs] Error:', error);
    console.error('[Get NFTs] Stack:', error.stack);

    // Fallback: check database if on-chain query fails
    console.log('[Get NFTs] Falling back to database query...');
    try {
      const { getDatabase } = await import('../db/init.js');
      const db = getDatabase();

      const subscriptions = db.prepare(`
        SELECT * FROM subscriptions
        WHERE wallet = ? AND nft_mint IS NOT NULL
        ORDER BY created_at DESC
      `).all(walletAddress);

      console.log(`[Get NFTs] Found ${subscriptions.length} subscriptions in database`);

      return subscriptions.map(sub => ({
        mint: sub.nft_mint,
        name: `Akca Network - ${sub.plan}`,
        symbol: 'AKCA',
        uri: '',
        json: {
          attributes: [
            { trait_type: 'Plan', value: sub.plan },
            { trait_type: 'Expires At', value: sub.expires_at },
            { trait_type: 'Device Limit', value: sub.device_limit },
          ],
        },
      }));
    } catch (dbError) {
      console.error('[Get NFTs] Database fallback also failed:', dbError);
      return [];
    }
  }
}

/**
 * Check if wallet has valid Akca Access NFT
 * @param {string} walletAddress - Wallet address
 * @returns {Promise<{hasAccess: boolean, nfts: Array}>}
 */
export async function checkWalletAccess(walletAddress) {
  try {
    const nfts = await getWalletNFTs(walletAddress);

    if (nfts.length === 0) {
      return { hasAccess: false, nfts: [] };
    }

    // Check if any NFT is not expired
    const now = new Date();
    const validNfts = nfts.filter(nft => {
      const expiresAtAttr = nft.json?.attributes?.find(
        attr => attr.trait_type === 'Expires At'
      );

      if (!expiresAtAttr) {
        return false;
      }

      const expiresAt = new Date(expiresAtAttr.value);
      return expiresAt > now;
    });

    console.log(`[Check Access] Wallet ${walletAddress}: ${validNfts.length} valid NFTs`);

    return {
      hasAccess: validNfts.length > 0,
      nfts: validNfts,
    };
  } catch (error) {
    console.error('[Check Access] Error:', error.message);
    return { hasAccess: false, nfts: [] };
  }
}
