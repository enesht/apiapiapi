import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { PublicKey } from '@solana/web3.js';

/**
 * Verify a Solana wallet signature
 * @param {string} message - The message that was signed
 * @param {string} signature - Base58 encoded signature
 * @param {string} walletAddress - Public key of the wallet
 * @returns {boolean} - True if signature is valid
 */
export function verifySignature(message, signature, walletAddress) {
  try {
    // Decode the signature from base58
    const signatureUint8 = bs58.decode(signature);

    // Convert message to Uint8Array
    const messageUint8 = new TextEncoder().encode(message);

    // Get public key
    const publicKey = new PublicKey(walletAddress);
    const publicKeyUint8 = publicKey.toBytes();

    // Verify signature
    return nacl.sign.detached.verify(
      messageUint8,
      signatureUint8,
      publicKeyUint8
    );
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

/**
 * Generate a random message for signing
 * @returns {string} - Random message for wallet to sign
 */
export function generateAuthMessage() {
  const timestamp = new Date().toISOString();
  const nonce = Math.random().toString(36).substring(7);
  return `Sign this message to authenticate with Akca Network.\n\nTimestamp: ${timestamp}\nNonce: ${nonce}`;
}
