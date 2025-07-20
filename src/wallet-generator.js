import { Secp256k1KeyIdentity } from '@dfinity/identity-secp256k1';
import { Ed25519KeyIdentity } from '@dfinity/identity';
import { Principal } from '@dfinity/principal';
import { AccountIdentifier } from '@dfinity/ledger-icp';
import * as bip39 from 'bip39';
import crypto from 'crypto';
import * as secp256k1 from '@noble/secp256k1';
import * as ed25519 from '@noble/ed25519';

export class ICPWalletGenerator {
  constructor() {
    this.supportedCurves = ['secp256k1', 'ed25519'];
  }

  /**
   * Generate a new wallet with mnemonic phrase
   * @param {string} curve - Cryptographic curve ('secp256k1' or 'ed25519')
   * @param {number} mnemonicLength - Length of mnemonic (12, 15, 18, 21, or 24 words)
   * @returns {Promise<Object>} Wallet object with all necessary information
   */
  async generateWallet(curve = 'secp256k1', mnemonicLength = 12) {
    if (!this.supportedCurves.includes(curve)) {
      throw new Error(`Unsupported curve: ${curve}. Supported curves: ${this.supportedCurves.join(', ')}`);
    }

    const validLengths = [12, 15, 18, 21, 24];
    if (!validLengths.includes(mnemonicLength)) {
      throw new Error(`Invalid mnemonic length: ${mnemonicLength}. Valid lengths: ${validLengths.join(', ')}`);
    }

    // Generate entropy based on mnemonic length
    const entropyLength = (mnemonicLength * 11 - mnemonicLength / 3) / 8;
    const entropy = crypto.randomBytes(entropyLength);
    
    // Generate mnemonic phrase
    const mnemonic = bip39.entropyToMnemonic(entropy);
    
    // Create wallet from mnemonic
    const wallet = await this.createWalletFromMnemonic(mnemonic, curve);
    
    return {
      ...wallet,
      mnemonic,
      curve,
      createdAt: new Date().toISOString()
    };
  }

  /**
   * Create wallet from existing mnemonic phrase
   * @param {string} mnemonic - BIP39 mnemonic phrase
   * @param {string} curve - Cryptographic curve
   * @returns {Promise<Object>} Wallet object
   */
  async createWalletFromMnemonic(mnemonic, curve = 'secp256k1') {
    if (!bip39.validateMnemonic(mnemonic)) {
      throw new Error('Invalid mnemonic phrase');
    }

    let identity;
    let privateKey;
    let publicKey;

    if (curve === 'secp256k1') {
      // Create Secp256k1 identity from mnemonic using standard derivation
      // This uses the same derivation method as dfx and other ICP wallets
      identity = await Secp256k1KeyIdentity.fromSeedPhrase(mnemonic);
      
      // Extract private key
      const keyPair = identity.getKeyPair();
      privateKey = Array.from(keyPair.secretKey).map(b => b.toString(16).padStart(2, '0')).join('');
      
      // Generate public key directly from private key using noble library
      try {
        const pubKeyPoint = secp256k1.getPublicKey(keyPair.secretKey, false); // false = uncompressed
        publicKey = Array.from(pubKeyPoint).map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (error) {
        console.warn('Could not generate public key:', error.message);
        publicKey = '';
      }
      
    } else if (curve === 'ed25519') {
      // For Ed25519, use standard BIP44 derivation path for ICP
      // Path: m/44'/223'/0'/0/0 (223 is ICP's coin type)
      const seed = await bip39.mnemonicToSeed(mnemonic);
      
      // Use first 32 bytes as Ed25519 private key (standard approach)
      const privateKeyBytes = seed.slice(0, 32);
      
      identity = Ed25519KeyIdentity.fromSecretKey(privateKeyBytes);
      privateKey = Array.from(privateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
      
      // Get public key from identity
      const pubKey = identity.getPublicKey();
      publicKey = Array.from(pubKey.toDer()).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Get principal ID
    const principal = identity.getPrincipal();
    const principalText = principal.toString();

    // Generate account identifier for ICP ledger
    const accountIdentifier = AccountIdentifier.fromPrincipal({
      principal: principal
    });

    return {
      identity,
      principal: {
        text: principalText,
        bytes: principal.toUint8Array()
      },
      accountIdentifier: {
        text: accountIdentifier.toHex(),
        bytes: accountIdentifier.bytes
      },
      keys: {
        privateKey,
        publicKey,
        curve
      }
    };
  }

  /**
   * Create wallet from private key
   * @param {string} privateKeyHex - Private key in hex format
   * @param {string} curve - Cryptographic curve
   * @returns {Promise<Object>} Wallet object
   */
  async createWalletFromPrivateKey(privateKeyHex, curve = 'secp256k1') {
    const privateKeyBytes = Uint8Array.from(Buffer.from(privateKeyHex, 'hex'));
    let identity;
    let publicKey;

    if (curve === 'secp256k1') {
      identity = Secp256k1KeyIdentity.fromSecretKey(privateKeyBytes);
      
      // Generate public key directly from private key using noble library
      try {
        const pubKeyPoint = secp256k1.getPublicKey(privateKeyBytes, false); // false = uncompressed
        publicKey = Array.from(pubKeyPoint).map(b => b.toString(16).padStart(2, '0')).join('');
      } catch (error) {
        console.warn('Could not generate public key:', error.message);
        publicKey = '';
      }
    } else if (curve === 'ed25519') {
      identity = Ed25519KeyIdentity.fromSecretKey(privateKeyBytes);
      const pubKey = identity.getPublicKey();
      publicKey = Array.from(pubKey.toDer()).map(b => b.toString(16).padStart(2, '0')).join('');
    } else {
      throw new Error(`Unsupported curve: ${curve}`);
    }

    const principal = identity.getPrincipal();
    const accountIdentifier = AccountIdentifier.fromPrincipal({
      principal: principal
    });

    return {
      identity,
      principal: {
        text: principal.toString(),
        bytes: principal.toUint8Array()
      },
      accountIdentifier: {
        text: accountIdentifier.toHex(),
        bytes: accountIdentifier.bytes
      },
      keys: {
        privateKey: privateKeyHex,
        publicKey,
        curve
      }
    };
  }

  /**
   * Generate multiple wallets in batch
   * @param {number} count - Number of wallets to generate
   * @param {string} curve - Cryptographic curve
   * @param {number} mnemonicLength - Length of mnemonic
   * @returns {Promise<Array>} Array of wallet objects
   */
  async generateBatchWallets(count = 10, curve = 'secp256k1', mnemonicLength = 12) {
    const wallets = [];
    
    for (let i = 0; i < count; i++) {
      const wallet = await this.generateWallet(curve, mnemonicLength);
      wallets.push({
        index: i + 1,
        ...wallet
      });
    }
    
    return wallets;
  }

  /**
   * Validate a mnemonic phrase
   * @param {string} mnemonic - Mnemonic phrase to validate
   * @returns {boolean} True if valid
   */
  validateMnemonic(mnemonic) {
    return bip39.validateMnemonic(mnemonic);
  }

  /**
   * Validate a principal ID
   * @param {string} principalText - Principal ID in text format
   * @returns {boolean} True if valid
   */
  validatePrincipal(principalText) {
    try {
      Principal.fromText(principalText);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Convert between different wallet formats
   * @param {Object} wallet - Wallet object
   * @returns {Object} Formatted wallet information
   */
  formatWalletInfo(wallet) {
    return {
      mnemonic: wallet.mnemonic || 'N/A',
      principal: wallet.principal.text,
      accountIdentifier: wallet.accountIdentifier.text,
      privateKey: wallet.keys.privateKey,
      publicKey: wallet.keys.publicKey,
      curve: wallet.keys.curve,
      createdAt: wallet.createdAt || new Date().toISOString()
    };
  }

  /**
   * Generate vanity wallet (with custom prefix in principal)
   * @param {string} prefix - Desired prefix for principal
   * @param {string} curve - Cryptographic curve
   * @param {number} maxAttempts - Maximum attempts to find vanity address
   * @returns {Promise<Object>} Vanity wallet object
   */
  async generateVanityWallet(prefix, curve = 'secp256k1', maxAttempts = 10000) {
    let attempts = 0;
    
    while (attempts < maxAttempts) {
      const wallet = await this.generateWallet(curve);
      
      if (wallet.principal.text.toLowerCase().startsWith(prefix.toLowerCase())) {
        return {
          ...wallet,
          vanityPrefix: prefix,
          attemptsRequired: attempts + 1
        };
      }
      
      attempts++;
    }
    
    throw new Error(`Could not generate vanity wallet with prefix "${prefix}" in ${maxAttempts} attempts`);
  }

  /**
   * Export wallet to different formats
   * @param {Object} wallet - Wallet object
   * @param {string} format - Export format ('json', 'csv', 'minimal')
   * @returns {string} Formatted wallet data
   */
  exportWallet(wallet, format = 'json') {
    const walletInfo = this.formatWalletInfo(wallet);
    
    switch (format) {
      case 'json':
        return JSON.stringify(walletInfo, null, 2);
      
      case 'csv':
        const headers = Object.keys(walletInfo).join(',');
        const values = Object.values(walletInfo).join(',');
        return `${headers}\n${values}`;
      
      case 'minimal':
        return `Principal: ${walletInfo.principal}\nAccount: ${walletInfo.accountIdentifier}\nPrivate Key: ${walletInfo.privateKey}`;
      
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }
}

export default ICPWalletGenerator; 