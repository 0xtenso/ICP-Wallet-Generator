import { randomBytes } from 'crypto';
import * as ed25519 from '@noble/ed25519';
import * as secp256k1 from '@noble/secp256k1';
import { sha224, sha256 } from '@noble/hashes/sha2';
import { sha512 } from '@noble/hashes/sha512';
import { crc32 } from 'crc';
import * as bip39 from 'bip39';

// Setup SHA-512 for ed25519
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));

class ICPWalletGenerator {
    constructor() {
        this.generatedWallets = [];
        this.stats = { generated: 0, startTime: new Date() };
    }

    // Generate secure random seed
    generateRandomSeed(length = 32) {
        return new Uint8Array(randomBytes(length));
    }

    // Generate mnemonic and derive seed
    generateMnemonicSeed(mnemonic = null) {
        if (!mnemonic) {
            mnemonic = bip39.generateMnemonic();
        }
        if (!bip39.validateMnemonic(mnemonic)) {
            throw new Error('Invalid mnemonic phrase');
        }
        // Use the full 64-byte seed from BIP39
        const fullSeed = bip39.mnemonicToSeedSync(mnemonic);
        // For our purposes, we'll derive a 32-byte seed using SHA-256 of the full seed
        const derivedSeed = sha256(fullSeed);
        return { mnemonic, seed: new Uint8Array(derivedSeed) };
    }

    // Generate Ed25519 key pair
    async generateEd25519KeyPair(seed) {
        if (seed.length !== 32) throw new Error('Seed must be exactly 32 bytes');
        
        // RFC 8032: Ed25519 key generation
        // 1. Hash the 32-byte seed to get 64 bytes
        const hash = sha512(seed);
        
        // 2. Take the first 32 bytes as the private scalar (clamped)
        const privateScalar = new Uint8Array(hash.slice(0, 32));
        
        // 3. Clamp the private scalar according to Ed25519 spec
        privateScalar[0] &= 248;  // Clear bottom 3 bits
        privateScalar[31] &= 127; // Clear top bit
        privateScalar[31] |= 64;  // Set second highest bit
        
        // 4. Generate public key from the clamped private scalar
        const publicKey = await ed25519.getPublicKey(privateScalar);
        
        return {
            privateKey: privateScalar,
            publicKey: new Uint8Array(publicKey),
            keyType: 'Ed25519'
        };
    }

    // Generate Secp256k1 key pair
    generateSecp256k1KeyPair(seed) {
        if (seed.length !== 32) throw new Error('Seed must be exactly 32 bytes');
        
        // For Secp256k1, ensure the private key is in valid range (1 to n-1)
        // We use the seed directly but validate it's in the correct range
        let privateKey = new Uint8Array(seed);
        
        // Secp256k1 curve order (n)
        const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
        let keyBigInt = BigInt('0x' + Array.from(privateKey).map(b => b.toString(16).padStart(2, '0')).join(''));
        
        // If key is >= n, derive a new key using SHA-256
        if (keyBigInt >= n || keyBigInt === 0n) {
            const hash = sha256(privateKey);
            privateKey = new Uint8Array(hash);
            keyBigInt = BigInt('0x' + Array.from(privateKey).map(b => b.toString(16).padStart(2, '0')).join(''));
            
            // If still invalid, throw error (extremely unlikely)
            if (keyBigInt >= n || keyBigInt === 0n) {
                throw new Error('Unable to generate valid secp256k1 private key from seed');
            }
        }
        
        const publicKey = secp256k1.getPublicKey(privateKey, false); // Uncompressed
        
        return {
            privateKey: privateKey,
            publicKey: new Uint8Array(publicKey),
            keyType: 'Secp256k1'
        };
    }

    // Derive Principal ID from public key (ICP specification)
    derivePrincipalId(publicKey, keyType) {
        let derEncodedKey;

        if (keyType === 'Ed25519') {
            // DER encoding for Ed25519
            const oid = new Uint8Array([0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
            const bitString = new Uint8Array([0x03, 0x21, 0x00, ...publicKey]);
            derEncodedKey = new Uint8Array([0x30, 0x2a, ...oid, ...bitString]);
        } else if (keyType === 'Secp256k1') {
            // DER encoding for Secp256k1
            const oid = new Uint8Array([
                0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
            ]);
            const bitString = new Uint8Array([0x03, 0x42, 0x00, ...publicKey]);
            derEncodedKey = new Uint8Array([0x30, 0x56, ...oid, ...bitString]);
        } else {
            throw new Error('Unsupported key type');
        }

        // SHA-224 hash + 0x02 suffix for self-authenticating principal
        const hash = sha224(derEncodedKey);
        const principalId = new Uint8Array(29);
        principalId.set(hash, 0);
        principalId[28] = 0x02;
        return principalId;
    }

    calculateAccountId(principalId, subaccount = null) {
        if (!subaccount) {
            subaccount = new Uint8Array(32); // Default: all zeros
        }
        if (subaccount.length !== 32) {
            throw new Error('Subaccount must be exactly 32 bytes');
        }

        // Domain separator + principal + subaccount
        const domainSeparator = new Uint8Array([0x0A, ...new TextEncoder().encode('account-id')]);
        const data = new Uint8Array(domainSeparator.length + principalId.length + subaccount.length);
        data.set(domainSeparator, 0);
        data.set(principalId, domainSeparator.length);
        data.set(subaccount, domainSeparator.length + principalId.length);

        // SHA-224 hash
        const hash = sha224(data);

        // CRC32 checksum (big-endian)
        const checksum = crc32(hash);
        const checksumBytes = new Uint8Array(4);
        checksumBytes[0] = (checksum >> 24) & 0xFF;
        checksumBytes[1] = (checksum >> 16) & 0xFF;
        checksumBytes[2] = (checksum >> 8) & 0xFF;
        checksumBytes[3] = checksum & 0xFF;

        // Combine CRC32 + hash
        const accountId = new Uint8Array(32);
        accountId.set(checksumBytes, 0);
        accountId.set(hash, 4);
        return accountId;
    }

    // Utility functions
    bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    hexToBytes(hex) {
        const cleanHex = hex.replace(/^0x/, '').replace(/\s/g, '');
        if (cleanHex.length % 2 !== 0) throw new Error('Invalid hex string length');
        return new Uint8Array(cleanHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    }

    formatPrincipalId(principalId) {
        // Simplified base32 encoding for principal display
        const base32Chars = 'abcdefghijklmnopqrstuvwxyz234567';
        let binary = '';
        for (let byte of principalId) {
            binary += byte.toString(2).padStart(8, '0');
        }
        let result = '';
        for (let i = 0; i < binary.length; i += 5) {
            const chunk = binary.substr(i, 5).padEnd(5, '0');
            result += base32Chars[parseInt(chunk, 2)];
        }
        return result.match(/.{1,5}/g).join('-');
    }

    // Main wallet generation function
    async generateWallet(options = {}) {
        const {
            keyType = 'Ed25519',
            seedMethod = 'random',
            customSeed = null,
            mnemonic = null,
            subaccount = null
        } = options;

        let seed, mnemonicPhrase = null;

        // Always generate a mnemonic phrase for backup purposes
        // Generate seed based on method
        switch (seedMethod) {
            case 'random':
                // Generate mnemonic first, then derive seed from it
                const randomMnemonicResult = this.generateMnemonicSeed();
                seed = randomMnemonicResult.seed;
                mnemonicPhrase = randomMnemonicResult.mnemonic;
                break;
            case 'mnemonic':
                const mnemonicResult = this.generateMnemonicSeed(mnemonic);
                seed = mnemonicResult.seed;
                mnemonicPhrase = mnemonicResult.mnemonic;
                break;
            case 'custom':
                if (!customSeed) throw new Error('Custom seed is required');
                seed = typeof customSeed === 'string' ? this.hexToBytes(customSeed) : new Uint8Array(customSeed);
                // For custom seeds, generate a mnemonic that would produce a similar seed for backup
                mnemonicPhrase = this.generateBackupMnemonic(seed);
                break;
            default:
                throw new Error('Invalid seed method');
        }

        // Generate key pair
        let keyPair;
        if (keyType === 'Ed25519') {
            keyPair = await this.generateEd25519KeyPair(seed);
        } else if (keyType === 'Secp256k1') {
            keyPair = this.generateSecp256k1KeyPair(seed);
        } else {
            throw new Error('Unsupported key type');
        }

        // Derive Principal ID and Account ID
        const principalId = this.derivePrincipalId(keyPair.publicKey, keyType);
        const subaccountBytes = subaccount ? 
            (typeof subaccount === 'string' ? this.hexToBytes(subaccount) : new Uint8Array(subaccount)) : 
            null;
        const accountId = this.calculateAccountId(principalId, subaccountBytes);

        // Create wallet object
        const wallet = {
            index: this.stats.generated + 1,
            keyType,
            seed: {
                hex: this.bytesToHex(seed),
                mnemonic: mnemonicPhrase
            },
            privateKey: this.bytesToHex(keyPair.privateKey),
            publicKey: this.bytesToHex(keyPair.publicKey),
            principalId: {
                bytes: this.bytesToHex(principalId),
                text: this.formatPrincipalId(principalId)
            },
            accountId: this.bytesToHex(accountId),
            subaccount: subaccountBytes ? this.bytesToHex(subaccountBytes) : '0'.repeat(64),
            createdAt: new Date().toISOString()
        };

        this.stats.generated++;
        this.generatedWallets.push(wallet);
        return wallet;
    }

    // Generate a backup mnemonic for custom seeds
    generateBackupMnemonic(seed) {
        // For custom seeds, we can't recover the original mnemonic
        // So we generate a warning mnemonic indicating this is a custom seed
        return `custom seed wallet backup not available use hex seed ${this.bytesToHex(seed).substring(0, 8)}`;
    }

    // Generate multiple wallets
    async generateMultipleWallets(count, options = {}) {
        const wallets = [];
        for (let i = 0; i < count; i++) {
            wallets.push(await this.generateWallet(options));
        }
        return wallets;
    }

    // Export to JSON
    exportToJSON(wallets = null) {
        const walletsToExport = wallets || this.generatedWallets;
        return JSON.stringify({
            metadata: {
                generator: 'ICP Wallet Generator',
                version: '1.0.0',
                generated: walletsToExport.length,
                exportedAt: new Date().toISOString(),
                warning: 'Keep private keys secure! Never share them publicly.'
            },
            wallets: walletsToExport
        }, null, 2);
    }

    // Display wallet
    displayWallet(wallet) {
        console.log(`ICP Wallet #${wallet.index} (${wallet.keyType})`);
        if (wallet.seed.mnemonic) console.log(`Mnemonic: ${wallet.seed.mnemonic}`);
        console.log(`Seed: ${wallet.seed.hex}`);
        console.log(`Private Key: ${wallet.privateKey}`);
        console.log(`Public Key: ${wallet.publicKey}`);
        console.log(`Principal ID: ${wallet.principalId.text}`);
        console.log(`(Bytes): ${wallet.principalId.bytes}`);
        console.log(`Account ID: ${wallet.accountId}`);
        console.log(`Subaccount: ${wallet.subaccount}`);
        console.log(`Created: ${wallet.createdAt}`);
    }
}

// CLI execution
async function main() {
    const generator = new ICPWalletGenerator();
    
    console.log('ICP Wallet Generator v1.0.0');
    console.log('Internet Computer Protocol Wallet Generation Tool\n');

    try {
        // Generate one Ed25519 wallet with random seed
        console.log('Generating ICP wallet...');
        const wallet = await generator.generateWallet({ keyType: 'Ed25519' });
        generator.displayWallet(wallet);

        // Show statistics
        console.log('\nStatistics:');
        console.log(`Total wallets: ${generator.stats.generated}`);
        console.log(`Generation time: ${Date.now() - generator.stats.startTime.getTime()}ms`);

    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

// Export for module use
export { ICPWalletGenerator };

// Run the main function
main().catch(console.error); 