import { randomBytes } from 'crypto';
import { ed25519 } from '@noble/ed25519';
import { secp256k1 } from '@noble/secp256k1';
import { sha224 } from '@noble/hashes/sha224';
import { crc32 } from 'crc';
import * as bip39 from 'bip39';

class ICPWalletGenerator {
    constructor() {
        this.generatedWallets = [];
        this.stats = { generated: 0, startTime: new Date() };
    }

    // Generate secure random seed
    generateRandomSeed(length = 32) {
        return randomBytes(length);
    }

    // Generate mnemonic and derive seed
    generateMnemonicSeed(mnemonic = null) {
        if (!mnemonic) {
            mnemonic = bip39.generateMnemonic();
        }
        if (!bip39.validateMnemonic(mnemonic)) {
            throw new Error('Invalid mnemonic phrase');
        }
        const seed = bip39.mnemonicToSeedSync(mnemonic);
        return { mnemonic, seed: new Uint8Array(seed.slice(0, 32)) };
    }

    // Generate Ed25519 key pair
    async generateEd25519KeyPair(seed) {
        if (seed.length !== 32) throw new Error('Seed must be exactly 32 bytes');
        const privateKey = seed;
        const publicKey = await ed25519.getPublicKey(privateKey);
        return {
            privateKey: new Uint8Array(privateKey),
            publicKey: new Uint8Array(publicKey),
            keyType: 'Ed25519'
        };
    }

    // Generate Secp256k1 key pair
    generateSecp256k1KeyPair(seed) {
        if (seed.length !== 32) throw new Error('Seed must be exactly 32 bytes');
        const privateKey = seed;
        const publicKey = secp256k1.getPublicKey(privateKey, false); // Uncompressed
        return {
            privateKey: new Uint8Array(privateKey),
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

        // Generate seed based on method
        switch (seedMethod) {
            case 'random':
                seed = this.generateRandomSeed();
                break;
            case 'mnemonic':
                const mnemonicResult = this.generateMnemonicSeed(mnemonic);
                seed = mnemonicResult.seed;
                mnemonicPhrase = mnemonicResult.mnemonic;
                break;
            case 'custom':
                if (!customSeed) throw new Error('Custom seed is required');
                seed = typeof customSeed === 'string' ? this.hexToBytes(customSeed) : new Uint8Array(customSeed);
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
        // Generate Ed25519 wallet with random seed
        console.log('Generating Ed25519 wallet...');
        const wallet1 = await generator.generateWallet({ keyType: 'Ed25519' });
        generator.displayWallet(wallet1);

        // Generate Secp256k1 wallet with mnemonic
        console.log('\nGenerating Secp256k1 wallet with mnemonic...');
        const wallet2 = await generator.generateWallet({ 
            keyType: 'Secp256k1', 
            seedMethod: 'mnemonic' 
        });
        generator.displayWallet(wallet2);

        // Generate 3 more wallets
        console.log('\nGenerating 3 additional wallets...');
        const additionalWallets = await generator.generateMultipleWallets(3, { keyType: 'Ed25519' });
        additionalWallets.forEach(wallet => generator.displayWallet(wallet));

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

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(console.error);
} 