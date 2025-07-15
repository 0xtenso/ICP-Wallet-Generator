# ICP Wallet Generator

A comprehensive Node.js tool for generating Internet Computer Protocol (ICP) wallets following the official ICP specifications. This tool generates cryptographic key pairs and derives ICP account identifiers according to the Internet Computer Protocol documentation.

## Features

- Ed25519 and Secp256k1 key pair generation
- Principal ID derivation from public keys using SHA-224
- Account ID calculation with CRC32 checksum following ICP specs
- Subaccount support for multiple accounts per principal
- Mnemonic phrase support (BIP39 compatible)
- Multiple seed methods (random, mnemonic, custom)
- Secure client-side generation - no network communication
- JSON export functionality
- Command-line interface

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd ICP-Wallet-Generator

# Install dependencies
npm install

# Make the script executable (optional)
chmod +x wallet-generator.js
```

## Usage

### Command Line Usage

```bash
# Run directly with Node.js
node wallet-generator.js

# Or if made executable
./wallet-generator.js
```

### Programmatic Usage

```javascript
import { ICPWalletGenerator } from './wallet-generator.js';

const generator = new ICPWalletGenerator();

// Generate a wallet with default settings (Ed25519, random seed)
const wallet = await generator.generateWallet();

// Generate with specific options
const wallet2 = await generator.generateWallet({
    keyType: 'Secp256k1',
    seedMethod: 'mnemonic',
    mnemonic: 'your twelve word mnemonic phrase here...'
});

// Generate with custom subaccount
const wallet3 = await generator.generateWallet({
    keyType: 'Ed25519',
    subaccount: '0000000000000000000000000000000000000000000000000000000000000001'
});

// Display wallet information
generator.displayWallet(wallet);
```

### Generation Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keyType` | string | `'Ed25519'` | Key algorithm: `'Ed25519'` or `'Secp256k1'` |
| `seedMethod` | string | `'random'` | Seed generation: `'random'`, `'mnemonic'`, or `'custom'` |
| `mnemonic` | string | `null` | BIP39 mnemonic phrase (for `seedMethod: 'mnemonic'`) |
| `customSeed` | string/Uint8Array | `null` | Custom 32-byte seed (for `seedMethod: 'custom'`) |
| `subaccount` | string/Uint8Array | `null` | 32-byte subaccount identifier |

## Output Format

Each generated wallet contains:

```javascript
{
    index: 1,
    keyType: 'Ed25519',
    seed: {
        hex: '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d',
        mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    },
    privateKey: '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d',
    publicKey: 'f25c0fc2e2b9c033ee4b93b5b8da5b807c5b8b6b6b8b8b8b8b8b8b8b8b8b8b8b',
    principalId: {
        bytes: 'a1b2c3d4e5f6789abcdef01234567890abcdef01234567890abcdef',
        text: 'rdmx6-jaaaa-aaaaa-aaadq-cai'
    },
    accountId: 'a1b2c3d4e5f6789abcdef01234567890abcdef01234567890abcdef01234567890',
    subaccount: '0000000000000000000000000000000000000000000000000000000000000000',
    createdAt: '2025-01-27T10:30:00.000Z'
}
```

## Technical Implementation

### Principal ID Derivation

Following the ICP specification:
1. DER encode the public key with appropriate OID
2. Calculate SHA-224 hash of the DER-encoded key
3. Append 0x02 suffix for self-authenticating principal

```
principal_id = SHA-224(DER_encoded_public_key) · 0x02
```

### Account ID Calculation

Following the ICP ledger specification:
1. Create domain separator: `\x0Aaccount-id`
2. Concatenate: `domain_separator || principal_id || subaccount`
3. Calculate SHA-224 hash
4. Calculate CRC32 checksum of the hash
5. Combine: `CRC32(hash) || hash`

```
hash = SHA-224("\x0Aaccount-id" || principal || subaccount)
account_id = CRC32(hash) || hash
```

### Key Types Supported

Ed25519 (Recommended)
- Curve: Ed25519
- Key size: 32 bytes private, 32 bytes public
- OID: 1.3.101.112

Secp256k1
- Curve: secp256k1 (same as Bitcoin)
- Key size: 32 bytes private, 65 bytes public (uncompressed)
- OID: 1.2.840.10045.3.1.7

## Security Notes

Important Security Considerations:

1. Private Key Security: Never share or expose private keys publicly
2. Seed Phrase Security: Store mnemonic phrases securely offline
3. Client-Side Generation: All keys are generated locally - no network communication
4. Verify Addresses: Always verify generated addresses before using them
5. Backup: Keep secure backups of all wallet information

## Dependencies

- `@noble/ed25519` - Ed25519 cryptographic operations
- `@noble/secp256k1` - Secp256k1 cryptographic operations  
- `@noble/hashes` - SHA-224 hashing
- `crc` - CRC32 checksum calculation
- `bip39` - Mnemonic phrase generation and validation

## Examples

### Generate Multiple Wallets

```javascript
const generator = new ICPWalletGenerator();

// Generate 5 Ed25519 wallets
for (let i = 0; i < 5; i++) {
    const wallet = await generator.generateWallet({ keyType: 'Ed25519' });
    generator.displayWallet(wallet);
}
```

### Use Custom Seed

```javascript
const customSeed = '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d';
const wallet = await generator.generateWallet({
    keyType: 'Ed25519',
    seedMethod: 'custom',
    customSeed: customSeed
});
```

### Generate with Mnemonic

```javascript
const wallet = await generator.generateWallet({
    keyType: 'Secp256k1',
    seedMethod: 'mnemonic',
    mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
});
```

## Testing

```bash
npm test
```

## References

- [Internet Computer Documentation](https://internetcomputer.org/docs)
- [ICP Ledger Specification](https://internetcomputer.org/docs/references/ledger)
- [Internet Identity Specification](https://internetcomputer.org/docs/references/ii-spec)