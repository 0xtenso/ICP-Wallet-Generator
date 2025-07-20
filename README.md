# ICP Wallet Generator

A comprehensive wallet generator for the Internet Computer Protocol (ICP) with full Internet Identity integration. Generate, restore, and manage ICP wallets with support for both Secp256k1 and Ed25519 cryptographic curves.

## Features

- Multiple Cryptographic Curves: Support for Secp256k1 and Ed25519
- BIP39 Mnemonic Generation: Standard 12, 15, 18, 21, or 24-word mnemonics
- Principal ID Generation: Compatible with ICP's addressing system
- Account Identifier Support: For ICP ledger transactions
- Internet Identity Integration: Native ICP authentication
- Vanity Address Generation: Create custom prefixed principals
- Batch Generation: Generate multiple wallets efficiently
- Wallet Restoration: From mnemonic phrases or private keys
- QR Code Support: Easy wallet sharing
- Interactive CLI: Beautiful command-line interface
- Export Formats: JSON, CSV, and minimal formats
- Comprehensive Testing: Full test suite included

## Installation

### Prerequisites

- Node.js 18.0.0 or higher
- npm or yarn package manager

### Install Dependencies

```bash
# Clone or download the project
npm install

# Or install globally (after publishing)
npm install -g icp-wallet-generator
```

## Quick Start

### Command Line Interface

```bash
# Start interactive CLI
npm start

# Or directly
node src/index.js cli
```

### Programmatic Usage

```javascript
import { generateWallet, restoreWallet } from './src/index.js';

// Generate a new wallet
const wallet = await generateWallet({
  curve: 'secp256k1',
  mnemonicLength: 12
});

console.log('Principal:', wallet.principal.text);
console.log('Account ID:', wallet.accountIdentifier.text);
console.log('Mnemonic:', wallet.mnemonic);
```

## Usage Examples

### 1. Generate Single Wallet

```javascript
import { ICPWalletGenerator } from './src/wallet-generator.js';

const generator = new ICPWalletGenerator();

// Generate with Secp256k1 curve and 12-word mnemonic
const wallet = await generator.generateWallet('secp256k1', 12);

console.log({
  mnemonic: wallet.mnemonic,
  principal: wallet.principal.text,
  accountId: wallet.accountIdentifier.text,
  privateKey: wallet.keys.privateKey,
  publicKey: wallet.keys.publicKey,
  curve: wallet.keys.curve
});
```

### 2. Generate Multiple Wallets

```javascript
const wallets = await generator.generateBatchWallets(5, 'secp256k1', 12);

wallets.forEach((wallet, i) => {
  console.log(`Wallet ${i + 1}: ${wallet.principal.text}`);
});
```

### 3. Restore Wallet from Mnemonic

```javascript
const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const restoredWallet = await generator.createWalletFromMnemonic(mnemonic, 'secp256k1');

console.log('Restored Principal:', restoredWallet.principal.text);
```

### 4. Import Wallet from Private Key

```javascript
const privateKey = "your-private-key-hex";
const importedWallet = await generator.createWalletFromPrivateKey(privateKey, 'secp256k1');

console.log('Imported Principal:', importedWallet.principal.text);
```

### 5. Generate Vanity Wallet

```javascript
// Generate wallet with custom prefix
const vanityWallet = await generator.generateVanityWallet('abc', 'secp256k1', 10000);

console.log('Vanity Principal:', vanityWallet.principal.text);
console.log('Attempts Required:', vanityWallet.attemptsRequired);
```

### 6. Internet Identity Integration

```javascript
import { InternetIdentityManager } from './src/internet-identity.js';

const ii = new InternetIdentityManager({
  // For mainnet: 'https://identity.ic0.app'
  identityProvider: 'http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:4943'
});

// Initialize
await ii.initialize();

// Check authentication
const isAuthenticated = await ii.isAuthenticated();

if (!isAuthenticated) {
  // Login (browser environment only)
  const result = await ii.login();
  console.log('Logged in as:', result.principal);
}

// Get current principal
const principal = await ii.getCurrentPrincipal();
console.log('Current Principal:', principal.toString());
```

## Command Line Usage

### Interactive CLI

```bash
node src/index.js cli
```

The CLI provides an interactive menu with the following options:

- Generate New Wallet
- Generate Multiple Wallets  
- Restore Wallet from Mnemonic
- Import Wallet from Private Key
- Generate Vanity Wallet
- Internet Identity Demo
- Validate Address/Mnemonic

### Direct Commands

```bash
# Generate single wallet
node src/index.js generate --curve secp256k1 --length 12

# Generate multiple wallets
node src/index.js batch 5 --curve ed25519 --length 24

# Run examples
node src/index.js examples

# Show help
node src/index.js --help
```

## API Reference

### ICPWalletGenerator

#### `generateWallet(curve, mnemonicLength)`

Generate a new wallet with mnemonic phrase.

- `curve`: `'secp256k1'` | `'ed25519'`
- `mnemonicLength`: `12` | `15` | `18` | `21` | `24`

Returns: `Promise<WalletObject>`

#### `createWalletFromMnemonic(mnemonic, curve)`

Restore wallet from existing mnemonic phrase.

- `mnemonic`: BIP39 mnemonic phrase string
- `curve`: Cryptographic curve to use

Returns: `Promise<WalletObject>`

#### `createWalletFromPrivateKey(privateKeyHex, curve)`

Import wallet from private key.

- `privateKeyHex`: Private key in hexadecimal format
- `curve`: Cryptographic curve to use

Returns: `Promise<WalletObject>`

#### `generateBatchWallets(count, curve, mnemonicLength)`

Generate multiple wallets in batch.

- `count`: Number of wallets to generate
- `curve`: Cryptographic curve to use  
- `mnemonicLength`: Mnemonic length

Returns: `Promise<WalletObject[]>`

#### `generateVanityWallet(prefix, curve, maxAttempts)`

Generate wallet with custom principal prefix.

- `prefix`: Desired prefix (2-5 characters)
- `curve`: Cryptographic curve to use
- `maxAttempts`: Maximum generation attempts

Returns: `Promise<VanityWalletObject>`

### InternetIdentityManager

#### `initialize()`

Initialize the Internet Identity client.

Returns: `Promise<void>`

#### `login(options)`

Login with Internet Identity (browser only).

- `options`: Login configuration options

Returns: `Promise<AuthResult>`

#### `logout()`

Logout from Internet Identity.

Returns: `Promise<void>`

#### `isAuthenticated()`

Check if user is currently authenticated.

Returns: `Promise<boolean>`

#### `getCurrentPrincipal()`

Get the current user's principal.

Returns: `Promise<Principal|null>`

#### `createActor(canisterId, interfaceFactory, options)`

Create an actor for canister interaction.

- `canisterId`: Target canister ID
- `interfaceFactory`: Candid interface factory
- `options`: Additional configuration

Returns: `Promise<Actor>`

## Wallet Object Structure

```javascript
{
  mnemonic: "twelve word mnemonic phrase...",
  principal: {
    text: "principal-id-string",
    bytes: Uint8Array
  },
  accountIdentifier: {
    text: "account-id-hex-string", 
    bytes: Uint8Array
  },
  keys: {
    privateKey: "private-key-hex",
    publicKey: "public-key-hex",
    curve: "secp256k1" | "ed25519"
  },
  identity: Identity, // DFINITY Identity object
  createdAt: "2023-01-01T00:00:00.000Z"
}
```

## Environment Configuration

### Local Development

```javascript
const ii = new InternetIdentityManager({
  identityProvider: 'http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:4943'
});
```

### Production/Mainnet

```javascript
const ii = new InternetIdentityManager({
  identityProvider: 'https://identity.ic0.app'
});
```

## Testing

Run the comprehensive test suite:

```bash
npm test
# or
node src/test.js
```

Tests cover:
- Wallet generation (both curves)
- Wallet restoration  
- Private key import
- Batch generation
- Validation functions
- Export functionality
- Internet Identity integration
- Error handling
- Performance metrics

## Security Considerations

Important Security Notes:

1. Never share your private keys or mnemonic phrases
2. Store wallet data securely offline
3. Use hardware wallets for large amounts
4. Verify all addresses before sending funds
5. Keep your recovery phrases in multiple secure locations

### Best Practices

- Generate wallets on offline devices when possible
- Use strong, unique passwords for encrypted storage
- Regularly backup your wallet data
- Test recovery procedures with small amounts first
- Keep software and dependencies updated

## Integration Examples

### Web Application

```html
<!DOCTYPE html>
<html>
<head>
    <title>ICP Wallet App</title>
</head>
<body>
    <button id="login">Login with Internet Identity</button>
    <button id="generate">Generate Wallet</button>
    
    <script type="module">
        import { InternetIdentityManager, ICPWalletGenerator } from './src/index.js';
        
        const ii = new InternetIdentityManager();
        const generator = new ICPWalletGenerator();
        
        document.getElementById('login').onclick = async () => {
            await ii.initialize();
            const result = await ii.login();
            console.log('Logged in:', result.principal);
        };
        
        document.getElementById('generate').onclick = async () => {
            const wallet = await generator.generateWallet('secp256k1', 12);
            console.log('Generated wallet:', wallet.principal.text);
        };
    </script>
</body>
</html>
```

### Node.js Backend

```javascript
import { ICPWalletGenerator } from './src/wallet-generator.js';
import express from 'express';

const app = express();
const generator = new ICPWalletGenerator();

app.post('/generate-wallet', async (req, res) => {
  try {
    const { curve = 'secp256k1', length = 12 } = req.body;
    const wallet = await generator.generateWallet(curve, length);
    
    // Never send private keys in production!
    res.json({
      principal: wallet.principal.text,
      accountId: wallet.accountIdentifier.text
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000);
```

## Troubleshooting

### Common Issues

1. Module import errors
   - Ensure you're using Node.js 18+ with ES modules support
   - Check that `"type": "module"` is in package.json

2. Internet Identity not working
   - Verify the correct identity provider URL for your environment
   - Ensure you're running in a browser environment for authentication

3. Invalid mnemonic errors 
   - Check that the mnemonic has the correct number of words
   - Verify words are from the BIP39 wordlist

4. Principal validation fails
   - Ensure the principal string is properly formatted
   - Check for any extra whitespace or invalid characters

### Getting Help

- Check the [Internet Computer documentation](https://internetcomputer.org/docs)
- Review the test files for usage examples
- Open an issue if you find bugs or need features

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality  
5. Ensure all tests pass
6. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- [DFINITY Foundation](https://dfinity.org/) for the Internet Computer protocol
- [Internet Computer SDK](https://github.com/dfinity/sdk) for development tools
- [agent-js](https://github.com/dfinity/agent-js) for ICP interaction libraries