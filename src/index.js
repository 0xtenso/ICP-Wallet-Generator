#!/usr/bin/env node

import { ICPWalletGenerator } from './wallet-generator.js';
import { InternetIdentityManager } from './internet-identity.js';
import ICPWalletCLI from './cli.js';

// Export all classes for programmatic use
export { ICPWalletGenerator, InternetIdentityManager, ICPWalletCLI };

// Simple API for quick wallet generation
export const generateWallet = async (options = {}) => {
  const generator = new ICPWalletGenerator();
  return await generator.generateWallet(options.curve, options.mnemonicLength);
};

export const generateWallets = async (count = 1, options = {}) => {
  const generator = new ICPWalletGenerator();
  return await generator.generateBatchWallets(count, options.curve, options.mnemonicLength);
};

export const restoreWallet = async (mnemonic, curve = 'secp256k1') => {
  const generator = new ICPWalletGenerator();
  return await generator.createWalletFromMnemonic(mnemonic, curve);
};

export const importWallet = async (privateKey, curve = 'secp256k1') => {
  const generator = new ICPWalletGenerator();
  return await generator.createWalletFromPrivateKey(privateKey, curve);
};

// Example usage functions
export const examples = {
  async basicUsage() {
    // Generate a single wallet
    console.log('Generating a single wallet...');
    const wallet = await generateWallet({ curve: 'secp256k1', mnemonicLength: 12 });
    console.log('Principal:', wallet.principal.text);
    console.log('Account ID:', wallet.accountIdentifier.text);
    console.log('Mnemonic:', wallet.mnemonic);
    console.log('');
    
    // Generate multiple wallets
    console.log('Generating 3 wallets...');
    const wallets = await generateWallets(3, { curve: 'secp256k1', mnemonicLength: 12 });
    wallets.forEach((w, i) => {
      console.log(`Wallet ${i + 1}: ${w.principal.text}`);
    });
    console.log('');
    
    // Restore wallet from mnemonic
    console.log('Restoring wallet from mnemonic...');
    const restoredWallet = await restoreWallet(wallet.mnemonic, 'secp256k1');
    console.log('Restored Principal:', restoredWallet.principal.text);
    console.log('Match:', wallet.principal.text === restoredWallet.principal.text ? 'Success' : 'Failed');
    console.log('');
    
    return { wallet, wallets, restoredWallet };
  },

  async advancedUsage() {
    console.log('ICP Wallet Generator - Advanced Usage Examples\n');
    
    const generator = new ICPWalletGenerator();
    
    // Generate vanity wallet
    console.log('Generating vanity wallet with prefix "abc"...');
    try {
      const vanityWallet = await generator.generateVanityWallet('abc', 'secp256k1', 1000);
      console.log('Vanity Principal:', vanityWallet.principal.text);
      console.log('Attempts required:', vanityWallet.attemptsRequired);
    } catch (error) {
      console.log('Could not find vanity wallet in 1000 attempts');
    }
    console.log('');
    
    // Different curves
    console.log('Generating wallets with different curves...');
    const secp256k1Wallet = await generator.generateWallet('secp256k1', 12);
    const ed25519Wallet = await generator.generateWallet('ed25519', 12);
    
    console.log('Secp256k1 Principal:', secp256k1Wallet.principal.text);
    console.log('Ed25519 Principal:', ed25519Wallet.principal.text);
    console.log('');
    
    // Export wallet
    console.log('Export wallet in different formats...');
    const exportedJSON = generator.exportWallet(secp256k1Wallet, 'json');
    const exportedCSV = generator.exportWallet(secp256k1Wallet, 'csv');
    const exportedMinimal = generator.exportWallet(secp256k1Wallet, 'minimal');
    
    console.log('JSON format length:', exportedJSON.length);
    console.log('CSV format length:', exportedCSV.length);
    console.log('Minimal format:');
    console.log(exportedMinimal);
    console.log('');
    
    return { secp256k1Wallet, ed25519Wallet };
  },

  async internetIdentityDemo() {
    console.log('Internet Identity Integration Demo\n');
    
    const ii = new InternetIdentityManager();
    
    console.log('Environment:', ii.isLocalEnvironment() ? 'Local Development' : 'Production');
    console.log('Identity Provider:', ii.options.identityProvider);
    console.log('');
    
    // Initialize
    await ii.initialize();
    console.log('Internet Identity initialized');
    
    // Check authentication status
    const isAuth = await ii.isAuthenticated();
    console.log('Authentication status:', isAuth ? 'Authenticated' : 'Not authenticated');
    
    if (isAuth) {
      const principal = await ii.getCurrentPrincipal();
      console.log('Current Principal:', principal?.toString() || 'Unknown');
      
      const walletInfo = await ii.getWalletInfo();
      console.log('Wallet Info:', walletInfo);
    } else {
      console.log('To authenticate, use ii.login() in a browser environment');
    }
    console.log('');
    
    return ii;
  }
};

// Command line interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
ICP Wallet Generator

Usage:
  node src/index.js [command] [options]

Commands:
  cli              Start interactive CLI
  examples         Run usage examples
  generate         Generate a single wallet
  batch <count>    Generate multiple wallets
  
Options:
  --curve <curve>     Cryptographic curve (secp256k1|ed25519)
  --length <length>   Mnemonic length (12|15|18|21|24)
  --help, -h          Show this help
  
Examples:
  node src/index.js cli
  node src/index.js examples
  node src/index.js generate --curve secp256k1 --length 24
  node src/index.js batch 5 --curve ed25519
    `);
    process.exit(0);
  }
  
  const command = args[0] || 'cli';
  
  switch (command) {
    case 'cli':
      const cli = new ICPWalletCLI();
      cli.start();
      break;
      
    case 'examples':
      (async () => {
        try {
          await examples.basicUsage();
          await examples.advancedUsage();
          await examples.internetIdentityDemo();
        } catch (error) {
          console.error('Error:', error.message);
        }
      })();
      break;
      
    case 'generate':
      (async () => {
        try {
          const curveIndex = args.indexOf('--curve');
          const lengthIndex = args.indexOf('--length');
          
          const curve = curveIndex !== -1 ? args[curveIndex + 1] : 'secp256k1';
          const length = lengthIndex !== -1 ? parseInt(args[lengthIndex + 1]) : 12;
          
          console.log('Generating wallet...');
          const wallet = await generateWallet({ curve, mnemonicLength: length });
          
          console.log('\n✅ Wallet generated successfully!\n');
          console.log('=================================');
          console.log('Mnemonic      :', wallet.mnemonic);
          console.log('Principal     :', wallet.principal.text);
          console.log('Account ID    :', wallet.accountIdentifier.text);
          console.log('Private Key   :', wallet.keys.privateKey);
          console.log('Public Key    :', wallet.keys.publicKey || 'Not available');
          console.log('Curve         :', wallet.keys.curve);
          console.log('Created At    :', wallet.createdAt);
          console.log('=================================');
        } catch (error) {
          console.error('Error generating wallet:', error.message);
        }
      })();
      break;
      
    case 'batch':
      (async () => {
        try {
          const count = parseInt(args[1]) || 5;
          const curveIndex = args.indexOf('--curve');
          const lengthIndex = args.indexOf('--length');
          
          const curve = curveIndex !== -1 ? args[curveIndex + 1] : 'secp256k1';
          const length = lengthIndex !== -1 ? parseInt(args[lengthIndex + 1]) : 12;
          
          console.log(`Generating ${count} wallets...`);
          const wallets = await generateWallets(count, { curve, mnemonicLength: length });
          
          console.log(`\n✅ Generated ${count} wallets successfully!\n`);
          wallets.forEach((wallet, i) => {
            console.log(`Wallet ${i + 1}:`);
            console.log('  Principal :', wallet.principal.text);
            console.log('  Account ID:', wallet.accountIdentifier.text);
            console.log('  Mnemonic  :', wallet.mnemonic);
            console.log('  Curve     :', wallet.keys.curve);
            console.log('');
          });
        } catch (error) {
          console.error('Error generating wallets:', error.message);
        }
      })();
      break;
      
    default:
      console.log(`Unknown command: ${command}`);
      console.log('Use --help for usage information');
      process.exit(1);
  }
}

export default {
  ICPWalletGenerator,
  InternetIdentityManager,
  ICPWalletCLI,
  generateWallet,
  generateWallets,
  restoreWallet,
  importWallet,
  examples
}; 