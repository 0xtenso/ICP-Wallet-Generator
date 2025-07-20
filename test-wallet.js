#!/usr/bin/env node

import { ICPWalletGenerator } from './src/wallet-generator.js';

async function testWallet() {
  try {
    console.log('ICP Wallet Generator\n');
    
    const generator = new ICPWalletGenerator();
    
    // Generate a simple wallet
    console.log('Generating wallet');
    const wallet = await generator.generateWallet('secp256k1', 12);
    
    console.log('\nWallet Generated Successfully!\n');
    console.log('Mnemonic      :', wallet.mnemonic);
    console.log('Principal     :', wallet.principal.text);
    console.log('Account ID    :', wallet.accountIdentifier.text);
    console.log('Private Key   :', wallet.keys.privateKey);
    console.log('Public Key    :', wallet.keys.publicKey || 'Not available');
    console.log('Curve         :', wallet.keys.curve);
    console.log('Created At    :', wallet.createdAt);
    
    // Test restore functionality
    console.log('Wallet restoration');
    const restored = await generator.createWalletFromMnemonic(wallet.mnemonic, 'secp256k1');
    
    const match = wallet.principal.text === restored.principal.text;
    console.log('Restoration test:', match ? 'SUCCESS' : 'FAILED');
    console.log('Original Principal :', wallet.principal.text);
    console.log('Restored Principal :', restored.principal.text);
    
    if (match) {
      console.log('\nAll tests passed! Your ICP wallet generator is working correctly.\n');
    }
    
  } catch (error) {
    console.error('Error:', error.message);
    console.error('Stack:', error.stack);
  }
}

testWallet(); 