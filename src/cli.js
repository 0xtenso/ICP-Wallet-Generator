#!/usr/bin/env node

import inquirer from 'inquirer';
import chalk from 'chalk';
import QRCode from 'qrcode';
import fs from 'fs/promises';
import path from 'path';
import { ICPWalletGenerator } from './wallet-generator.js';
import { InternetIdentityManager } from './internet-identity.js';

class ICPWalletCLI {
  constructor() {
    this.walletGenerator = new ICPWalletGenerator();
    this.internetIdentity = new InternetIdentityManager();
  }

  /**
   * Display the main menu
   */
  async showMainMenu() {
    console.log("ICP Wallet Generator");

    const { action } = await inquirer.prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: 'Generate New Wallet', value: 'generate' },
          { name: 'Generate Multiple Wallets', value: 'batch' },
          { name: 'Restore Wallet from Mnemonic', value: 'restore' },
          { name: 'Import Wallet from Private Key', value: 'import' },
          { name: 'Generate Vanity Wallet', value: 'vanity' },
          { name: 'Internet Identity Demo', value: 'internet-identity' },
          { name: 'Validate Address/Mnemonic', value: 'validate' },
          { name: 'Exit', value: 'exit' }
        ]
      }
    ]);

    switch (action) {
      case 'generate':
        await this.generateSingleWallet();
        break;
      case 'batch':
        await this.generateBatchWallets();
        break;
      case 'restore':
        await this.restoreWallet();
        break;
      case 'import':
        await this.importWallet();
        break;
      case 'vanity':
        await this.generateVanityWallet();
        break;
      case 'internet-identity':
        await this.internetIdentityDemo();
        break;
      case 'validate':
        await this.validateInputs();
        break;
      case 'exit':
        process.exit(0);
        break;
    }
  }

  /**
   * Generate a single wallet
   */
  async generateSingleWallet() {
    try {
      const { curve, mnemonicLength } = await inquirer.prompt([
        {
          type: 'list',
          name: 'curve',
          message: 'Choose cryptographic curve:',
          choices: [
            { name: 'Secp256k1 (Bitcoin/Ethereum compatible)', value: 'secp256k1' },
            { name: 'Ed25519 (Modern, faster)', value: 'ed25519' }
          ]
        },
        {
          type: 'list',
          name: 'mnemonicLength',
          message: 'Choose mnemonic length:',
          choices: [
            { name: '12 words (128-bit entropy)', value: 12 },
            { name: '15 words (160-bit entropy)', value: 15 },
            { name: '18 words (192-bit entropy)', value: 18 },
            { name: '21 words (224-bit entropy)', value: 21 },
            { name: '24 words (256-bit entropy)', value: 24 }
          ]
        }
      ]);

      console.log(chalk.yellow('\nGenerating wallet...'));
      const wallet = await this.walletGenerator.generateWallet(curve, mnemonicLength);

      await this.displayWallet(wallet);
      await this.saveWalletPrompt(wallet);

    } catch (error) {
      console.error(chalk.red(`Error generating wallet: ${error.message}`));
    }

    await this.backToMenu();
  }

  /**
   * Generate multiple wallets
   */
  async generateBatchWallets() {
    try {
      const { count, curve, mnemonicLength } = await inquirer.prompt([
        {
          type: 'number',
          name: 'count',
          message: 'How many wallets to generate?',
          default: 5,
          validate: (value) => value > 0 && value <= 100 ? true : 'Please enter a number between 1 and 100'
        },
        {
          type: 'list',
          name: 'curve',
          message: 'Choose cryptographic curve:',
          choices: [
            { name: 'Secp256k1', value: 'secp256k1' },
            { name: 'Ed25519', value: 'ed25519' }
          ]
        },
        {
          type: 'list',
          name: 'mnemonicLength',
          message: 'Choose mnemonic length:',
          choices: [
            { name: '12 words', value: 12 },
            { name: '24 words', value: 24 }
          ]
        }
      ]);

      console.log(chalk.yellow(`\nGenerating ${count} wallets...`));
      const wallets = await this.walletGenerator.generateBatchWallets(count, curve, mnemonicLength);

      // Display summary
      console.log(chalk.green(`\nGenerated ${count} wallets successfully!\n`));
      
      wallets.forEach((wallet, index) => {
        console.log(chalk.cyan(`Wallet ${index + 1}:`));
        console.log(`  Principal: ${wallet.principal.text}`);
        console.log(`  Account:   ${wallet.accountIdentifier.text}`);
        console.log('');
      });

      await this.saveBatchWalletsPrompt(wallets);

    } catch (error) {
      console.error(chalk.red(`Error generating batch wallets: ${error.message}`));
    }

    await this.backToMenu();
  }

  /**
   * Restore wallet from mnemonic
   */
  async restoreWallet() {
    try {
      const { mnemonic, curve } = await inquirer.prompt([
        {
          type: 'input',
          name: 'mnemonic',
          message: 'Enter your mnemonic phrase:',
          validate: (value) => {
            if (!value.trim()) return 'Mnemonic phrase is required';
            if (!this.walletGenerator.validateMnemonic(value.trim())) {
              return 'Invalid mnemonic phrase';
            }
            return true;
          }
        },
        {
          type: 'list',
          name: 'curve',
          message: 'Choose cryptographic curve:',
          choices: [
            { name: 'Secp256k1', value: 'secp256k1' },
            { name: 'Ed25519', value: 'ed25519' }
          ]
        }
      ]);

      console.log(chalk.yellow('\nRestoring wallet...'));
      const wallet = await this.walletGenerator.createWalletFromMnemonic(mnemonic.trim(), curve);
      wallet.mnemonic = mnemonic.trim();
      wallet.curve = curve;

      await this.displayWallet(wallet);

    } catch (error) {
      console.error(chalk.red(`Error restoring wallet: ${error.message}`));
    }

    await this.backToMenu();
  }

  /**
   * Import wallet from private key
   */
  async importWallet() {
    try {
      const { privateKey, curve } = await inquirer.prompt([
        {
          type: 'input',
          name: 'privateKey',
          message: 'Enter private key (hex format):',
          validate: (value) => {
            if (!value.trim()) return 'Private key is required';
            if (!/^[0-9a-fA-F]+$/.test(value.trim())) {
              return 'Private key must be in hex format';
            }
            return true;
          }
        },
        {
          type: 'list',
          name: 'curve',
          message: 'Choose cryptographic curve:',
          choices: [
            { name: 'Secp256k1', value: 'secp256k1' },
            { name: 'Ed25519', value: 'ed25519' }
          ]
        }
      ]);

      console.log(chalk.yellow('\nImporting wallet...'));
      const wallet = await this.walletGenerator.createWalletFromPrivateKey(privateKey.trim(), curve);

      await this.displayWallet(wallet);

    } catch (error) {
      console.error(chalk.red(`Error importing wallet: ${error.message}`));
    }

    await this.backToMenu();
  }

  /**
   * Generate vanity wallet
   */
  async generateVanityWallet() {
    try {
      const { prefix, curve, maxAttempts } = await inquirer.prompt([
        {
          type: 'input',
          name: 'prefix',
          message: 'Enter desired prefix for principal (2-5 characters):',
          validate: (value) => {
            if (!value.trim()) return 'Prefix is required';
            if (value.trim().length < 2 || value.trim().length > 5) {
              return 'Prefix must be 2-5 characters long';
            }
            return true;
          }
        },
        {
          type: 'list',
          name: 'curve',
          message: 'Choose cryptographic curve:',
          choices: [
            { name: 'Secp256k1', value: 'secp256k1' },
            { name: 'Ed25519', value: 'ed25519' }
          ]
        },
        {
          type: 'number',
          name: 'maxAttempts',
          message: 'Maximum attempts (higher = more likely to find, but slower):',
          default: 10000,
          validate: (value) => value > 0 && value <= 100000 ? true : 'Please enter a number between 1 and 100,000'
        }
      ]);

      console.log(chalk.yellow(`\n🔄 Searching for vanity wallet with prefix "${prefix.trim()}"...`));
      console.log(chalk.gray('This may take a while depending on the prefix and max attempts.'));

      const wallet = await this.walletGenerator.generateVanityWallet(prefix.trim(), curve, maxAttempts);

      console.log(chalk.green(`\n🎉 Found vanity wallet after ${wallet.attemptsRequired} attempts!`));
      await this.displayWallet(wallet);

    } catch (error) {
      console.error(chalk.red(`❌ Error generating vanity wallet: ${error.message}`));
    }

    await this.backToMenu();
  }

  /**
   * Internet Identity demo
   */
  async internetIdentityDemo() {
    console.log(chalk.blue('\nInternet Identity Demo'));
    console.log(chalk.gray('Note: This demo is configured for local development.'));
    console.log(chalk.gray('For production, update the identity provider URL.\n'));

    try {
      // Check if already authenticated
      const isAuth = await this.internetIdentity.isAuthenticated();
      
      if (isAuth) {
        console.log(chalk.green('Already authenticated!'));
        const walletInfo = await this.internetIdentity.getWalletInfo();
        console.log(chalk.cyan(`Principal: ${walletInfo.principal}`));
        
        const { action } = await inquirer.prompt([
          {
            type: 'list',
            name: 'action',
            message: 'What would you like to do?',
            choices: [
              { name: 'View wallet info', value: 'info' },
              { name: 'Logout', value: 'logout' },
              { name: 'Back to main menu', value: 'back' }
            ]
          }
        ]);

        if (action === 'logout') {
          await this.internetIdentity.logout();
          console.log(chalk.green('Logged out successfully'));
        }
      } else {
        console.log(chalk.yellow('Not authenticated. Login requires a browser.'));
        console.log(chalk.gray('In a real web application, this would open Internet Identity.'));
        
        // For CLI demo, we'll show what the process would be
        console.log(chalk.blue('\nInternet Identity Login Process:'));
        console.log('1. User clicks "Login with Internet Identity"');
        console.log('2. Browser redirects to Internet Identity');
        console.log('3. User authenticates with passkey/biometric');
        console.log('4. User gets redirected back with authentication');
        console.log('5. App can now make authenticated calls');
      }

    } catch (error) {
      console.error(chalk.red(`Internet Identity error: ${error.message}`));
    }

    await this.backToMenu();
  }

  /**
   * Validate inputs
   */
  async validateInputs() {
    const { inputType } = await inquirer.prompt([
      {
        type: 'list',
        name: 'inputType',
        message: 'What would you like to validate?',
        choices: [
          { name: 'Mnemonic phrase', value: 'mnemonic' },
          { name: 'Principal ID', value: 'principal' }
        ]
      }
    ]);

    if (inputType === 'mnemonic') {
      const { mnemonic } = await inquirer.prompt([
        {
          type: 'input',
          name: 'mnemonic',
          message: 'Enter mnemonic phrase to validate:'
        }
      ]);

      const isValid = this.walletGenerator.validateMnemonic(mnemonic.trim());
      console.log(isValid 
        ? chalk.green('Valid mnemonic phrase')
        : chalk.red('Invalid mnemonic phrase')
      );
    } else {
      const { principal } = await inquirer.prompt([
        {
          type: 'input',
          name: 'principal',
          message: 'Enter principal ID to validate:'
        }
      ]);

      const isValid = this.walletGenerator.validatePrincipal(principal.trim());
      console.log(isValid 
        ? chalk.green('Valid principal ID')
        : chalk.red('Invalid principal ID')
      );
    }

    await this.backToMenu();
  }

  /**
   * Display wallet information
   */
  async displayWallet(wallet) {
    console.log(chalk.green('\nWallet generated successfully!\n'));
    
    console.log(chalk.cyan.bold('Wallet Information:'));
    console.log(chalk.cyan('├─ Mnemonic:     ') + chalk.white(wallet.mnemonic || 'N/A'));
    console.log(chalk.cyan('├─ Principal:    ') + chalk.white(wallet.principal.text));
    console.log(chalk.cyan('├─ Account ID:   ') + chalk.white(wallet.accountIdentifier.text));
    console.log(chalk.cyan('├─ Private Key:  ') + chalk.white(wallet.keys.privateKey));
    console.log(chalk.cyan('├─ Public Key:   ') + chalk.white(wallet.keys.publicKey));
    console.log(chalk.cyan('└─ Curve:        ') + chalk.white(wallet.keys.curve));

    // Generate QR code for principal
    try {
      const qrCode = await QRCode.toString(wallet.principal.text, { type: 'terminal' });
      console.log(chalk.cyan('\nPrincipal QR Code:'));
      console.log(qrCode);
    } catch (error) {
      console.log(chalk.gray('Could not generate QR code'));
    }

    // Security warning
    console.log(chalk.red.bold('\nSECURITY WARNING:'));
    console.log(chalk.red('• Never share your private key or mnemonic phrase'));
    console.log(chalk.red('• Store them securely offline'));
    console.log(chalk.red('• Anyone with access to these can control your wallet'));
  }

  /**
   * Prompt to save wallet
   */
  async saveWalletPrompt(wallet) {
    const { shouldSave } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'shouldSave',
        message: 'Save wallet to file?',
        default: false
      }
    ]);

    if (shouldSave) {
      await this.saveWallet(wallet);
    }
  }

  /**
   * Prompt to save batch wallets
   */
  async saveBatchWalletsPrompt(wallets) {
    const { shouldSave, format } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'shouldSave',
        message: 'Save wallets to file?',
        default: true
      },
      {
        type: 'list',
        name: 'format',
        message: 'Choose format:',
        choices: [
          { name: 'JSON', value: 'json' },
          { name: 'CSV', value: 'csv' }
        ],
        when: (answers) => answers.shouldSave
      }
    ]);

    if (shouldSave) {
      await this.saveBatchWallets(wallets, format);
    }
  }

  /**
   * Save single wallet to file
   */
  async saveWallet(wallet) {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `icp-wallet-${timestamp}.json`;
      const walletData = this.walletGenerator.exportWallet(wallet, 'json');
      
      await fs.writeFile(filename, walletData);
      console.log(chalk.green(`Wallet saved to ${filename}`));
    } catch (error) {
      console.error(chalk.red(`Error saving wallet: ${error.message}`));
    }
  }

  /**
   * Save batch wallets to file
   */
  async saveBatchWallets(wallets, format) {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const filename = `icp-wallets-${timestamp}.${format}`;
      
      let content;
      if (format === 'json') {
        content = JSON.stringify(wallets.map(w => this.walletGenerator.formatWalletInfo(w)), null, 2);
      } else {
        // CSV format
        const headers = 'index,mnemonic,principal,accountIdentifier,privateKey,publicKey,curve,createdAt';
        const rows = wallets.map(w => {
          const info = this.walletGenerator.formatWalletInfo(w);
          return `${w.index},"${info.mnemonic}",${info.principal},${info.accountIdentifier},${info.privateKey},${info.publicKey},${info.curve},${info.createdAt}`;
        });
        content = headers + '\n' + rows.join('\n');
      }
      
      await fs.writeFile(filename, content);
      console.log(chalk.green(`Wallets saved to ${filename}`));
    } catch (error) {
      console.error(chalk.red(`Error saving wallets: ${error.message}`));
    }
  }

  /**
   * Back to menu prompt
   */
  async backToMenu() {
    await inquirer.prompt([
      {
        type: 'input',
        name: 'continue',
        message: 'Press Enter to continue...'
      }
    ]);
    
    await this.showMainMenu();
  }

  /**
   * Start the CLI application
   */
  async start() {
    try {
      await this.showMainMenu();
    } catch (error) {
      console.error(chalk.red('Fatal error:'), error.message);
      process.exit(1);
    }
  }
}

// Start the CLI if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const cli = new ICPWalletCLI();
  cli.start();
}

export default ICPWalletCLI; 