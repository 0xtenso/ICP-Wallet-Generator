import { AuthClient } from '@dfinity/auth-client';
import { HttpAgent, Actor } from '@dfinity/agent';
import { Principal } from '@dfinity/principal';

export class InternetIdentityManager {
  constructor(options = {}) {
    this.authClient = null;
    this.isInitialized = false;
    this.options = {
      // Default to local development, change to production for mainnet
      identityProvider: options.identityProvider || 'http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:4943',
      // For production use: 'https://identity.ic0.app'
      maxTimeToLive: options.maxTimeToLive || BigInt(8 * 60 * 60 * 1000 * 1000 * 1000), // 8 hours
      ...options
    };
  }

  /**
   * Initialize the Internet Identity client
   * @returns {Promise<void>}
   */
  async initialize() {
    if (this.isInitialized) {
      return;
    }

    try {
      this.authClient = await AuthClient.create({
        idleOptions: {
          disableIdle: true,
          disableDefaultIdleCallback: true
        }
      });
      this.isInitialized = true;
    } catch (error) {
      throw new Error(`Failed to initialize Internet Identity: ${error.message}`);
    }
  }

  /**
   * Check if user is currently authenticated
   * @returns {Promise<boolean>}
   */
  async isAuthenticated() {
    await this.initialize();
    return await this.authClient.isAuthenticated();
  }

  /**
   * Get the current user's principal
   * @returns {Promise<Principal|null>}
   */
  async getCurrentPrincipal() {
    await this.initialize();
    
    if (await this.isAuthenticated()) {
      const identity = this.authClient.getIdentity();
      return identity.getPrincipal();
    }
    
    return null;
  }

  /**
   * Login with Internet Identity
   * @param {Object} options - Login options
   * @returns {Promise<Object>} Authentication result
   */
  async login(options = {}) {
    await this.initialize();

    return new Promise((resolve, reject) => {
      this.authClient.login({
        identityProvider: this.options.identityProvider,
        maxTimeToLive: this.options.maxTimeToLive,
        onSuccess: async () => {
          try {
            const identity = this.authClient.getIdentity();
            const principal = identity.getPrincipal();
            
            resolve({
              success: true,
              principal: principal.toString(),
              identity: identity
            });
          } catch (error) {
            reject(new Error(`Login success but failed to get identity: ${error.message}`));
          }
        },
        onError: (error) => {
          reject(new Error(`Internet Identity login failed: ${error}`));
        },
        ...options
      });
    });
  }

  /**
   * Logout from Internet Identity
   * @returns {Promise<void>}
   */
  async logout() {
    await this.initialize();
    
    if (await this.isAuthenticated()) {
      await this.authClient.logout();
    }
  }

  /**
   * Get the current identity for making authenticated calls
   * @returns {Promise<Identity|null>}
   */
  async getIdentity() {
    await this.initialize();
    
    if (await this.isAuthenticated()) {
      return this.authClient.getIdentity();
    }
    
    return null;
  }

  /**
   * Create an actor for interacting with canisters
   * @param {string} canisterId - The canister ID
   * @param {Function} interfaceFactory - The interface factory function
   * @param {Object} options - Additional options
   * @returns {Promise<Actor>}
   */
  async createActor(canisterId, interfaceFactory, options = {}) {
    const identity = await this.getIdentity();
    
    if (!identity) {
      throw new Error('Not authenticated. Please login first.');
    }

    const agent = new HttpAgent({
      identity,
      host: options.host || 'http://localhost:4943', // Change for mainnet
      ...options.agentOptions
    });

    // Fetch root key for local development (remove for production)
    if (options.host?.includes('localhost') || !options.host) {
      await agent.fetchRootKey();
    }

    return Actor.createActor(interfaceFactory, {
      agent,
      canisterId,
      ...options.actorOptions
    });
  }

  /**
   * Get user information and wallet details
   * @returns {Promise<Object>} User wallet information
   */
  async getWalletInfo() {
    const principal = await this.getCurrentPrincipal();
    
    if (!principal) {
      throw new Error('Not authenticated');
    }

    // You can extend this to get balance, transaction history, etc.
    return {
      principal: principal.toString(),
      isAuthenticated: true,
      authMethod: 'Internet Identity'
    };
  }

  /**
   * Check if running in local development environment
   * @returns {boolean}
   */
  isLocalEnvironment() {
    return this.options.identityProvider.includes('localhost') || 
           this.options.identityProvider.includes('127.0.0.1');
  }

  /**
   * Switch between local and production environments
   * @param {boolean} isLocal - Whether to use local environment
   */
  switchEnvironment(isLocal = true) {
    this.options.identityProvider = isLocal 
      ? 'http://rdmx6-jaaaa-aaaaa-aaadq-cai.localhost:4943'
      : 'https://identity.ic0.app';
    
    // Reset client to apply new settings
    this.isInitialized = false;
    this.authClient = null;
  }
}

/**
 * Example interface factory for a simple canister
 * @param {Object} IDL - Candid interface description language
 * @returns {Object} Service interface
 */
export const createSimpleInterfaceFactory = ({ IDL }) => {
  return IDL.Service({
    'whoami': IDL.Func([], [IDL.Principal], ['query']),
    'greet': IDL.Func([IDL.Text], [IDL.Text], ['query']),
  });
};

/**
 * Example interface factory for ICP ledger canister
 * @param {Object} IDL - Candid interface description language  
 * @returns {Object} Ledger service interface
 */
export const createLedgerInterfaceFactory = ({ IDL }) => {
  const BlockHeight = IDL.Nat64;
  const AccountIdentifier = IDL.Vec(IDL.Nat8);
  const Tokens = IDL.Record({ 'e8s': IDL.Nat64 });
  
  return IDL.Service({
    'account_balance': IDL.Func([AccountIdentifier], [Tokens], ['query']),
    'get_blocks': IDL.Func([BlockHeight, IDL.Nat64], [IDL.Vec(IDL.Record({
      'block': IDL.Record({
        'transaction': IDL.Record({
          'operation': IDL.Variant({
            'Transfer': IDL.Record({
              'to': AccountIdentifier,
              'fee': Tokens,
              'from': AccountIdentifier,
              'amount': Tokens,
            }),
          }),
        }),
      }),
    }))], ['query']),
  });
};

export default InternetIdentityManager; 