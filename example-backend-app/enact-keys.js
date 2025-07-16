#!/usr/bin/env node
// Simple CLI for managing Enact security keys
import { KeyManager } from '@enactprotocol/security';

const command = process.argv[2];
const args = process.argv.slice(3);

function showUsage() {
  console.log('🔐 Enact Security Key Manager');
  console.log('');
  console.log('Usage:');
  console.log('  enact-keys generate <key-id> [description]  - Generate new key pair');
  console.log('  enact-keys list                             - List all keys');
  console.log('  enact-keys trusted                          - List trusted public keys');
  console.log('  enact-keys info <key-id>                    - Show key information');
  console.log('  enact-keys export <key-id> <file>           - Export key to file');
  console.log('  enact-keys import-public <key-id> <key>     - Import public key');
  console.log('  enact-keys remove <key-id>                  - Remove key');
  console.log('  enact-keys paths                            - Show storage paths');
  console.log('');
  console.log('Examples:');
  console.log('  enact-keys generate my-signing-key "My personal signing key"');
  console.log('  enact-keys info my-signing-key');
  console.log('  enact-keys export my-signing-key ./backup.json');
}

async function main() {
  try {
    switch (command) {
      case 'generate':
        if (!args[0]) {
          console.error('❌ Key ID required');
          process.exit(1);
        }
        const keyPair = KeyManager.generateAndStoreKey(args[0], args[1]);
        console.log('✅ Generated key:', args[0]);
        console.log('   Public:', keyPair.publicKey.substring(0, 32) + '...');
        console.log('   Stored in ~/.enact/');
        break;

      case 'list':
        const keys = KeyManager.listKeys();
        console.log('🔑 Keys with private keys:');
        if (keys.length === 0) {
          console.log('   (none)');
        } else {
          keys.forEach(keyId => {
            const metadata = KeyManager.getKeyMetadata(keyId);
            console.log(`   ${keyId} - ${metadata?.description || 'No description'}`);
          });
        }
        break;

      case 'trusted':
        const trustedKeys = KeyManager.listTrustedKeys();
        console.log('🤝 Trusted public keys:');
        if (trustedKeys.length === 0) {
          console.log('   (none)');
        } else {
          trustedKeys.forEach(keyId => {
            const metadata = KeyManager.getKeyMetadata(keyId);
            const hasPrivate = KeyManager.keyExists(keyId);
            console.log(`   ${keyId} ${hasPrivate ? '(full key)' : '(public only)'} - ${metadata?.description || 'No description'}`);
          });
        }
        break;

      case 'info':
        if (!args[0]) {
          console.error('❌ Key ID required');
          process.exit(1);
        }
        const metadata = KeyManager.getKeyMetadata(args[0]);
        const publicKey = KeyManager.getPublicKey(args[0]);
        const hasPrivate = KeyManager.keyExists(args[0]);
        
        if (!metadata && !publicKey) {
          console.error(`❌ Key '${args[0]}' not found`);
          process.exit(1);
        }
        
        console.log(`🔍 Key information: ${args[0]}`);
        if (metadata) {
          console.log(`   Created: ${metadata.created}`);
          console.log(`   Algorithm: ${metadata.algorithm}`);
          console.log(`   Description: ${metadata.description || 'None'}`);
        }
        if (publicKey) {
          console.log(`   Public key: ${publicKey.substring(0, 32)}...`);
        }
        console.log(`   Has private key: ${hasPrivate ? 'Yes' : 'No'}`);
        break;

      case 'export':
        if (!args[0] || !args[1]) {
          console.error('❌ Key ID and output file required');
          process.exit(1);
        }
        KeyManager.exportKeyToFile(args[0], args[1], false);
        console.log(`✅ Exported public key to: ${args[1]}`);
        break;

      case 'import-public':
        if (!args[0] || !args[1]) {
          console.error('❌ Key ID and public key required');
          process.exit(1);
        }
        KeyManager.importPublicKey(args[0], args[1], args[2] || 'Imported public key');
        console.log(`✅ Imported public key: ${args[0]}`);
        break;

      case 'remove':
        if (!args[0]) {
          console.error('❌ Key ID required');
          process.exit(1);
        }
        const removed = KeyManager.removeKey(args[0]);
        if (removed) {
          console.log(`✅ Removed key: ${args[0]}`);
        } else {
          console.log(`❌ Key not found: ${args[0]}`);
        }
        break;

      case 'paths':
        const paths = KeyManager.getStoragePaths();
        console.log('📁 Storage paths:');
        console.log(`   Trusted keys: ${paths.trustedKeys}`);
        console.log(`   Private keys: ${paths.privateKeys}`);
        break;

      default:
        showUsage();
        process.exit(1);
    }
  } catch (error) {
    console.error('❌ Error:', error.message);
    process.exit(1);
  }
}

main();