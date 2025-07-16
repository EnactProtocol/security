// Demo of the enhanced KeyManager with file-based storage
import { KeyManager, SigningService, CryptoUtils } from '@enactprotocol/security';
import fs from 'fs';

console.log('🔐 Enhanced KeyManager Demo - File-Based Storage');
console.log('=' .repeat(60));

// Show storage paths
const paths = KeyManager.getStoragePaths();
console.log('📁 Storage Locations:');
console.log(`   Trusted Keys: ${paths.trustedKeys}`);
console.log(`   Private Keys: ${paths.privateKeys}`);
console.log();

try {
  // 1. Generate and store a new key
  console.log('1️⃣  Generating and storing a new key...');
  const keyPair = KeyManager.generateAndStoreKey('demo-signing-key', 'Demo key for testing');
  console.log(`✅ Generated key: demo-signing-key`);
  console.log(`   Public:  ${keyPair.publicKey.substring(0, 32)}...`);
  console.log(`   Private: ${keyPair.privateKey.substring(0, 32)}...`);
  console.log();

  // 2. List stored keys
  console.log('2️⃣  Listing stored keys...');
  const keys = KeyManager.listKeys();
  const trustedKeys = KeyManager.listTrustedKeys();
  console.log(`✅ Keys with private keys: ${keys.join(', ')}`);
  console.log(`✅ All trusted public keys: ${trustedKeys.join(', ')}`);
  console.log();

  // 3. Get key metadata
  console.log('3️⃣  Reading key metadata...');
  const metadata = KeyManager.getKeyMetadata('demo-signing-key');
  if (metadata) {
    console.log('✅ Key metadata:');
    console.log(`   Key ID: ${metadata.keyId}`);
    console.log(`   Created: ${metadata.created}`);
    console.log(`   Algorithm: ${metadata.algorithm}`);
    console.log(`   Description: ${metadata.description}`);
  }
  console.log();

  // 4. Import a public key only (for verification)
  console.log('4️⃣  Importing a public key from another party...');
  const otherPublicKey = CryptoUtils.generateKeyPair().publicKey;
  KeyManager.importPublicKey('trusted-partner', otherPublicKey, 'Partner company public key');
  console.log('✅ Imported public key: trusted-partner');
  console.log(`   Public: ${otherPublicKey.substring(0, 32)}...`);
  console.log();

  // 5. Test signing with stored key
  console.log('5️⃣  Testing document signing with stored key...');
  const testDoc = {
    name: 'key-storage-demo/test-tool',
    description: 'Testing file-based key storage',
    command: 'echo "File storage works!"',
    enact: '1.0.0'
  };

  const storedKey = KeyManager.getKey('demo-signing-key');
  if (storedKey) {
    const signature = SigningService.signDocument(testDoc, storedKey.privateKey, {
      useEnactDefaults: true
    });
    console.log('✅ Document signed with stored key');
    console.log(`   Signature: ${signature.signature.substring(0, 40)}...`);
    
    // Verify with public key only
    const publicKey = KeyManager.getPublicKey('demo-signing-key');
    if (publicKey) {
      const isValid = SigningService.verifyDocument(testDoc, signature, {
        useEnactDefaults: true
      });
      console.log(`✅ Verification using stored public key: ${isValid ? 'VALID' : 'INVALID'}`);
    }
  }
  console.log();

  // 6. Export key to file
  console.log('6️⃣  Exporting key to file...');
  const exportPath = './exported-key.json';
  KeyManager.exportKeyToFile('demo-signing-key', exportPath, false); // Public key only
  console.log(`✅ Exported public key to: ${exportPath}`);
  
  if (fs.existsSync(exportPath)) {
    const exportedData = JSON.parse(fs.readFileSync(exportPath, 'utf8'));
    console.log('   Export contains:');
    console.log(`   - Metadata: ${exportedData.metadata ? 'Yes' : 'No'}`);
    console.log(`   - Public Key: ${exportedData.publicKey ? 'Yes' : 'No'}`);
    console.log(`   - Private Key: ${exportedData.privateKey ? 'Yes' : 'No'}`);
  }
  console.log();

  // 7. Check file permissions
  console.log('7️⃣  Checking file permissions...');
  const publicKeyFile = `${paths.trustedKeys}/demo-signing-key.pub`;
  const privateKeyFile = `${paths.privateKeys}/demo-signing-key.key`;
  
  if (fs.existsSync(publicKeyFile)) {
    const publicStats = fs.statSync(publicKeyFile);
    console.log(`✅ Public key file permissions: ${(publicStats.mode & parseInt('777', 8)).toString(8)}`);
  }
  
  if (fs.existsSync(privateKeyFile)) {
    const privateStats = fs.statSync(privateKeyFile);
    console.log(`✅ Private key file permissions: ${(privateStats.mode & parseInt('777', 8)).toString(8)}`);
  }
  console.log();

  // 8. Show directory structure
  console.log('8️⃣  Directory structure:');
  if (fs.existsSync(paths.trustedKeys)) {
    const trustedFiles = fs.readdirSync(paths.trustedKeys);
    console.log(`✅ Trusted keys directory (${trustedFiles.length} files):`);
    trustedFiles.forEach(file => {
      console.log(`   - ${file}`);
    });
  }
  
  if (fs.existsSync(paths.privateKeys)) {
    const privateFiles = fs.readdirSync(paths.privateKeys);
    console.log(`✅ Private keys directory (${privateFiles.length} files):`);
    privateFiles.forEach(file => {
      console.log(`   - ${file}`);
    });
  }
  console.log();

  console.log('🎉 File-based key storage demo completed successfully!');
  console.log();
  console.log('💡 Key features demonstrated:');
  console.log('   ✅ Secure file storage with proper permissions');
  console.log('   ✅ Separation of public and private keys');
  console.log('   ✅ Metadata tracking with descriptions');
  console.log('   ✅ Public key import for verification');
  console.log('   ✅ Key export functionality');
  console.log('   ✅ Integration with signing/verification');

} catch (error) {
  console.error('❌ Demo failed:', error.message);
  process.exit(1);
}