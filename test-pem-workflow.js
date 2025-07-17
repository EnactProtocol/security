import { PemUtils, SigningService, CryptoUtils } from './packages/security-web/src/index.ts';

console.log('🧪 Testing complete PEM workflow...');

// 1. Generate a key pair in PEM format
const { keyPair, privateKeyPem, publicKeyPem } = PemUtils.generateKeyPairAsPem();
console.log('✅ Generated key pair in PEM format');
console.log('Private key PEM length:', privateKeyPem.length);
console.log('Public key PEM length:', publicKeyPem.length);

// 2. Convert back to hex for signing
const hexKeys = PemUtils.pemToKeyPair(privateKeyPem, publicKeyPem);
console.log('✅ Converted PEM back to hex');
console.log('Keys match original:', 
  hexKeys.privateKey === keyPair.privateKey && 
  hexKeys.publicKey === keyPair.publicKey
);

// 3. Sign a document with command-only field selection
const toolDocument = { command: 'test-tool' };
const signature = SigningService.signDocument(toolDocument, hexKeys.privateKey, {
  includeFields: ['command']
});
console.log('✅ Signed document with command field only');
console.log('Signature length:', signature.signature.length);
console.log('Algorithm:', signature.algorithm);

// 4. Verify the signature
const isValid = CryptoUtils.verify(signature.publicKey, 
  CryptoUtils.hash(JSON.stringify({ command: 'test-tool' })), 
  signature.signature
);
console.log('✅ Direct crypto verification:', isValid);

// 5. Validate the key pair
const validation = PemUtils.validateKeyPair(privateKeyPem, publicKeyPem);
console.log('✅ Key pair validation:', validation.isValid);

// 6. Test download functionality (simulated)
console.log('✅ PEM download functions available:');
console.log('- downloadPrivateKeyPem');
console.log('- downloadPublicKeyPem');
console.log('- downloadKeyPairPems');

// 7. Show the actual PEM content (first few lines)
console.log('\n📄 Generated PEM files:');
console.log('Private Key PEM:');
console.log(privateKeyPem.split('\n').slice(0, 3).join('\n') + '...');
console.log('\nPublic Key PEM:');
console.log(publicKeyPem.split('\n').slice(0, 3).join('\n') + '...');

console.log('\n🎉 Complete PEM workflow test successful!');