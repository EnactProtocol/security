import { CryptoUtils, SigningService, KeyManager } from './packages/security/src/index.ts';

// Ensure trusted key is loaded
console.log('All trusted keys:', KeyManager.getAllTrustedPublicKeys());

// Test the exact same values being used
const toolDocument = { command: 'stuff' };
const signature = {
  signature: '59e7a79d6c2528884dbca1cf3eda382fc1a0d3ee8d01680039b31f78edd5ce493e4f7e027fdd1605e61596ed7cc34269d15673b0fa6a0a75921046f9f7a15660',
  publicKey: '0322e24cbec953028f2dfb1d18e0c5e0dd1b837b5fd214656179e5d1f0e0364772',
  algorithm: 'secp256k1',
  timestamp: 1752773974011
};

console.log('Testing exact same params from CLI...');
console.log('Document:', JSON.stringify(toolDocument));
console.log('Signature:', JSON.stringify(signature));

const isValid = SigningService.verifyDocument(toolDocument, signature, {
  includeFields: ['command']
});

console.log('Verification result:', isValid);

if (isValid) {
  console.log('✅ SUCCESS: Signature verification works with these exact values!');
} else {
  console.log('❌ FAILED: Even with exact values, verification fails');
  
  // Debug why it fails
  const canonicalDoc = SigningService.getCanonicalDocument(toolDocument, { includeFields: ['command'] });
  console.log('Canonical document:', JSON.stringify(canonicalDoc));
  
  const docString = JSON.stringify(canonicalDoc);
  const messageHash = CryptoUtils.hash(docString);
  console.log('Message hash:', messageHash);
  
  const directVerify = CryptoUtils.verify(signature.publicKey, messageHash, signature.signature);
  console.log('Direct crypto verify:', directVerify);
  
  const trustedKeys = KeyManager.getAllTrustedPublicKeys();
  console.log('Is key trusted?', trustedKeys.includes(signature.publicKey));
}