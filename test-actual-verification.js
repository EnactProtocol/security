import { CryptoUtils, SigningService } from './packages/security/src/index.ts';

// Test with the actual private key from your PEM
const actualPrivateKeyPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvUtKnGmfFXH6d8IU
cHkdqEiaM41KCNv4d9Rm7LZxyKehRANCAAQ++i9puiqw21DaHZl4MNZkZdNvTTar
X0Ni1GUuIz0pxMzA/NQrWWjSNOy5qRZuAV1etXn0713SU4KBpmskdubf
-----END PRIVATE KEY-----`;

try {
  // Extract the private key correctly
  const privateKeyHex = CryptoUtils.pemToHex(actualPrivateKeyPem, 'PRIVATE');
  const publicKeyHex = CryptoUtils.getPublicKeyFromPrivate(privateKeyHex);
  
  console.log('Private key hex:', privateKeyHex);
  console.log('Public key hex:', publicKeyHex);
  
  // Create the tool document with just the command field
  const toolDocument = { command: 'stuff' };
  
  // Sign the document with the correct private key
  const signature = SigningService.signDocument(toolDocument, privateKeyHex, {
    includeFields: ['command']
  });
  
  console.log('Generated signature:', signature);
  
  // Verify the signature
  const isValid = SigningService.verifyDocument(toolDocument, signature, {
    includeFields: ['command']
  });
  
  console.log('Verification result:', isValid);
  
  // Now test with the actual signature from your database
  const databaseSignature = {
    signature: '3f012fa831c80a8090a2f062c7b2139803e46bea8fc5ec62c3fbac6e6ea698d456735a6546a26ef56a5b419e0400304e43d24812e92f17a89e46bc826d5e21aa',
    publicKey: publicKeyHex, // Use the correct public key
    algorithm: 'secp256k1',
    timestamp: 1752768859086
  };
  
  console.log('Testing database signature with correct public key...');
  const isValidFromDB = SigningService.verifyDocument(toolDocument, databaseSignature, {
    includeFields: ['command']
  });
  
  console.log('Database signature verification result:', isValidFromDB);
  
  // Output the correct hardcoded values for your backend
  console.log('\n=== HARDCODED VALUES FOR BACKEND ===');
  console.log('Correct public key:', `"${publicKeyHex}"`);
  console.log('Expected signature:', `"${databaseSignature.signature}"`);
  console.log('Tool document:', JSON.stringify(toolDocument));
  
} catch (error) {
  console.error('Error:', error.message);
}