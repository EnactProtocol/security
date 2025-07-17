import { CryptoUtils, SigningService } from './packages/security/src/index.ts';

const toolDocument = { command: 'mytools/fun' };
const signature = {
  signature: '61002831e885bef963b671c54b0e49df8609edffaa128cbbff2164378a27beb94be4c66dc911aa2557483cb8e4018dbcacda77be1d7ddeac5c6d9ec3f051ebbc',
  publicKey: '03c1c485a0ae4026bdd1f8eeb3837c7d1b0111ec15c7a5033c7dd817bb88982f14', // Correct public key
  algorithm: 'secp256k1',
  timestamp: 1752767427799
};

console.log('Testing with correct public key from PEM...');
const isValid = SigningService.verifyDocument(toolDocument, signature, {
  includeFields: ['command']
});

console.log('Verification result:', isValid);