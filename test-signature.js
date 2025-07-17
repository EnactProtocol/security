import { CryptoUtils, SigningService } from './packages/security/src/index.ts';

const toolDocument = { command: 'mytools/fun' };
const signature = {
  signature: '61002831e885bef963b671c54b0e49df8609edffaa128cbbff2164378a27beb94be4c66dc911aa2557483cb8e4018dbcacda77be1d7ddeac5c6d9ec3f051ebbc',
  publicKey: '028f49cb15b4649d57828c2badd6e6c32bdcc010f3753c6177643ec85959ec42ac',
  algorithm: 'secp256k1',
  timestamp: 1752767427799
};

const isValid = SigningService.verifyDocument(toolDocument, signature, {
  includeFields: ['command']
});

console.log('Verification result:', isValid);