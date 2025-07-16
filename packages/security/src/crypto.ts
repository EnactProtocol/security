import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

export class CryptoUtils {
  static generateKeyPair() {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const publicKey = secp256k1.getPublicKey(privateKey);
    
    return {
      privateKey: bytesToHex(privateKey),
      publicKey: bytesToHex(publicKey)
    };
  }

  static getPublicKeyFromPrivate(privateKeyHex: string): string {
    const privateKey = hexToBytes(privateKeyHex);
    const publicKey = secp256k1.getPublicKey(privateKey);
    return bytesToHex(publicKey);
  }

  static hash(data: string): string {
    return bytesToHex(sha256(data));
  }

  static sign(privateKeyHex: string, messageHash: string): string {
    const privateKey = hexToBytes(privateKeyHex);
    const hash = hexToBytes(messageHash);
    
    const signature = secp256k1.sign(hash, privateKey);
    return signature.toCompactHex();
  }

  static verify(publicKeyHex: string, messageHash: string, signatureHex: string): boolean {
    try {
      const publicKey = hexToBytes(publicKeyHex);
      const hash = hexToBytes(messageHash);
      
      return secp256k1.verify(signatureHex, hash, publicKey);
    } catch {
      return false;
    }
  }

  // PEM conversion utilities
  static hexToPem(hexKey: string, type: 'PUBLIC' | 'PRIVATE'): string {
    // For secp256k1, we need to add DER encoding
    let derKey: string;
    
    if (type === 'PUBLIC') {
      // For public keys, we need to add the DER structure
      // secp256k1 public key DER prefix: 3056301006072a8648ce3d020106052b8104000a034200
      const publicKeyBytes = hexToBytes(hexKey);
      
      // Create DER structure for secp256k1 public key
      const derPrefix = '3056301006072a8648ce3d020106052b8104000a034200';
      derKey = derPrefix + hexKey;
    } else {
      // For private keys, we need to add the DER structure
      // secp256k1 private key DER prefix varies, but we'll use a simple EC private key format
      const privateKeyBytes = hexToBytes(hexKey);
      
      // Create DER structure for secp256k1 private key
      const derPrefix = '308184020100301006072a8648ce3d020106052b8104000a046d306b0201010420';
      const derSuffix = 'a144034200' + CryptoUtils.getPublicKeyFromPrivate(hexKey);
      derKey = derPrefix + hexKey + derSuffix;
    }
    
    // Convert to base64
    const derBytes = hexToBytes(derKey);
    const base64Key = Buffer.from(derBytes).toString('base64');
    
    // Format as PEM
    const keyType = type === 'PUBLIC' ? 'PUBLIC KEY' : 'PRIVATE KEY';
    const pemLines = base64Key.match(/.{1,64}/g) || [];
    
    return [
      `-----BEGIN ${keyType}-----`,
      ...pemLines,
      `-----END ${keyType}-----`
    ].join('\n');
  }

  static pemToHex(pemKey: string, type: 'PUBLIC' | 'PRIVATE'): string {
    const keyType = type === 'PUBLIC' ? 'PUBLIC KEY' : 'PRIVATE KEY';
    const beginMarker = `-----BEGIN ${keyType}-----`;
    const endMarker = `-----END ${keyType}-----`;
    
    // Extract base64 content
    const base64Content = pemKey
      .replace(beginMarker, '')
      .replace(endMarker, '')
      .replace(/\s+/g, '');
    
    // Convert to hex
    const derBytes = Buffer.from(base64Content, 'base64');
    const derHex = bytesToHex(derBytes);
    
    if (type === 'PUBLIC') {
      // Extract the actual public key from DER structure
      // Skip the DER prefix and extract the 33-byte public key
      const publicKeyStart = derHex.indexOf('034200') + 6; // Skip to after the bit string indicator
      return derHex.substring(publicKeyStart, publicKeyStart + 66); // 33 bytes = 66 hex chars
    } else {
      // Extract the actual private key from DER structure
      // Look for the 32-byte private key after the DER prefix
      const privateKeyStart = derHex.indexOf('0420') + 4; // Skip to after the octet string indicator
      return derHex.substring(privateKeyStart, privateKeyStart + 64); // 32 bytes = 64 hex chars
    }
  }

  static isPemFormat(key: string): boolean {
    return key.includes('-----BEGIN') && key.includes('-----END');
  }
}