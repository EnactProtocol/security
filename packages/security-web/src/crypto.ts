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
}