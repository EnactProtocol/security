import { test, expect, beforeEach, afterEach } from 'bun:test';
import { SigningService, CryptoUtils, DEFAULT_SECURITY_CONFIG } from '../index';
import { KeyManager } from '../keyManager';
import type { EnactDocument, SecurityConfig, Signature } from '../types';
import fs from 'fs';
import path from 'path';
import os from 'os';

const testDocument: EnactDocument = {
  name: "test-tool",
  description: "A test tool",
  command: "echo 'test'",
  enact: "1.0.0"
};

// Test directories
const testTrustedKeysDir = path.join(os.tmpdir(), 'test-security-config-trusted-keys');
const testPrivateKeysDir = path.join(os.tmpdir(), 'test-security-config-private-keys');

// Mock the storage paths for testing
const originalTrustedKeysDir = (KeyManager as any).TRUSTED_KEYS_DIR;
const originalPrivateKeysDir = (KeyManager as any).PRIVATE_KEYS_DIR;

beforeEach(() => {
  // Override the storage paths to use temp directories
  (KeyManager as any).TRUSTED_KEYS_DIR = testTrustedKeysDir;
  (KeyManager as any).PRIVATE_KEYS_DIR = testPrivateKeysDir;
  
  // Clean up any existing test directories
  if (fs.existsSync(testTrustedKeysDir)) {
    fs.rmSync(testTrustedKeysDir, { recursive: true, force: true });
  }
  if (fs.existsSync(testPrivateKeysDir)) {
    fs.rmSync(testPrivateKeysDir, { recursive: true, force: true });
  }
});

afterEach(() => {
  // Restore original paths
  (KeyManager as any).TRUSTED_KEYS_DIR = originalTrustedKeysDir;
  (KeyManager as any).PRIVATE_KEYS_DIR = originalPrivateKeysDir;
  
  // Clean up test directories
  if (fs.existsSync(testTrustedKeysDir)) {
    fs.rmSync(testTrustedKeysDir, { recursive: true, force: true });
  }
  if (fs.existsSync(testPrivateKeysDir)) {
    fs.rmSync(testPrivateKeysDir, { recursive: true, force: true });
  }
});

test('Default security config allows single signature', () => {
  const keyPair = KeyManager.generateAndStoreKey('test-key', 'Test key for single signature');
  const signature = SigningService.signDocument(testDocument, keyPair.privateKey, { useEnactDefaults: true });
  
  const isValid = SigningService.verifyDocument(
    testDocument, 
    signature, 
    { useEnactDefaults: true }
  );
  
  expect(isValid).toBe(true);
});

test('AllowLocalUnsigned=true allows documents with no signatures', () => {
  const config: SecurityConfig = {
    allowLocalUnsigned: true,
    minimumSignatures: 1
  };
  
  const documentWithoutSignatures: EnactDocument = {
    ...testDocument,
    signatures: []
  };
  
  // Pass empty signature since we're testing documents without signatures
  const dummySignature: Signature = {
    signature: '',
    publicKey: '',
    algorithm: 'secp256k1',
    timestamp: Date.now()
  };
  
  const isValid = SigningService.verifyDocument(
    documentWithoutSignatures,
    dummySignature,
    { useEnactDefaults: true },
    config
  );
  
  expect(isValid).toBe(true);
});

test('AllowLocalUnsigned=false rejects documents with no signatures', () => {
  const config: SecurityConfig = {
    allowLocalUnsigned: false,
    minimumSignatures: 1
  };
  
  const documentWithoutSignatures: EnactDocument = {
    ...testDocument,
    signatures: []
  };
  
  const dummySignature: Signature = {
    signature: '',
    publicKey: '',
    algorithm: 'secp256k1',
    timestamp: Date.now()
  };
  
  const isValid = SigningService.verifyDocument(
    documentWithoutSignatures,
    dummySignature,
    { useEnactDefaults: true },
    config
  );
  
  expect(isValid).toBe(false);
});

test('MinimumSignatures=2 requires at least 2 signatures', () => {
  const config: SecurityConfig = {
    allowLocalUnsigned: false,
    minimumSignatures: 2
  };
  
  const keyPair1 = KeyManager.generateAndStoreKey('test-key-1', 'Test key 1');
  const keyPair2 = KeyManager.generateAndStoreKey('test-key-2', 'Test key 2');
  const signature1 = SigningService.signDocument(testDocument, keyPair1.privateKey, { useEnactDefaults: true });
  const signature2 = SigningService.signDocument(testDocument, keyPair2.privateKey, { useEnactDefaults: true });
  
  const documentWithTwoSignatures: EnactDocument = {
    ...testDocument,
    signatures: [signature1, signature2]
  };
  
  // Should pass with 2 signatures
  const isValid = SigningService.verifyDocument(
    documentWithTwoSignatures,
    signature1, // This gets ignored since document has signatures array
    { useEnactDefaults: true },
    config
  );
  
  expect(isValid).toBe(true);
});

test('MinimumSignatures=2 rejects documents with only 1 signature', () => {
  const config: SecurityConfig = {
    allowLocalUnsigned: false,
    minimumSignatures: 2
  };
  
  const keyPair = KeyManager.generateAndStoreKey('test-key', 'Test key');
  const signature = SigningService.signDocument(testDocument, keyPair.privateKey, { useEnactDefaults: true });
  
  const documentWithOneSignature: EnactDocument = {
    ...testDocument,
    signatures: [signature]
  };
  
  const isValid = SigningService.verifyDocument(
    documentWithOneSignature,
    signature,
    { useEnactDefaults: true },
    config
  );
  
  expect(isValid).toBe(false);
});

test('Invalid signature fails verification regardless of config', () => {
  const config: SecurityConfig = {
    allowLocalUnsigned: true,
    minimumSignatures: 1
  };
  
  const keyPair = KeyManager.generateAndStoreKey('test-key', 'Test key');
  const validSignature = SigningService.signDocument(testDocument, keyPair.privateKey, { useEnactDefaults: true });
  
  // Create invalid signature by corrupting the signature string
  const invalidSignature: Signature = {
    ...validSignature,
    signature: 'invalid_signature_string'
  };
  
  const documentWithInvalidSignature: EnactDocument = {
    ...testDocument,
    signatures: [invalidSignature]
  };
  
  const isValid = SigningService.verifyDocument(
    documentWithInvalidSignature,
    invalidSignature,
    { useEnactDefaults: true },
    config
  );
  
  expect(isValid).toBe(false);
});

test('Mixed valid and invalid signatures fail verification', () => {
  const config: SecurityConfig = {
    allowLocalUnsigned: false,
    minimumSignatures: 2
  };
  
  const keyPair = KeyManager.generateAndStoreKey('test-key', 'Test key');
  const validSignature = SigningService.signDocument(testDocument, keyPair.privateKey, { useEnactDefaults: true });
  const invalidSignature: Signature = {
    signature: 'invalid',
    publicKey: 'invalid',
    algorithm: 'secp256k1',
    timestamp: Date.now()
  };
  
  const documentWithMixedSignatures: EnactDocument = {
    ...testDocument,
    signatures: [validSignature, invalidSignature]
  };
  
  const isValid = SigningService.verifyDocument(
    documentWithMixedSignatures,
    validSignature,
    { useEnactDefaults: true },
    config
  );
  
  expect(isValid).toBe(false);
});

test('Default config values are used when not specified', () => {
  const keyPair = KeyManager.generateAndStoreKey('test-key', 'Test key');
  const signature = SigningService.signDocument(testDocument, keyPair.privateKey, { useEnactDefaults: true });
  
  // Test with undefined config - should use defaults
  const isValid = SigningService.verifyDocument(
    testDocument,
    signature,
    { useEnactDefaults: true },
    undefined
  );
  
  expect(isValid).toBe(true);
});

test('Partial config merges with defaults', () => {
  const partialConfig: SecurityConfig = {
    minimumSignatures: 2
    // allowLocalUnsigned not specified, should use default (true)
  };
  
  const documentWithoutSignatures: EnactDocument = {
    ...testDocument,
    signatures: []
  };
  
  const dummySignature: Signature = {
    signature: '',
    publicKey: '',
    algorithm: 'secp256k1',
    timestamp: Date.now()
  };
  
  // Should pass because allowLocalUnsigned defaults to true
  const isValid = SigningService.verifyDocument(
    documentWithoutSignatures,
    dummySignature,
    { useEnactDefaults: true },
    partialConfig
  );
  
  expect(isValid).toBe(true);
});