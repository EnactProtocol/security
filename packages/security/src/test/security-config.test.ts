import { test, expect } from 'bun:test';
import { SigningService, CryptoUtils, DEFAULT_SECURITY_CONFIG } from '../index';
import type { EnactDocument, SecurityConfig, Signature } from '../types';

const testDocument: EnactDocument = {
  name: "test-tool",
  description: "A test tool",
  command: "echo 'test'",
  enact: "1.0.0"
};

const keyPair = CryptoUtils.generateKeyPair();

test('Default security config allows single signature', () => {
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
  
  const signature1 = SigningService.signDocument(testDocument, keyPair.privateKey, { useEnactDefaults: true });
  const keyPair2 = CryptoUtils.generateKeyPair();
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