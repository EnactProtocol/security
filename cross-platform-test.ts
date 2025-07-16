// Cross-platform compatibility test
// This file demonstrates that signatures created on frontend work on backend and vice versa

import { SigningService as BackendSigning, CryptoUtils as BackendCrypto } from './packages/security/src/index';
import { SigningService as FrontendSigning, CryptoUtils as FrontendCrypto } from './packages/security-web/src/index';
import type { EnactDocument } from './packages/security/src/types';

// Shared test data
const testDocument: EnactDocument = {
  id: "cross-platform-test-123",
  content: "This document tests cross-platform signature compatibility",
  timestamp: 1640995200000,
  metadata: { 
    test: "cross-platform",
    version: "1.0" 
  }
};

const testPrivateKey = "d8f8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0";

console.log("🔐 Cross-Platform Signature Compatibility Test\n");

// Test 1: Backend signs, frontend verifies
console.log("Test 1: Backend signing → Frontend verification");
const backendSignature = BackendSigning.signDocument(testDocument, testPrivateKey);
console.log("✅ Backend signature created:", {
  signature: backendSignature.signature.substring(0, 20) + "...",
  publicKey: backendSignature.publicKey.substring(0, 20) + "...",
  algorithm: backendSignature.algorithm
});

const frontendVerifiesBackend = FrontendSigning.verifyDocument(testDocument, backendSignature);
console.log(`${frontendVerifiesBackend ? '✅' : '❌'} Frontend verification result:`, frontendVerifiesBackend);

// Test 2: Frontend signs, backend verifies
console.log("\nTest 2: Frontend signing → Backend verification");
const frontendSignature = FrontendSigning.signDocument(testDocument, testPrivateKey);
console.log("✅ Frontend signature created:", {
  signature: frontendSignature.signature.substring(0, 20) + "...",
  publicKey: frontendSignature.publicKey.substring(0, 20) + "...",
  algorithm: frontendSignature.algorithm
});

const backendVerifiesFrontend = BackendSigning.verifyDocument(testDocument, frontendSignature);
console.log(`${backendVerifiesFrontend ? '✅' : '❌'} Backend verification result:`, backendVerifiesFrontend);

// Test 3: Key derivation consistency
console.log("\nTest 3: Key derivation consistency");
const backendPublicKey = BackendCrypto.getPublicKeyFromPrivate(testPrivateKey);
const frontendPublicKey = FrontendCrypto.getPublicKeyFromPrivate(testPrivateKey);
const keysMatch = backendPublicKey === frontendPublicKey;

console.log("Backend derived public key:", backendPublicKey.substring(0, 20) + "...");
console.log("Frontend derived public key:", frontendPublicKey.substring(0, 20) + "...");
console.log(`${keysMatch ? '✅' : '❌'} Public keys match:`, keysMatch);

// Test 4: Hash consistency
console.log("\nTest 4: Hash function consistency");
const testString = JSON.stringify(testDocument);
const backendHash = BackendCrypto.hash(testString);
const frontendHash = FrontendCrypto.hash(testString);
const hashesMatch = backendHash === frontendHash;

console.log("Backend hash:", backendHash.substring(0, 20) + "...");
console.log("Frontend hash:", frontendHash.substring(0, 20) + "...");
console.log(`${hashesMatch ? '✅' : '❌'} Hashes match:`, hashesMatch);

// Summary
console.log("\n📊 Cross-Platform Compatibility Summary:");
console.log(`Backend → Frontend: ${frontendVerifiesBackend ? '✅ PASS' : '❌ FAIL'}`);
console.log(`Frontend → Backend: ${backendVerifiesFrontend ? '✅ PASS' : '❌ FAIL'}`);
console.log(`Key derivation: ${keysMatch ? '✅ PASS' : '❌ FAIL'}`);
console.log(`Hash function: ${hashesMatch ? '✅ PASS' : '❌ FAIL'}`);

const allTestsPass = frontendVerifiesBackend && backendVerifiesFrontend && keysMatch && hashesMatch;
console.log(`\n🎯 Overall result: ${allTestsPass ? '✅ ALL TESTS PASS' : '❌ SOME TESTS FAILED'}`);

if (allTestsPass) {
  console.log("\n🚀 Your security libraries are fully cross-platform compatible!");
  console.log("   • Signatures created on frontend can be verified on backend");
  console.log("   • Signatures created on backend can be verified on frontend");
  console.log("   • Key derivation is consistent across platforms");
  console.log("   • Hash functions produce identical results");
} else {
  console.log("\n⚠️  Some compatibility issues detected. Please review the implementation.");
}