// Frontend signing test - creates signature that backend will verify
import { SigningService, CryptoUtils } from './packages/security-web/src/index';
import type { EnactDocument } from './packages/security-web/src/types';

console.log("🌐 Frontend Signing Test");
console.log("Creating signature that backend will verify...\n");

// Create a realistic Enact tool for testing
const testTool: EnactDocument = {
  name: "frontend-test/file-formatter",
  description: "Formats code files using frontend-generated signature",
  command: "npx prettier@3.3.3 --write '${file}' --config .prettierrc",
  enact: "1.0.0",
  version: "2.1.0",
  from: "node:18-alpine",
  timeout: "45s",
  annotations: {
    destructiveHint: true,
    title: "Frontend File Formatter",
    readOnlyHint: false,
    idempotentHint: true
  },
  env: {
    PRETTIER_CONFIG: {
      description: "Prettier configuration file path",
      required: false,
      default: ".prettierrc"
    },
    NODE_ENV: {
      description: "Node environment for execution",
      required: true,
      default: "production"
    }
  },
  inputSchema: {
    type: "object",
    properties: {
      file: { 
        type: "string", 
        description: "Path to file to format",
        pattern: "\\.(js|ts|jsx|tsx|json|css|scss|md)$"
      },
      parser: { 
        type: "string", 
        enum: ["typescript", "babel", "json", "css", "markdown"],
        description: "Parser to use for formatting",
        default: "typescript"
      }
    },
    required: ["file"]
  },
  
  // Non-security-critical fields (won't be signed with Enact defaults)
  tags: ["formatting", "code-quality", "prettier", "frontend"],
  license: "MIT",
  authors: [
    { name: "Frontend Dev Team", email: "frontend@enact.dev" },
    { name: "Security Team", email: "security@enact.dev" }
  ],
  
  // Generic document fields
  id: "frontend-tool-test-12345",
  content: "Frontend-generated tool definition for cross-platform testing",
  timestamp: Date.now(),
  metadata: {
    createdBy: "frontend-test",
    platform: "browser",
    testSuite: "cross-platform-verification",
    signatureMethod: "frontend-web-crypto"
  }
};

// Generate a key pair for this test
const keyPair = CryptoUtils.generateKeyPair();
console.log("🔑 Generated test key pair:");
console.log(`Private key: ${keyPair.privateKey.substring(0, 32)}...`);
console.log(`Public key: ${keyPair.publicKey.substring(0, 32)}...\n`);

// Sign with Enact Protocol defaults (security-critical fields only)
console.log("📝 Signing with Enact Protocol defaults...");
const enactSignature = SigningService.signDocument(testTool, keyPair.privateKey, {
  useEnactDefaults: true
});

// Get the canonical document that was signed
const canonicalDocument = SigningService.getCanonicalDocument(testTool, {
  useEnactDefaults: true
});

console.log("✅ Frontend signature created!");
console.log(`Signature: ${enactSignature.signature.substring(0, 40)}...`);
console.log(`Public key: ${enactSignature.publicKey.substring(0, 40)}...`);
console.log(`Algorithm: ${enactSignature.algorithm}`);
console.log(`Timestamp: ${new Date(enactSignature.timestamp).toISOString()}\n`);

console.log("📋 Canonical document (signed fields only):");
console.log(JSON.stringify(canonicalDocument, null, 2));
console.log(`\nFields signed: ${Object.keys(canonicalDocument).join(', ')}\n`);

// Verify locally on frontend first
console.log("🔍 Local frontend verification...");
const frontendVerification = SigningService.verifyDocument(testTool, enactSignature, {
  useEnactDefaults: true
});
console.log(`Frontend verification: ${frontendVerification ? '✅ VALID' : '❌ INVALID'}\n`);

// Output data for backend verification
console.log("📤 Data for backend verification:");
console.log("Copy and paste the following into backend-verifier.ts:\n");

const testData = {
  tool: testTool,
  signature: enactSignature,
  keyPair: keyPair,
  canonicalDocument: canonicalDocument,
  metadata: {
    frontendPlatform: "browser/web-crypto",
    signingOptions: { useEnactDefaults: true },
    signedFields: Object.keys(canonicalDocument),
    testTimestamp: new Date().toISOString()
  }
};

console.log("const frontendTestData = " + JSON.stringify(testData, null, 2) + ";");

console.log("\n🎯 Frontend signing completed!");
console.log("✅ Signature created using browser crypto APIs");
console.log("✅ Enact Protocol security-critical fields signed");
console.log("✅ Canonical JSON generated deterministically");
console.log("✅ Ready for backend verification");

// Also test custom field selection
console.log("\n📝 Additional test: Custom field selection...");
const customFields = ["name", "command", "version", "license", "tags"];
const customSignature = SigningService.signDocument(testTool, keyPair.privateKey, {
  includeFields: customFields
});

const customCanonical = SigningService.getCanonicalDocument(testTool, {
  includeFields: customFields
});

console.log("✅ Custom field signature:");
console.log(`Custom fields: ${customFields.join(', ')}`);
console.log(`Signature: ${customSignature.signature.substring(0, 40)}...`);
console.log("Custom canonical:");
console.log(JSON.stringify(customCanonical, null, 2));

console.log("\n🚀 Frontend test complete! Now run backend-verifier.ts to test cross-platform compatibility.");