// Examples of using @enactprotocol/security for field-specific signing

import { SigningService, EnactFieldSelector, GenericFieldSelector, CryptoUtils } from '../packages/security/src/index';
import type { EnactDocument } from '../packages/security/src/types';

console.log("🔐 Enact Protocol Signing Examples\n");

// Generate a key pair for these examples
const keyPair = CryptoUtils.generateKeyPair();
console.log("🔑 Generated key pair for examples");
console.log(`Private key: ${keyPair.privateKey.substring(0, 20)}...`);
console.log(`Public key: ${keyPair.publicKey.substring(0, 20)}...\n`);

// Example Enact tool definition
const exampleTool: EnactDocument = {
  // Required Enact fields
  name: "acme-corp/formatting/prettier",
  description: "Auto-formats JavaScript and TypeScript code using Prettier",
  command: "npx prettier@3.3.3 --write '${file}'",
  
  // Security-critical optional fields
  enact: "1.0.0",
  version: "2.1.0",
  from: "node:18-alpine",
  timeout: "45s",
  annotations: {
    destructiveHint: true,
    title: "Code Formatter",
    readOnlyHint: false
  },
  env: {
    PRETTIER_CONFIG: {
      description: "Path to prettier config file",
      required: false,
      default: ".prettierrc"
    }
  },
  inputSchema: {
    type: "object",
    properties: {
      file: { type: "string", description: "File path to format" },
      parser: { type: "string", enum: ["typescript", "babel"], description: "Parser to use" }
    },
    required: ["file"]
  },
  
  // Non-security-critical fields (metadata)
  tags: ["formatting", "javascript", "typescript", "code-quality"],
  license: "MIT",
  authors: [{ name: "ACME Corp Dev Team", email: "dev@acme.com" }],
  doc: "# Prettier Tool\n\nFormats your JavaScript and TypeScript code using industry-standard Prettier configuration.",
  
  // Generic document fields  
  id: "prettier-tool-v2.1.0",
  content: "Full tool definition with all metadata",
  timestamp: Date.now(),
  metadata: {
    createdBy: "dev-team",
    approvedBy: "security-team",
    environment: "production"
  }
};

console.log("📋 Example 1: Standard Enact Protocol Signing");
console.log("Signs only the security-critical fields defined by Enact protocol\n");

const enactSignature = SigningService.signDocument(exampleTool, keyPair.privateKey, {
  useEnactDefaults: true
});

console.log("✅ Signed security-critical fields:");
console.log(`   ${SigningService.getSignedFields({ useEnactDefaults: true }).join(', ')}`);
console.log(`✅ Signature: ${enactSignature.signature.substring(0, 40)}...`);

// Verify the signature
const enactVerified = SigningService.verifyDocument(exampleTool, enactSignature, {
  useEnactDefaults: true
});
console.log(`✅ Verification: ${enactVerified ? 'VALID' : 'INVALID'}\n`);

console.log("📋 Example 2: Custom Field Selection");
console.log("Sign only specific fields you care about\n");

const customFields = ["name", "command", "version", "license"];
const customSignature = SigningService.signDocument(exampleTool, keyPair.privateKey, {
  includeFields: customFields
});

console.log("✅ Signed custom fields:");
console.log(`   ${customFields.join(', ')}`);
console.log(`✅ Signature: ${customSignature.signature.substring(0, 40)}...`);

const customVerified = SigningService.verifyDocument(exampleTool, customSignature, {
  includeFields: customFields
});
console.log(`✅ Verification: ${customVerified ? 'VALID' : 'INVALID'}\n`);

console.log("📋 Example 3: Enact + Additional Fields");
console.log("Use Enact defaults but add extra fields for your use case\n");

const extendedSignature = SigningService.signDocument(exampleTool, keyPair.privateKey, {
  useEnactDefaults: true,
  additionalCriticalFields: ["license", "tags"]
});

const extendedCanonical = SigningService.getCanonicalDocument(exampleTool, {
  useEnactDefaults: true,
  additionalCriticalFields: ["license", "tags"]
});

console.log("✅ Canonical document includes:");
console.log(`   ${Object.keys(extendedCanonical).join(', ')}`);
console.log(`✅ Signature: ${extendedSignature.signature.substring(0, 40)}...`);

const extendedVerified = SigningService.verifyDocument(exampleTool, extendedSignature, {
  useEnactDefaults: true,
  additionalCriticalFields: ["license", "tags"]
});
console.log(`✅ Verification: ${extendedVerified ? 'VALID' : 'INVALID'}\n`);

console.log("📋 Example 4: Field Exclusion");
console.log("Exclude sensitive fields from signature\n");

const excludedSignature = SigningService.signDocument(exampleTool, keyPair.privateKey, {
  useEnactDefaults: true,
  excludeFields: ["env", "metadata"]  // Exclude potentially sensitive data
});

const excludedCanonical = SigningService.getCanonicalDocument(exampleTool, {
  useEnactDefaults: true,
  excludeFields: ["env", "metadata"]
});

console.log("✅ Excluded sensitive fields, canonical includes:");
console.log(`   ${Object.keys(excludedCanonical).join(', ')}`);
console.log(`✅ Signature: ${excludedSignature.signature.substring(0, 40)}...`);

const excludedVerified = SigningService.verifyDocument(exampleTool, excludedSignature, {
  useEnactDefaults: true,
  excludeFields: ["env", "metadata"]
});
console.log(`✅ Verification: ${excludedVerified ? 'VALID' : 'INVALID'}\n`);

console.log("📋 Example 5: Generic Document Signing");
console.log("For non-Enact documents, use generic defaults\n");

const genericDoc: EnactDocument = {
  id: "document-123",
  content: "Important contract terms and conditions",
  timestamp: Date.now(),
  metadata: {
    type: "contract",
    version: "1.0",
    parties: ["Alice", "Bob"]
  }
};

const genericSignature = SigningService.signDocument(genericDoc, keyPair.privateKey, {
  useEnactDefaults: false  // Use generic defaults: id, content, timestamp
});

console.log("✅ Signed generic document fields:");
console.log(`   ${SigningService.getSignedFields({ useEnactDefaults: false }).join(', ')}`);
console.log(`✅ Signature: ${genericSignature.signature.substring(0, 40)}...`);

const genericVerified = SigningService.verifyDocument(genericDoc, genericSignature, {
  useEnactDefaults: false
});
console.log(`✅ Verification: ${genericVerified ? 'VALID' : 'INVALID'}\n`);

console.log("🎯 Summary:");
console.log("✅ Enact protocol security-critical fields signing");
console.log("✅ Custom field selection for flexible signing policies"); 
console.log("✅ Field exclusion for sensitive data protection");
console.log("✅ Additional critical fields for extended security");
console.log("✅ Generic document signing for non-Enact use cases");
console.log("✅ Automatic empty field exclusion per Enact specification");
console.log("✅ Deterministic canonical JSON for reproducible signatures");

console.log("\n🚀 Your tools are now ready for secure, compliant Enact protocol signing!");