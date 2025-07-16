// enact-signing.ts
import * as crypto from 'crypto';
import * as fs from 'fs';

// Types for the Enact Protocol
export interface ToolDefinition {
  name: string;
  description: string;
  command: string;
  enact?: string;
  protocol_version?: string;
  version?: string;
  from?: string;
  timeout?: string;
  inputSchema?: object;
  input_schema?: object;
  env?: object;
  env_vars?: object;
  annotations?: object;
  [key: string]: any;
}

export interface SignatureMetadata {
  signature: string;
  signer: string;
  algorithm: string;
  created: string;
}

export interface CanonicalJsonResult {
  canonicalJson: string;
  debugLog?: string[];
}

// Utility functions matching the browser implementation exactly
function isEmptyOrOnlyEmptyObjects(value: any): boolean {
  if (value === null || value === undefined) return true;
  
  if (Array.isArray(value)) {
    return value.length === 0 || value.every(item => 
      typeof item === 'object' && item !== null && Object.keys(item).length === 0
    );
  }
  
  if (typeof value === 'object' && value !== null) {
    return Object.keys(value).length === 0;
  }
  
  return false;
}

function sortObjectKeys(obj: any): any {
  if (obj === null || obj === undefined) return obj;
  
  if (Array.isArray(obj)) {
    return obj.map(sortObjectKeys);
  }
  
  if (typeof obj === 'object' && obj !== null) {
    const sorted: any = {};
    const keys = Object.keys(obj).sort();
    for (const key of keys) {
      sorted[key] = sortObjectKeys(obj[key]);
    }
    return sorted;
  }
  
  return obj;
}

function createCanonicalToolDefinition(tool: ToolDefinition): any {
  const canonical: any = {};
  
  // Core required fields - only add if not empty
  if (tool.name && !isEmptyOrOnlyEmptyObjects(tool.name)) {
    canonical.name = tool.name;
  }
  if (tool.description && !isEmptyOrOnlyEmptyObjects(tool.description)) {
    canonical.description = tool.description;
  }
  if (tool.command && !isEmptyOrOnlyEmptyObjects(tool.command)) {
    canonical.command = tool.command;
  }
  
  // Protocol version
  const enactValue = tool.enact || tool.protocol_version;
  if (enactValue && !isEmptyOrOnlyEmptyObjects(enactValue)) {
    canonical.enact = enactValue;
  }
  
  // Tool version
  if (tool.version && !isEmptyOrOnlyEmptyObjects(tool.version)) {
    canonical.version = tool.version;
  }
  
  // Container/execution environment
  if (tool.from && !isEmptyOrOnlyEmptyObjects(tool.from)) {
    canonical.from = tool.from;
  }
  
  // Execution timeout
  if (tool.timeout && !isEmptyOrOnlyEmptyObjects(tool.timeout)) {
    canonical.timeout = tool.timeout;
  }
  
  // Input schema
  const inputSchemaValue = tool.input_schema || tool.inputSchema;
  if (inputSchemaValue && !isEmptyOrOnlyEmptyObjects(inputSchemaValue)) {
    canonical.inputSchema = inputSchemaValue;
  }
  
  // Environment variables
  const envValue = tool.env_vars || tool.env;
  if (envValue && !isEmptyOrOnlyEmptyObjects(envValue)) {
    canonical.env = envValue;
  }
  
  // Execution metadata/annotations
  if (tool.annotations && !isEmptyOrOnlyEmptyObjects(tool.annotations)) {
    canonical.annotations = tool.annotations;
  }

  return canonical;
}

export function createCanonicalJson(tool: ToolDefinition, withDebug = false): CanonicalJsonResult {
  const debugLog: string[] = [];
  
  if (withDebug) {
    debugLog.push('🔍 DEBUG: Starting canonical JSON creation');
    debugLog.push('🔍 DEBUG: Input tool object:');
    debugLog.push(JSON.stringify(tool, null, 2));
  }
  
  // Step 1: Create canonical representation
  const canonical = createCanonicalToolDefinition(tool);
  
  if (withDebug) {
    debugLog.push('🔍 DEBUG: After createCanonicalToolDefinition:');
    debugLog.push(JSON.stringify(canonical, null, 2));
  }
  
  // Step 2: Extra cleaning step
  const cleanedCanonical: any = {};
  for (const [key, value] of Object.entries(canonical)) {
    if (withDebug) {
      debugLog.push(`🔍 DEBUG: Checking field '${key}': isEmpty=${isEmptyOrOnlyEmptyObjects(value)}`);
    }
    
    if (!isEmptyOrOnlyEmptyObjects(value)) {
      cleanedCanonical[key] = sortObjectKeys(value);
      if (withDebug) {
        debugLog.push(`✅ DEBUG: Including field '${key}'`);
      }
    } else {
      if (withDebug) {
        debugLog.push(`❌ DEBUG: Excluding field '${key}' (empty)`);
      }
    }
  }
  
  if (withDebug) {
    debugLog.push('🔍 DEBUG: Final cleaned canonical:');
    debugLog.push(JSON.stringify(cleanedCanonical, null, 2));
  }
  
  // Step 3: Create JSON
  const canonicalJson = JSON.stringify(cleanedCanonical);
  
  if (withDebug) {
    debugLog.push('🔍 DEBUG: Canonical JSON string:');
    debugLog.push(canonicalJson);
    debugLog.push(`🔍 DEBUG: Canonical JSON length: ${canonicalJson.length}`);
  }
  
  return withDebug ? { canonicalJson, debugLog } : { canonicalJson };
}

// Key generation functions
export function generateKeyPair(): { privateKey: string; publicKey: string } {
  const keyPair = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1', // P-256
    publicKeyEncoding: {
      type: 'spki',
      format: 'der'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'der'
    }
  });

  return {
    privateKey: keyPair.privateKey.toString('base64'),
    publicKey: keyPair.publicKey.toString('base64')
  };
}

// Signing functions
export function signTool(tool: ToolDefinition, privateKeyBase64: string, withDebug = false): {
  signature: string;
  metadata: SignatureMetadata;
  canonicalJson: string;
  debugLog?: string[];
} {
  try {
    // Create canonical JSON
    const result = createCanonicalJson(tool, withDebug);
    const { canonicalJson, debugLog } = result;

    if (withDebug) {
      debugLog?.push('🔐 DEBUG: Starting signing process');
      debugLog?.push(`🔍 DEBUG: Canonical JSON length: ${canonicalJson.length}`);
    }

    // Create private key object from Base64
    const privateKeyDer = Buffer.from(privateKeyBase64, 'base64');
    const privateKey = crypto.createPrivateKey({
      key: privateKeyDer,
      format: 'der',
      type: 'pkcs8'
    });

    // Create hash of canonical JSON
    const hash = crypto.createHash('sha256');
    hash.update(canonicalJson, 'utf8');
    const toolHash = hash.digest();

    if (withDebug) {
      debugLog?.push(`🔍 DEBUG: Hash length: ${toolHash.length}`);
      debugLog?.push(`🔍 DEBUG: Hash (hex): ${toolHash.toString('hex')}`);
    }

    // Sign the hash
    const sign = crypto.createSign('SHA256');
    sign.update(canonicalJson, 'utf8');
    const signature = sign.sign(privateKey);

    if (withDebug) {
      debugLog?.push(`🔍 DEBUG: Raw signature bytes length: ${signature.length}`);
    }

    // Convert to Base64
    const signatureB64 = signature.toString('base64');

    if (withDebug) {
      debugLog?.push(`🔍 DEBUG: Base64 signature length: ${signatureB64.length}`);
      debugLog?.push(`🔍 DEBUG: Base64 signature: ${signatureB64}`);
    }

    // Create signature metadata
    const metadata: SignatureMetadata = {
      signature: signatureB64,
      signer: `user-${Date.now()}`,
      algorithm: 'ecdsa-p256-sha256',
      created: new Date().toISOString()
    };

    return {
      signature: signatureB64,
      metadata,
      canonicalJson,
      debugLog: withDebug ? debugLog : undefined
    };

  } catch (error) {
    throw new Error(`Signing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// Verification functions
export function verifySignature(
  tool: ToolDefinition, 
  signatureBase64: string, 
  publicKeyBase64: string,
  withDebug = false
): {
  isValid: boolean;
  canonicalJson: string;
  debugLog?: string[];
} {
  try {
    // Create canonical JSON
    const result = createCanonicalJson(tool, withDebug);
    const { canonicalJson, debugLog } = result;

    if (withDebug) {
      debugLog?.push('🔐 DEBUG: Starting verification process');
      debugLog?.push(`🔍 DEBUG: Canonical JSON for verification: ${canonicalJson}`);
    }

    // Create public key object from Base64
    const publicKeyDer = Buffer.from(publicKeyBase64, 'base64');
    const publicKey = crypto.createPublicKey({
      key: publicKeyDer,
      format: 'der',
      type: 'spki'
    });

    // Convert Base64 signature to buffer
    const signatureBuffer = Buffer.from(signatureBase64, 'base64');

    if (withDebug) {
      debugLog?.push(`🔍 DEBUG: Signature buffer length: ${signatureBuffer.length}`);
    }

    // Verify signature
    const verify = crypto.createVerify('SHA256');
    verify.update(canonicalJson, 'utf8');
    const isValid = verify.verify(publicKey, signatureBuffer);

    if (withDebug) {
      debugLog?.push(`🔍 DEBUG: Verification result: ${isValid}`);
    }

    return {
      isValid,
      canonicalJson,
      debugLog: withDebug ? debugLog : undefined
    };

  } catch (error) {
    if (withDebug) {
      console.error('Verification error:', error);
    }
    return {
      isValid: false,
      canonicalJson: '',
      debugLog: withDebug ? [`❌ Verification error: ${error instanceof Error ? error.message : 'Unknown error'}`] : undefined
    };
  }
}

// File-based key management
export function saveKeysToFile(privateKey: string, publicKey: string, filename = 'enact-keys'): void {
  const keys = {
    privateKey,
    publicKey,
    generated: new Date().toISOString()
  };

  fs.writeFileSync(`${filename}.json`, JSON.stringify(keys, null, 2));
  console.log(`✅ Keys saved to ${filename}.json`);
}

export function loadKeysFromFile(filename = 'enact-keys'): { privateKey: string; publicKey: string } {
  try {
    const data = fs.readFileSync(`${filename}.json`, 'utf8');
    const keys = JSON.parse(data);
    return {
      privateKey: keys.privateKey,
      publicKey: keys.publicKey
    };
  } catch (error) {
    throw new Error(`Failed to load keys from ${filename}.json: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// Complete example usage
export function example(): void {
  console.log('🔐 Enact Protocol Signing & Verification Example\n');

  // 1. Generate key pair
  console.log('1. Generating key pair...');
  const { privateKey, publicKey } = generateKeyPair();
  console.log('✅ Key pair generated');
  console.log(`Private key length: ${privateKey.length}`);
  console.log(`Public key length: ${publicKey.length}\n`);

  // 2. Sample tool definition
  const toolDefinition: ToolDefinition = {
    name: "kgroves88/hello-world",
    description: "A simple greeting tool that says hello to a person",
    command: "echo 'Hello, ${name}! Welcome to Enact Protocol.'",
    enact: "1.0.0",
    version: "1.0.0",
    timeout: "10s",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Name of the person to greet",
          default: "World"
        }
      },
      required: ["name"]
    },
    annotations: {
      readOnlyHint: true,
      idempotentHint: true,
      destructiveHint: false,
      openWorldHint: false
    }
  };

  // 3. Sign the tool
  console.log('2. Signing tool...');
  const signResult = signTool(toolDefinition, privateKey, true);
  console.log('✅ Tool signed successfully');
  console.log(`Signature: ${signResult.signature}`);
  console.log(`Canonical JSON: ${signResult.canonicalJson}\n`);

  // 4. Verify the signature
  console.log('3. Verifying signature...');
  const verifyResult = verifySignature(toolDefinition, signResult.signature, publicKey, true);
  
  if (verifyResult.isValid) {
    console.log('✅ Signature is valid!');
    console.log('The tool definition is authentic and has not been tampered with.\n');
  } else {
    console.log('❌ Signature is invalid!');
    console.log('The tool definition may have been tampered with.\n');
  }

  // 5. Save keys to file
  console.log('4. Saving keys to file...');
  saveKeysToFile(privateKey, publicKey, 'example-keys');

  // 6. Test with modified tool (should fail verification)
  console.log('5. Testing with modified tool (should fail)...');
  const modifiedTool = { ...toolDefinition, description: "Modified description" };
  const modifiedVerifyResult = verifySignature(modifiedTool, signResult.signature, publicKey);
  
  if (modifiedVerifyResult.isValid) {
    console.log('❌ This should not happen - modified tool verified as valid!');
  } else {
    console.log('✅ Correctly detected modified tool as invalid');
  }

  console.log('\n🎉 Example completed successfully!');
}

// CLI interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const command = args[0];

  switch (command) {
    case 'example':
      example();
      break;
      
    case 'generate':
      const keys = generateKeyPair();
      console.log('Private Key (Base64):');
      console.log(keys.privateKey);
      console.log('\nPublic Key (Base64):');
      console.log(keys.publicKey);
      break;
      
    case 'sign':
      if (args.length < 3) {
        console.error('Usage: ts-node enact-signing.ts sign <tool-file.json> <private-key-base64>');
        process.exit(1);
      }
      const toolFile = args[1];
      const privKey = args[2];
      try {
        const toolData = JSON.parse(fs.readFileSync(toolFile, 'utf8'));
        const result = signTool(toolData, privKey, true);
        console.log('Signature:', result.signature);
        console.log('Metadata:', JSON.stringify(result.metadata, null, 2));
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : 'Unknown error');
        process.exit(1);
      }
      break;
      
    case 'verify':
      if (args.length < 4) {
        console.error('Usage: ts-node enact-signing.ts verify <tool-file.json> <signature-base64> <public-key-base64>');
        process.exit(1);
      }
      const verifyToolFile = args[1];
      const signature = args[2];
      const pubKey = args[3];
      try {
        const toolData = JSON.parse(fs.readFileSync(verifyToolFile, 'utf8'));
        const result = verifySignature(toolData, signature, pubKey, true);
        console.log('Valid:', result.isValid);
        if (result.debugLog) {
          console.log('\nDebug Log:');
          result.debugLog.forEach(log => console.log(log));
        }
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : 'Unknown error');
        process.exit(1);
      }
      break;
      
    default:
      console.log('Usage:');
      console.log('  ts-node enact-signing.ts example');
      console.log('  ts-node enact-signing.ts generate');
      console.log('  ts-node enact-signing.ts sign <tool-file.json> <private-key-base64>');
      console.log('  ts-node enact-signing.ts verify <tool-file.json> <signature-base64> <public-key-base64>');
      break;
  }
}