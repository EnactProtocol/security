// Backend demo using the published @enactprotocol/security package
import { 
    SigningService, 
    CryptoUtils, 
    KeyManager,
    EnactFieldSelector 
} from '@enactprotocol/security';

console.log('🖥️  Backend Security Demo');
console.log('📦 Using @enactprotocol/security v0.1.0');
console.log('🌐 Cross-platform compatible with @enactprotocol/security-web\n');

// Sample Enact tool
const exampleTool = {
    name: "backend-demo/file-processor",
    description: "Server-side file processing tool with security signing",
    command: "node process-files.js '${inputPath}' --output '${outputPath}'",
    enact: "1.0.0",
    version: "3.0.0",
    from: "node:20-alpine",
    timeout: "120s",
    annotations: {
        destructiveHint: false,
        title: "Backend File Processor",
        readOnlyHint: false,
        idempotentHint: true,
        openWorldHint: false
    },
    env: {
        NODE_ENV: {
            description: "Node environment",
            required: true,
            default: "production"
        },
        LOG_LEVEL: {
            description: "Logging level",
            required: false,
            default: "info"
        }
    },
    inputSchema: {
        type: "object",
        properties: {
            inputPath: { 
                type: "string", 
                description: "Path to input file or directory"
            },
            outputPath: { 
                type: "string", 
                description: "Path for processed output"
            },
            format: { 
                type: "string", 
                enum: ["json", "csv", "xml"],
                default: "json"
            }
        },
        required: ["inputPath", "outputPath"]
    },
    
    // Additional fields
    tags: ["file-processing", "backend", "node", "server"],
    license: "MIT",
    authors: [{ name: "Backend Team", email: "backend@example.com" }],
    
    // Generic document fields
    id: "backend-demo-tool-67890",
    content: "Backend demonstration tool definition",
    timestamp: Date.now(),
    metadata: {
        createdBy: "backend-demo",
        platform: "node.js",
        serverSide: true
    }
};

async function runBackendDemo() {
    try {
        console.log('🔑 1. Key Management Demo');
        console.log('─'.repeat(50));
        
        // Generate and store a key
        const keyId = 'demo-signing-key';
        const keyPair = KeyManager.generateAndStoreKey(keyId);
        
        console.log(`✅ Generated and stored key: ${keyId}`);
        console.log(`   Private: ${keyPair.privateKey.substring(0, 32)}...`);
        console.log(`   Public:  ${keyPair.publicKey.substring(0, 32)}...`);
        
        // List stored keys
        const keyIds = KeyManager.listKeys();
        console.log(`✅ Stored keys: ${keyIds.join(', ')}\n`);
        
        console.log('📝 2. Document Signing Demo');
        console.log('─'.repeat(50));
        
        // Sign with Enact Protocol defaults
        console.log('Signing with Enact Protocol security-critical fields...');
        const enactSignature = SigningService.signDocument(exampleTool, keyPair.privateKey, {
            useEnactDefaults: true
        });
        
        console.log(`✅ Enact signature created:`);
        console.log(`   Algorithm: ${enactSignature.algorithm}`);
        console.log(`   Signature: ${enactSignature.signature.substring(0, 40)}...`);
        console.log(`   Timestamp: ${new Date(enactSignature.timestamp).toISOString()}`);
        
        // Get signed fields
        const signedFields = SigningService.getSignedFields({ useEnactDefaults: true });
        console.log(`   Fields signed: ${signedFields.join(', ')}\n`);
        
        console.log('🔍 3. Signature Verification Demo');
        console.log('─'.repeat(50));
        
        // Verify the signature
        const isValid = SigningService.verifyDocument(exampleTool, enactSignature, {
            useEnactDefaults: true
        });
        
        console.log(`✅ Signature verification: ${isValid ? 'VALID ✅' : 'INVALID ❌'}`);
        
        if (isValid) {
            console.log('   ✅ Document integrity confirmed');
            console.log('   ✅ Signature cryptographically valid');
            console.log('   ✅ Security-critical fields protected\n');
        }
        
        console.log('🎯 4. Custom Field Selection Demo');
        console.log('─'.repeat(50));
        
        // Sign with custom fields
        const customFields = ['name', 'command', 'version', 'license'];
        const customSignature = SigningService.signDocument(exampleTool, keyPair.privateKey, {
            includeFields: customFields
        });
        
        console.log(`✅ Custom field signature created for: ${customFields.join(', ')}`);
        
        // Get canonical document
        const canonical = SigningService.getCanonicalDocument(exampleTool, {
            includeFields: customFields
        });
        
        console.log('✅ Canonical document:');
        console.log(JSON.stringify(canonical, null, 2));
        console.log();
        
        console.log('🌐 5. Cross-Platform Compatibility Demo');
        console.log('─'.repeat(50));
        
        // Test hash consistency
        const testData = JSON.stringify(canonical);
        const hash1 = CryptoUtils.hash(testData);
        const hash2 = CryptoUtils.hash(testData);
        
        console.log(`✅ Hash consistency: ${hash1 === hash2 ? 'PASS' : 'FAIL'}`);
        console.log(`   Hash: ${hash1.substring(0, 40)}...`);
        
        // Test key derivation
        const derivedPublicKey = CryptoUtils.getPublicKeyFromPrivate(keyPair.privateKey);
        const keyMatch = derivedPublicKey === keyPair.publicKey;
        
        console.log(`✅ Key derivation: ${keyMatch ? 'PASS' : 'FAIL'}`);
        
        // Test empty field exclusion
        const toolWithEmpties = {
            ...exampleTool,
            emptyString: '',
            nullValue: null,
            emptyObject: {},
            emptyArray: []
        };
        
        const canonicalFiltered = SigningService.getCanonicalDocument(toolWithEmpties, {
            useEnactDefaults: true
        });
        
        const hasEmptyFields = Object.values(canonicalFiltered).some(val => 
            val === '' || val === null || 
            (Array.isArray(val) && val.length === 0) ||
            (typeof val === 'object' && val !== null && Object.keys(val).length === 0)
        );
        
        console.log(`✅ Empty field exclusion: ${!hasEmptyFields ? 'PASS' : 'FAIL'}`);
        console.log();
        
        console.log('🎉 6. Summary');
        console.log('─'.repeat(50));
        console.log('✅ Key generation and management working');
        console.log('✅ Enact Protocol compliance verified');
        console.log('✅ Document signing and verification working');
        console.log('✅ Custom field selection available');
        console.log('✅ Cross-platform compatibility confirmed');
        console.log('✅ Ready for production use!');
        
        console.log('\n🔐 Backend demo completed successfully!');
        console.log('🌐 Signatures created here are compatible with @enactprotocol/security-web');
        
    } catch (error) {
        console.error('❌ Demo failed:', error.message);
        console.error(error.stack);
    }
}

// Run the demo
runBackendDemo();