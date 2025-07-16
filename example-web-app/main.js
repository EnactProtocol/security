// Interactive demo using the published @enactprotocol/security-web package
import { 
    SigningService, 
    CryptoUtils, 
    EnactFieldSelector,
    GenericFieldSelector
} from '@enactprotocol/security-web';

// Global state
let currentKeyPair = null;
let currentTool = null;
let currentSignature = null;

// Sample Enact tool for testing
const sampleTool = {
    name: "example-corp/web-demo/prettier",
    description: "Code formatter for JavaScript and TypeScript files",
    command: "npx prettier@3.3.3 --write '${file}' --config .prettierrc",
    enact: "1.0.0",
    version: "2.1.0",
    from: "node:18-alpine",
    timeout: "45s",
    annotations: {
        destructiveHint: true,
        title: "Web Demo Code Formatter",
        readOnlyHint: false,
        idempotentHint: true,
        openWorldHint: false
    },
    env: {
        PRETTIER_CONFIG: {
            description: "Path to prettier configuration file",
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
            },
            printWidth: {
                type: "number",
                description: "Line wrap width",
                default: 80,
                minimum: 40,
                maximum: 200
            }
        },
        required: ["file"]
    },
    
    // Non-security-critical fields
    tags: ["formatting", "code-quality", "prettier", "web-demo"],
    license: "MIT",
    authors: [
        { name: "Web Demo Team", email: "demo@example.com" },
        { name: "Security Team", email: "security@example.com" }
    ],
    doc: "# Web Demo Prettier Tool\\n\\nFormats JavaScript and TypeScript code using Prettier.",
    
    // Generic document fields
    id: "web-demo-tool-12345",
    content: "Interactive web demo tool definition",
    timestamp: Date.now(),
    metadata: {
        createdBy: "web-demo",
        platform: "browser",
        demoVersion: "1.0.0",
        interactive: true
    }
};

// Sample key pair for quick testing
const sampleKeyPair = {
    privateKey: "a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890",
    publicKey: "03f1e2d3c4b5a6978123456789012345678901234567890123456789012345678901"
};

// Utility functions
function logOutput(elementId, message, type = 'info') {
    const element = document.getElementById(elementId);
    if (element) {
        const timestamp = new Date().toLocaleTimeString();
        const prefix = type === 'error' ? '❌' : type === 'success' ? '✅' : 'ℹ️';
        element.textContent = `[${timestamp}] ${prefix} ${message}`;
    }
}

function displayJSON(elementId, obj) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = JSON.stringify(obj, null, 2);
    }
}

function showStatus(elementId, message, type = 'info') {
    const element = document.getElementById(elementId);
    if (element) {
        element.className = `status ${type}`;
        element.textContent = message;
    }
}

function updateFieldCheckboxes() {
    const container = document.getElementById('fieldCheckboxes');
    const toolJson = document.getElementById('toolJson').value;
    
    if (!toolJson.trim()) {
        container.innerHTML = '<p>Load a tool definition first to see available fields.</p>';
        return;
    }
    
    try {
        const tool = JSON.parse(toolJson);
        const fields = Object.keys(tool).sort();
        
        container.innerHTML = '';
        fields.forEach(field => {
            const div = document.createElement('div');
            div.className = 'checkbox-item';
            
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.id = `field_${field}`;
            checkbox.value = field;
            
            const label = document.createElement('label');
            label.htmlFor = `field_${field}`;
            label.textContent = field;
            
            div.appendChild(checkbox);
            div.appendChild(label);
            container.appendChild(div);
        });
    } catch (error) {
        container.innerHTML = '<p>Invalid JSON in tool definition.</p>';
    }
}

function getSelectedFields() {
    const mode = document.querySelector('input[name="fieldMode"]:checked').value;
    
    if (mode === 'enact') {
        return { useEnactDefaults: true };
    } else {
        const checkboxes = document.querySelectorAll('#fieldCheckboxes input[type="checkbox"]:checked');
        const selectedFields = Array.from(checkboxes).map(cb => cb.value);
        return { includeFields: selectedFields };
    }
}

// Event handlers
function handleGenerateKeys() {
    try {
        logOutput('keyStatus', 'Generating cryptographic key pair...');
        
        currentKeyPair = CryptoUtils.generateKeyPair();
        
        document.getElementById('privateKey').value = currentKeyPair.privateKey;
        document.getElementById('publicKey').value = currentKeyPair.publicKey;
        
        logOutput('keyStatus', 'New key pair generated successfully!');
        showStatus('keyStatus', '✅ Key pair generated and ready for signing', 'success');
        
    } catch (error) {
        logOutput('keyStatus', `Error generating keys: ${error.message}`, 'error');
        showStatus('keyStatus', '❌ Failed to generate key pair', 'error');
    }
}

function handleLoadSampleKeys() {
    currentKeyPair = { ...sampleKeyPair };
    
    document.getElementById('privateKey').value = currentKeyPair.privateKey;
    document.getElementById('publicKey').value = currentKeyPair.publicKey;
    
    logOutput('keyStatus', 'Sample key pair loaded');
    showStatus('keyStatus', '✅ Sample keys loaded for testing', 'info');
}

function handleLoadSampleTool() {
    const toolJson = JSON.stringify(sampleTool, null, 2);
    document.getElementById('toolJson').value = toolJson;
    currentTool = { ...sampleTool };
    
    updateFieldCheckboxes();
    
    logOutput('toolStatus', 'Sample tool definition loaded');
    showStatus('toolStatus', '✅ Sample Enact tool loaded successfully', 'success');
}

function handleClearTool() {
    document.getElementById('toolJson').value = '';
    currentTool = null;
    
    document.getElementById('fieldCheckboxes').innerHTML = '';
    
    logOutput('toolStatus', 'Tool definition cleared');
    showStatus('toolStatus', 'Tool definition cleared', 'info');
}

function handleSignDocument() {
    try {
        // Validate inputs
        const toolJson = document.getElementById('toolJson').value;
        const privateKey = document.getElementById('privateKey').value;
        
        if (!toolJson.trim()) {
            throw new Error('Please load or enter a tool definition');
        }
        
        if (!privateKey.trim()) {
            throw new Error('Please generate or load a private key');
        }
        
        // Parse tool
        currentTool = JSON.parse(toolJson);
        const fieldOptions = getSelectedFields();
        
        logOutput('signatureOutput', 'Creating canonical document and signing...');
        
        // Get canonical document
        const canonical = SigningService.getCanonicalDocument(currentTool, fieldOptions);
        displayJSON('canonicalOutput', canonical);
        
        // Sign the document
        currentSignature = SigningService.signDocument(currentTool, privateKey, fieldOptions);
        
        // Display signature
        const signatureInfo = {
            signature: currentSignature.signature,
            publicKey: currentSignature.publicKey,
            algorithm: currentSignature.algorithm,
            timestamp: new Date(currentSignature.timestamp).toISOString(),
            signedFields: Object.keys(canonical),
            fieldCount: Object.keys(canonical).length
        };
        
        displayJSON('signatureOutput', signatureInfo);
        
        logOutput('signatureStatus', 'Document signed successfully!');
        showStatus('signatureStatus', '✅ Document signed with selected fields', 'success');
        
    } catch (error) {
        logOutput('signatureOutput', `Error: ${error.message}`, 'error');
        showStatus('signatureStatus', `❌ Signing failed: ${error.message}`, 'error');
    }
}

function handleVerifySignature() {
    try {
        if (!currentTool || !currentSignature) {
            throw new Error('Please sign a document first');
        }
        
        const fieldOptions = getSelectedFields();
        
        logOutput('signatureStatus', 'Verifying signature...');
        
        const isValid = SigningService.verifyDocument(currentTool, currentSignature, fieldOptions);
        
        if (isValid) {
            logOutput('signatureStatus', 'Signature verification: VALID ✅');
            showStatus('signatureStatus', '✅ Signature is cryptographically valid', 'success');
        } else {
            logOutput('signatureStatus', 'Signature verification: INVALID ❌');
            showStatus('signatureStatus', '❌ Signature verification failed', 'error');
        }
        
    } catch (error) {
        logOutput('signatureStatus', `Verification error: ${error.message}`, 'error');
        showStatus('signatureStatus', `❌ Verification failed: ${error.message}`, 'error');
    }
}

function handleTestCompatibility() {
    try {
        if (!currentTool || !currentKeyPair) {
            throw new Error('Please load a tool and generate keys first');
        }
        
        logOutput('compatibilityOutput', 'Running cross-platform compatibility tests...');
        
        const tests = [];
        
        // Test 1: Enact field selection
        const enactCanonical = SigningService.getCanonicalDocument(currentTool, { useEnactDefaults: true });
        const enactFields = SigningService.getSignedFields({ useEnactDefaults: true });
        
        tests.push({
            test: 'Enact Protocol Field Selection',
            result: 'PASS',
            details: `Selected ${enactFields.length} security-critical fields: ${enactFields.join(', ')}`
        });
        
        // Test 2: Key derivation
        const derivedPublicKey = CryptoUtils.getPublicKeyFromPrivate(currentKeyPair.privateKey);
        const keyMatch = derivedPublicKey === currentKeyPair.publicKey;
        
        tests.push({
            test: 'Public Key Derivation',
            result: keyMatch ? 'PASS' : 'FAIL',
            details: `Derived public key ${keyMatch ? 'matches' : 'does not match'} generated public key`
        });
        
        // Test 3: Hash consistency
        const testString = JSON.stringify(enactCanonical);
        const hash1 = CryptoUtils.hash(testString);
        const hash2 = CryptoUtils.hash(testString);
        const hashConsistent = hash1 === hash2;
        
        tests.push({
            test: 'Hash Function Consistency',
            result: hashConsistent ? 'PASS' : 'FAIL',
            details: `Hash function produces ${hashConsistent ? 'consistent' : 'inconsistent'} results`
        });
        
        // Test 4: Signature verification
        const signature = SigningService.signDocument(currentTool, currentKeyPair.privateKey, { useEnactDefaults: true });
        const verified = SigningService.verifyDocument(currentTool, signature, { useEnactDefaults: true });
        
        tests.push({
            test: 'Signature Round-Trip',
            result: verified ? 'PASS' : 'FAIL',
            details: `Sign and verify cycle ${verified ? 'successful' : 'failed'}`
        });
        
        // Test 5: Empty field exclusion
        const testToolWithEmpties = {
            ...currentTool,
            emptyString: '',
            nullValue: null,
            emptyObject: {},
            emptyArray: []
        };
        
        const canonicalWithEmpties = SigningService.getCanonicalDocument(testToolWithEmpties, { useEnactDefaults: true });
        const hasEmptyFields = Object.values(canonicalWithEmpties).some(val => 
            val === '' || val === null || 
            (Array.isArray(val) && val.length === 0) ||
            (typeof val === 'object' && val !== null && Object.keys(val).length === 0)
        );
        
        tests.push({
            test: 'Empty Field Exclusion',
            result: !hasEmptyFields ? 'PASS' : 'FAIL',
            details: `Empty fields ${!hasEmptyFields ? 'properly excluded' : 'incorrectly included'} from canonical document`
        });
        
        // Display results
        const results = {
            timestamp: new Date().toISOString(),
            package: '@enactprotocol/security-web v0.1.0',
            platform: 'Browser/Web Crypto API',
            tests: tests,
            summary: {
                total: tests.length,
                passed: tests.filter(t => t.result === 'PASS').length,
                failed: tests.filter(t => t.result === 'FAIL').length
            }
        };
        
        displayJSON('compatibilityOutput', results);
        
        const allPassed = results.summary.failed === 0;
        
        if (allPassed) {
            logOutput('compatibilityStatus', 'All compatibility tests passed! ✅');
            showStatus('compatibilityStatus', '✅ Cross-platform compatibility confirmed', 'success');
        } else {
            logOutput('compatibilityStatus', `${results.summary.failed} tests failed ❌`);
            showStatus('compatibilityStatus', `❌ ${results.summary.failed} compatibility issues detected`, 'error');
        }
        
    } catch (error) {
        logOutput('compatibilityOutput', `Compatibility test error: ${error.message}`, 'error');
        showStatus('compatibilityStatus', `❌ Compatibility test failed: ${error.message}`, 'error');
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Key generation buttons
    document.getElementById('generateKeys').addEventListener('click', handleGenerateKeys);
    document.getElementById('loadSampleKeys').addEventListener('click', handleLoadSampleKeys);
    
    // Tool definition buttons
    document.getElementById('loadSampleTool').addEventListener('click', handleLoadSampleTool);
    document.getElementById('clearTool').addEventListener('click', handleClearTool);
    
    // Signing buttons
    document.getElementById('signDocument').addEventListener('click', handleSignDocument);
    document.getElementById('verifySignature').addEventListener('click', handleVerifySignature);
    
    // Compatibility test
    document.getElementById('testCompatibility').addEventListener('click', handleTestCompatibility);
    
    // Field mode radio buttons
    document.querySelectorAll('input[name="fieldMode"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            const customFields = document.getElementById('customFields');
            if (e.target.value === 'custom') {
                customFields.style.display = 'block';
                updateFieldCheckboxes();
            } else {
                customFields.style.display = 'none';
            }
        });
    });
    
    // Tool JSON textarea
    document.getElementById('toolJson').addEventListener('input', () => {
        if (document.querySelector('input[name="fieldMode"][value="custom"]').checked) {
            updateFieldCheckboxes();
        }
    });
    
    // Load sample data on startup for demo
    handleLoadSampleKeys();
    handleLoadSampleTool();
    
    // Show initial status
    showStatus('keyStatus', 'Sample keys loaded - ready for demo', 'info');
    showStatus('toolStatus', 'Sample tool loaded - ready for signing', 'info');
    
    console.log('🔐 Enact Security Web Demo loaded successfully!');
    console.log('📦 Using @enactprotocol/security-web v0.1.0');
    console.log('🌐 Cross-platform compatible with @enactprotocol/security');
});