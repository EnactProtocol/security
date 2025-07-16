# Enact Security Web Demo

Interactive web application demonstrating the `@enactprotocol/security-web` package.

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Or serve static files
npm run serve
```

## 🔐 Features Demonstrated

- **Key Generation**: Generate secp256k1 key pairs in the browser
- **Enact Protocol Compliance**: Sign security-critical fields per Enact specification
- **Field Selection**: Choose custom fields or use Enact defaults
- **Document Signing**: Cryptographically sign tool definitions
- **Signature Verification**: Verify document signatures
- **Cross-Platform Testing**: Verify compatibility with backend package

## 📦 Package Usage

This demo shows how to use the published npm package:

```javascript
import { 
    SigningService, 
    CryptoUtils, 
    EnactFieldSelector 
} from '@enactprotocol/security-web';

// Generate keys
const keyPair = CryptoUtils.generateKeyPair();

// Sign with Enact defaults
const signature = SigningService.signDocument(tool, keyPair.privateKey, {
    useEnactDefaults: true
});

// Verify signature
const isValid = SigningService.verifyDocument(tool, signature, {
    useEnactDefaults: true
});
```

## 🎯 Demo Workflow

1. **Generate Keys**: Create a cryptographic key pair
2. **Load Tool**: Use the sample tool or create your own
3. **Select Fields**: Choose Enact defaults or custom field selection
4. **Sign Document**: Create a cryptographic signature
5. **Verify Signature**: Confirm the signature is valid
6. **Test Compatibility**: Run cross-platform compatibility tests

## 🌐 Cross-Platform Compatibility

This web demo creates signatures that are fully compatible with the backend `@enactprotocol/security` package. Signatures created here can be verified on the server, and vice versa.

## 🔧 Technical Details

- **Cryptography**: secp256k1 ECDSA signatures
- **Hashing**: SHA-256 for document hashing
- **Field Selection**: Configurable with Enact Protocol compliance
- **Empty Field Handling**: Automatic exclusion per Enact specification
- **Canonical JSON**: Deterministic document representation

## 📋 Browser Compatibility

- Modern browsers with Web Crypto API support
- ES6 modules required
- Tested in Chrome, Firefox, Safari, Edge