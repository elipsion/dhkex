# 🔐 DH Key Exchange - Secure Password Generator

A client-side web application for generating matching passwords between two parties using Elliptic Curve Diffie-Hellman (ECDH) key exchange. Perfect for IT professionals who need to securely establish shared passwords without transmitting them.

🌐 **[Live Demo](https://elipsion.github.io/dhkex/)**

## ✨ Features

- **🔒 100% Client-Side**: All cryptographic operations happen in your browser - no server communication
- **🔑 ECDH Key Exchange**: Uses Web Crypto API with P-256, P-384, or P-521 curves
- **🎯 Customizable Constraints**: Configure password length, character sets, and exclusions
- **✓ Verification Tokens**: 24-bit tokens for out-of-band verification to prevent MITM attacks
- **💾 Session Persistence**: Keypairs stored in browser session storage (auto-cleared on tab close)
- **📦 Compact Tokens**: Binary TLV encoding for efficient token exchange
- **🔄 Smart Key Management**: Automatic keypair selection and generation
- **🌐 URL Token Support**: Share tokens via URL parameters for convenience
- **🛟 Built-in Help**: Comprehensive documentation and workflow guidance

## 🚀 How It Works

### Workflow

1. **User A** opens the page and configures password constraints (length, character types, excluded characters)
2. **User A** generates an EC keypair and shares their token with User B (via email, chat, etc.)
3. **User B** opens the page, pastes User A's token, which automatically imports the constraints
4. **User B** generates their own keypair and shares their token back to User A
5. **Both users** now have matching shared passwords and verification tokens
6. **Verify out-of-band**: Both users compare the 6-character verification token (phone call, video chat, etc.)
7. **Use the password**: Once verified, both users can use the shared password with confidence

### Security Principles

- **Public Key Cryptography**: Each user generates a keypair (private + public key). Only public keys are exchanged
- **Shared Secret Derivation**: Using ECDH, both parties independently compute the same shared secret without ever transmitting it
- **Password Generation**: The shared secret is deterministically converted to a password using the agreed constraints
- **Verification Token**: Incorporates both public keys and password parameters to detect any mismatch
- **Web Crypto API**: All cryptography uses browser-native, audited implementations

## 🔒 Privacy & Security

✅ **100% Client-Side**: All cryptographic operations happen in your browser using JavaScript  
✅ **No Server Communication**: This page makes zero network requests after loading  
✅ **No Tracking or Analytics**: No cookies, no tracking pixels, no telemetry of any kind  
✅ **Session Storage Only**: Keypairs are stored in your browser's session storage (cleared when tab closes)  
✅ **Open Source**: Single HTML file - view source to audit the complete code  

**You control token distribution.** This tool only provides the cryptographic mechanism to generate matching passwords.

## 💡 Use Cases

- **Database Passwords**: Generate shared admin passwords for database systems
- **Service Accounts**: Create matching passwords for shared service accounts
- **Emergency Access**: Set up emergency access passwords with colleagues
- **Secure Handoff**: Transfer passwords during system migrations or handoffs
- **VPN Tunnels**: Derive shared PSKs with external organizations

## 📖 Usage

### Basic Usage

1. Open the application in your browser
2. Configure password constraints (or use defaults)
3. A keypair is automatically generated
4. Copy your token and share it with your partner (via any channel)
5. Paste your partner's token when received
6. Both parties see matching passwords and verification tokens
7. Verify the verification token out-of-band before using the password

### URL Parameters

Share tokens directly via URL:
```
https://elipsion.github.io/dhkex/?token=BASE64_TOKEN
```

Supports both `?token=` and `?t=` parameters.

### Supported Curves

- **P-256** (Default) - NIST P-256 / secp256r1
- **P-384** - NIST P-384 / secp384r1  
- **P-521** - NIST P-521 / secp521r1

### Character Sets

- Uppercase letters (A-Z)
- Lowercase letters (a-z)
- Numbers (0-9)
- Special characters (!@#$%^&*()_+-=[]{}|;:,.<>?)
- Similar characters (O0Il1)
- Whitespace (space, tab)
- Diacritics (àáâäèéêë...)
- Emoji (😀🚀🎉...)

## 🛠️ Technical Details

### Token Format

Tokens use TLV (Type-Length-Value) binary encoding with base64 wrapping:

- **0x01**: Keypair ID (string)
- **0x02**: Public Key (binary)
- **0x03**: Curve (1 byte: 0=P-256, 1=P-384, 2=P-521)
- **0x04**: Min Length (1 byte)
- **0x05**: Max Length (1 byte)
- **0x06**: Charset Flags (bit-packed)
- **0x07**: Excluded chars (string)
- **0x08**: Partner Keypair ID reference (string)

### Password Derivation

1. Calculate required bytes based on character set size
2. Derive exact number of bits from ECDH shared secret
3. Use bytes to deterministically index into character set
4. Generate password of target length

### Verification Token

- XOR both public keys together
- XOR in serialized password constraints
- Hash to 24 bits (6 hex characters)
- Must match between both parties

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🤝 Contributing

This is a single-file application designed for simplicity and auditability. Contributions welcome via pull requests.

## ⚠️ Important Notes

- **Always verify tokens out-of-band**: Use phone, video call, or in-person verification
- **Tokens contain public information**: Safe to transmit via any channel (email, chat, SMS)
- **Session storage only**: Keypairs are cleared when you close the browser tab
- **Not for high-security environments**: This tool is for convenience, not maximum security
- **Browser compatibility**: Requires modern browser with Web Crypto API support

## 🔗 Links

- [Web Crypto API Documentation](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [Elliptic Curve Diffie-Hellman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
- [NIST Elliptic Curves](https://csrc.nist.gov/projects/elliptic-curve-cryptography)

---

**Built with ❤️ for IT professionals who value security and simplicity**
