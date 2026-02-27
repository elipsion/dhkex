// ========================================
// Crypto Module
// ========================================
// This module handles all cryptographic operations including:
// - Keypair generation (ECDH)
// - Token encoding/decoding (TLV format)
// - Variable-length integer encoding/decoding (VarInt)
// - Utility functions for encoding/decoding and ID generation

// ========================================
// Version Constants
// ========================================
const CRYPTO_VERSION = 1;

// ========================================
// Utility Functions
// ========================================
function generateId(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let id = '';
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    for (let i = 0; i < length; i++) {
        id += chars[array[i] % chars.length];
    }
    return id;
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// ========================================
// Variable-Length Integer Encoding (VarInt)
// ========================================
// Encodes integers efficiently: 1 byte for 0-127, 2 bytes for 128-16383, etc.
function encodeVarInt(value) {
    if (value < 0) {
        throw new Error('VarInt encoding only supports non-negative integers');
    }
    
    if (value < 128) {
        // Single byte: 0xxxxxxx
        return new Uint8Array([value]);
    } else if (value < 16384) {
        // Two bytes: 10xxxxxx xxxxxxxx
        return new Uint8Array([
            0x80 | (value >> 8),
            value & 0xFF
        ]);
    } else if (value < 2097152) {
        // Three bytes: 110xxxxx xxxxxxxx xxxxxxxx
        return new Uint8Array([
            0xC0 | (value >> 16),
            (value >> 8) & 0xFF,
            value & 0xFF
        ]);
    } else {
        // Four bytes: 11111111 xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx (max ~4 billion)
        return new Uint8Array([
            0xFF,
            (value >> 24) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF
        ]);
    }
}

// Decodes variable-length integer from buffer at offset
// If defaultValue is provided, returns { value: defaultValue, nextOffset: offset } instead of throwing exceptions
function decodeVarInt(buffer, offset, defaultValue) {
    const hasDefault = arguments.length >= 3;
    const view = new Uint8Array(buffer);
    
    if (offset >= view.length) {
        if (hasDefault) {
            return { value: defaultValue, nextOffset: offset };
        }
        throw new Error('VarInt decoding: offset out of bounds');
    }
    
    const firstByte = view[offset];
    
    if ((firstByte & 0x80) === 0) {
        // Single byte: 0xxxxxxx
        return { value: firstByte, nextOffset: offset + 1 };
    } else if ((firstByte & 0xC0) === 0x80) {
        // Two bytes: 10xxxxxx xxxxxxxx
        const value = ((firstByte & 0x3F) << 8) | view[offset + 1];
        return { value, nextOffset: offset + 2 };
    } else if ((firstByte & 0xE0) === 0xC0) {
        // Three bytes: 110xxxxx xxxxxxxx xxxxxxxx
        const value = ((firstByte & 0x1F) << 16) | (view[offset + 1] << 8) | view[offset + 2];
        return { value, nextOffset: offset + 3 };
    } else if (firstByte === 0xFF) {
        // Four bytes: 11111111 xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        const value = (view[offset + 1] << 24) | (view[offset + 2] << 16) | (view[offset + 3] << 8) | view[offset + 4];
        return { value, nextOffset: offset + 5 };
    } else {
        if (hasDefault) {
            return { value: defaultValue, nextOffset: offset };
        }
        throw new Error('Invalid VarInt encoding');
    }
}

// ========================================
// Cryptographic Functions
// ========================================
async function generateKeypair(curveName) {
    const keypair = await crypto.subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: curveName
        },
        true,
        ['deriveBits']
    );

    const publicKeyRaw = await crypto.subtle.exportKey('raw', keypair.publicKey);
    const keypairId = generateId(6);

    const keypairData = {
        id: keypairId,
        curve: curveName,
        publicKey: keypair.publicKey,
        privateKey: keypair.privateKey,
        publicKeyRaw: publicKeyRaw,
        timestamp: Date.now()
    };

    state.keypairs.push(keypairData);
    state.activeKeypairId = keypairId;

    // Store in sessionStorage
    saveKeypairsToSession();

    return keypairData;
}

async function saveKeypairsToSession() {
    // Export keys as JWK for storage
    const sessionData = [];
    for (const kp of state.keypairs) {
        const publicKeyJWK = await crypto.subtle.exportKey('jwk', kp.publicKey);
        const privateKeyJWK = await crypto.subtle.exportKey('jwk', kp.privateKey);
        sessionData.push({
            id: kp.id,
            curve: kp.curve,
            publicKeyRaw: arrayBufferToBase64(kp.publicKeyRaw),
            publicKeyJWK: publicKeyJWK,
            privateKeyJWK: privateKeyJWK,
            timestamp: kp.timestamp
        });
    }
    sessionStorage.setItem('dhkex_keypairs', JSON.stringify(sessionData));
    sessionStorage.setItem('dhkex_active', state.activeKeypairId);
}

// Note: Password generation functions moved to password.js
// Note: Browser storage functions moved to storage.js

// ========================================
// Token Management (TLV Encoding)
// ========================================
// TLV Tags:
// 0x01: Keypair ID (string)
// 0x02: Public Key (binary)
// 0x03: Curve (1 byte: 0=P-256, 1=P-384, 2=P-521)
// 0x04: Min Length (1 byte)
// 0x05: Max Length (1 byte)
// 0x06: Charset Flags (variable length, bit-packed)
//       Byte 0: bit 0=uppercase, 1=lowercase, 2=numbers, 3=special, 4=similar, 5=whitespace, 6=diacritics, 7=emoji
// 0x07: Excluded chars (string)
// 0x08: Partner Keypair ID (string) - ID of the keypair that should be used to respond
// 0x09: Crypto Version (varInt) - Version of crypto.js
// 0x0A: Password Version (varInt) - Version of password.js
// 0x0B: App Version (varInt) - Version of app.js

function encodeTLV(tag, value) {
    let valueBytes;
    
    if (typeof value === 'string') {
        const encoder = new TextEncoder();
        valueBytes = encoder.encode(value);
    } else if (typeof value === 'number') {
        valueBytes = new Uint8Array([value]);
    } else if (value instanceof ArrayBuffer || value instanceof Uint8Array) {
        valueBytes = new Uint8Array(value);
    } else {
        throw new Error('Unsupported value type for TLV encoding');
    }

    const length = valueBytes.length;
    let result;

    if (length < 128) {
        // Short form: 1 byte length
        result = new Uint8Array(2 + length);
        result[0] = tag;
        result[1] = length;
        result.set(valueBytes, 2);
    } else {
        // Long form: 2 bytes length (supports up to 65535)
        result = new Uint8Array(4 + length);
        result[0] = tag;
        result[1] = 0x80 | 0x02; // Length is encoded in next 2 bytes
        result[2] = (length >> 8) & 0xFF;
        result[3] = length & 0xFF;
        result.set(valueBytes, 4);
    }

    return result;
}

function decodeTLV(buffer, offset) {
    const view = new Uint8Array(buffer);
    
    if (offset >= view.length) {
        return null;
    }

    const tag = view[offset];
    let length;
    let valueOffset;

    if (view[offset + 1] & 0x80) {
        // Long form
        const lengthBytes = view[offset + 1] & 0x7F;
        if (lengthBytes === 2) {
            length = (view[offset + 2] << 8) | view[offset + 3];
            valueOffset = offset + 4;
        } else {
            throw new Error('Unsupported length encoding');
        }
    } else {
        // Short form
        length = view[offset + 1];
        valueOffset = offset + 2;
    }

    const value = view.slice(valueOffset, valueOffset + length);
    const nextOffset = valueOffset + length;

    return { tag, value, nextOffset };
}

function createToken(keypairId, publicKeyRaw, curve, constraints, partnerKeypairId = null) {
    const parts = [];

    // Tag 0x09: Crypto Version (varInt)
    parts.push(encodeTLV(0x09, encodeVarInt(CRYPTO_VERSION)));

    // Tag 0x0A: Password Version (varInt)
    parts.push(encodeTLV(0x0A, encodeVarInt(PASSWORD_VERSION)));

    // Tag 0x0B: App Version (varInt)
    parts.push(encodeTLV(0x0B, encodeVarInt(APP_VERSION)));

    // Tag 0x01: Keypair ID
    parts.push(encodeTLV(0x01, keypairId));

    // Tag 0x02: Public Key
    parts.push(encodeTLV(0x02, publicKeyRaw));

    // Tag 0x03: Curve (encode as number)
    const curveMap = { 'P-256': 0, 'P-384': 1, 'P-521': 2 };
    parts.push(encodeTLV(0x03, curveMap[curve] || 0));

    // Tag 0x04: Min Length
    parts.push(encodeTLV(0x04, constraints.minLength));

    // Tag 0x05: Max Length
    parts.push(encodeTLV(0x05, constraints.maxLength));

    // Tag 0x06: Charset Flags (multi-byte support)
    let flags = 0;
    if (constraints.uppercase) flags |= 0x01;
    if (constraints.lowercase) flags |= 0x02;
    if (constraints.numbers) flags |= 0x04;
    if (constraints.special) flags |= 0x08;
    if (constraints.similar) flags |= 0x10;
    if (constraints.whitespace) flags |= 0x20;
    if (constraints.diacritics) flags |= 0x40;
    if (constraints.emoji) flags |= 0x80;
    
    // Only add if flags is non-zero
    if (flags !== 0) {
        parts.push(encodeTLV(0x06, flags));
    }

    // Tag 0x07: Excluded chars (only if non-empty)
    if (constraints.excluded) {
        parts.push(encodeTLV(0x07, constraints.excluded));
    }

    // Tag 0x08: Partner Keypair ID (only if provided)
    if (partnerKeypairId) {
        parts.push(encodeTLV(0x08, partnerKeypairId));
    }

    // Concatenate all parts
    const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }

    // Base64 encode the binary TLV data
    return arrayBufferToBase64(result.buffer);
}

function parseToken(tokenString) {
    try {
        if (!tokenString || tokenString.length > MAX_TOKEN_LENGTH) {
            return null;
        }
        const buffer = base64ToArrayBuffer(tokenString);
        const result = {
            keypairId: null,
            publicKeyRaw: null,
            curve: null,
            partnerKeypairId: null,
            versions: {
                crypto: 1,
                password: 1,
                app: 1
            },
            constraints: {
                minLength: 16,
                maxLength: 32,
                uppercase: true,
                lowercase: true,
                numbers: true,
                special: true,
                similar: true,
                whitespace: false,
                diacritics: false,
                emoji: false,
                excluded: ''
            }
        };

        const curveMap = ['P-256', 'P-384', 'P-521'];
        let offset = 0;

        while (offset < buffer.byteLength) {
            const tlv = decodeTLV(buffer, offset);
            if (!tlv) break;

            const decoder = new TextDecoder();

            switch (tlv.tag) {
                case 0x01: // Keypair ID
                    result.keypairId = decoder.decode(tlv.value);
                    break;
                case 0x02: // Public Key
                    result.publicKeyRaw = tlv.value.buffer;
                    break;
                case 0x03: // Curve
                    result.curve = curveMap[tlv.value[0]] || 'P-256';
                    break;
                case 0x04: // Min Length
                    result.constraints.minLength = tlv.value[0];
                    break;
                case 0x05: // Max Length
                    result.constraints.maxLength = tlv.value[0];
                    break;
                case 0x06: // Charset Flags
                    const flags = tlv.value[0];
                    result.constraints.uppercase = !!(flags & 0x01);
                    result.constraints.lowercase = !!(flags & 0x02);
                    result.constraints.numbers = !!(flags & 0x04);
                    result.constraints.special = !!(flags & 0x08);
                    result.constraints.similar = !!(flags & 0x10);
                    result.constraints.whitespace = !!(flags & 0x20);
                    result.constraints.diacritics = !!(flags & 0x40);
                    result.constraints.emoji = !!(flags & 0x80);
                    break;
                case 0x07: // Excluded chars
                    result.constraints.excluded = decoder.decode(tlv.value);
                    break;
                case 0x08: // Partner Keypair ID
                    result.partnerKeypairId = decoder.decode(tlv.value);
                    break;
                case 0x09: // Crypto Version
                    result.versions.crypto = decodeVarInt(tlv.value.buffer, 0, 0).value;
                    break;
                case 0x0A: // Password Version
                    result.versions.password = decodeVarInt(tlv.value.buffer, 0, 0).value;
                    break;
                case 0x0B: // App Version
                    result.versions.app = decodeVarInt(tlv.value.buffer, 0, 0).value;
                    break;
            }

            offset = tlv.nextOffset;
        }

        return result;
    } catch (e) {
        console.error('Failed to parse token:', e);
        return null;
    }
}

