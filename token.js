// ========================================
// Token Module
// ========================================
// This module handles token encoding/decoding using TLV (Type-Length-Value) format.
// Tokens are used to exchange public keys and password constraints between users.
//
// Dependencies:
// - crypto.js: arrayBufferToBase64, base64ToArrayBuffer
// - password.js: getDefaultConstraints, constraintsToFlags, flagsToConstraints

// ========================================
// Constants
// ========================================
const MAX_TOKEN_LENGTH = 8192;

// Supported curve names for ECDH
const CURVE_NAMES = ['P-256', 'P-384', 'P-521'];

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
// Encoder/Decoder Functions
// ========================================
// Reusable encoder/decoder functions for different data types
const encoders = {
    string: (value) => new TextEncoder().encode(value),
    uint8: (value) => {
        const num = parseInt(value);
        if (isNaN(num) || num < 0 || num > 255) {
            throw new Error('Must be 0-255');
        }
        return new Uint8Array([num]);
    },
    varint: (value) => {
        const num = parseInt(value);
        if (isNaN(num) || num < 0) {
            throw new Error('Must be positive integer');
        }
        return encodeVarInt(num);
    },
    binary: (value) => {
        // Pass through raw bytes (ArrayBuffer or Uint8Array)
        if (value instanceof ArrayBuffer) {
            return new Uint8Array(value);
        } else if (value instanceof Uint8Array) {
            return value;
        }
        throw new Error('Binary value must be ArrayBuffer or Uint8Array');
    },
    curve: (value) => {
        const curveIndex = CURVE_NAMES.indexOf(value);
        if (curveIndex >= 0) {
            return new Uint8Array([curveIndex]);
        }
        const num = parseInt(value);
        if (isNaN(num) || num < 0 || num > 255) {
            throw new Error('Invalid curve');
        }
        return new Uint8Array([num]);
    },
    bitfield: (value) => {
        // Value is an integer (e.g., 0x0F for flags)
        const num = parseInt(value);
        if (isNaN(num) || num < 0) {
            throw new Error('Must be non-negative integer');
        }
        // Encode as minimal bytes needed
        if (num === 0) return new Uint8Array(0);
        const bytes = [];
        let n = num;
        while (n > 0) {
            bytes.unshift(n & 0xFF);
            n = n >>> 8;
        }
        return new Uint8Array(bytes);
    }
};

const decoders = {
    string: (bytes) => new TextDecoder().decode(bytes),
    uint8: (bytes) => bytes.length > 0 ? bytes[0] : 0,
    varint: (bytes) => decodeVarInt(bytes.buffer, 0, 0).value,
    binary: (bytes) => bytes,
    curve: (bytes) => {
        const index = bytes.length > 0 ? bytes[0] : 0;
        return CURVE_NAMES[index] || index;
    },
    bitfield: (bytes) => {
        // Return as integer (e.g., 0x0F)
        if (bytes.length === 0) return 0;
        let result = 0;
        for (let i = 0; i < bytes.length; i++) {
            result = (result << 8) | bytes[i];
        }
        return result;
    }
};

// ========================================
// TLV Tag Definitions
// ========================================
// Tag definitions for TLV encoding
const TAG_DEFINITIONS = {
    0x01: { name: 'Keypair ID', type: 'string', length: 6 },
    0x02: { name: 'Public Key', type: 'binary', length: null },
    0x03: { name: 'Curve', type: 'curve', length: 1 },
    0x04: { name: 'Min Length', type: 'uint8', length: 1 },
    0x05: { name: 'Max Length', type: 'uint8', length: 1 },
    0x06: { name: 'Charset Flags', type: 'bitfield', length: null },
    0x07: { name: 'Excluded Chars', type: 'string', length: null },
    0x08: { name: 'Partner Keypair ID', type: 'string', length: 6 },
    0x09: { name: 'Crypto Version', type: 'varint', length: null },
    0x0A: { name: 'Password Version', type: 'varint', length: null },
    0x0B: { name: 'App Version', type: 'varint', length: null }
};

// Get sorted list of tag names for dropdowns
function getTagNameOptions() {
    const options = [];
    for (const tag in TAG_DEFINITIONS) {
        options.push({ tag: parseInt(tag), name: TAG_DEFINITIONS[tag].name });
    }
    options.sort((a, b) => a.tag - b.tag);
    return options;
}

// Get field definition (with optional custom type override)
function getTagDefinition(tag, customType = null) {
    const def = TAG_DEFINITIONS[tag] || { name: 'Custom', type: 'binary', length: null };
    if (customType) {
        return { ...def, type: customType };
    }
    return def;
}

// Encode value based on tag (or custom type)
function encodeTagValue(tag, value, customType = null) {
    const def = getTagDefinition(tag, customType);
    const encoder = encoders[def.type] || encoders.binary;
    try {
        return encoder(value);
    } catch (e) {
        throw new Error(`Failed to encode ${def.name}: ${e.message}`);
    }
}

// Decode value based on tag (or custom type)
function decodeTagValue(tag, bytes, customType = null) {
    const def = getTagDefinition(tag, customType);
    const decoder = decoders[def.type] || decoders.binary;
    try {
        return decoder(bytes);
    } catch (e) {
        return 'Error: ' + e.message;
    }
}

// ========================================
// TLV Encoding/Decoding
// ========================================
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

// ========================================
// Token Creation and Parsing
// ========================================
function createToken(keypairId, publicKeyRaw, curve, constraints, partnerKeypairId, versions) {
    const parts = [];

    // Tag 0x01: Keypair ID
    parts.push(encodeTLV(0x01, encodeTagValue(0x01, keypairId)));

    // Tag 0x02: Public Key
    parts.push(encodeTLV(0x02, encodeTagValue(0x02, publicKeyRaw)));

    // Tag 0x03: Curve
    parts.push(encodeTLV(0x03, encodeTagValue(0x03, curve)));

    // Tag 0x04: Min Length
    parts.push(encodeTLV(0x04, encodeTagValue(0x04, constraints.minLength)));

    // Tag 0x05: Max Length
    parts.push(encodeTLV(0x05, encodeTagValue(0x05, constraints.maxLength)));

    // Tag 0x06: Charset Flags
    const flags = constraintsToFlags(constraints);
    if (flags !== 0) {
        parts.push(encodeTLV(0x06, encodeTagValue(0x06, flags)));
    }

    // Tag 0x07: Excluded chars (only if non-empty)
    if (constraints.excluded) {
        parts.push(encodeTLV(0x07, encodeTagValue(0x07, constraints.excluded)));
    }

    // Tag 0x08: Partner Keypair ID (only if provided)
    if (partnerKeypairId) {
        parts.push(encodeTLV(0x08, encodeTagValue(0x08, partnerKeypairId)));
    }

    // Tag 0x09: Crypto Version (varInt)
    parts.push(encodeTLV(0x09, encodeTagValue(0x09, versions.crypto)));

    // Tag 0x0A: Password Version (varInt)
    parts.push(encodeTLV(0x0A, encodeTagValue(0x0A, versions.password)));

    // Tag 0x0B: App Version (varInt)
    parts.push(encodeTLV(0x0B, encodeTagValue(0x0B, versions.app)));

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
            constraints: getDefaultConstraints()
        };

        // Tag handlers for special cases
        const handlers = {
            0x01: (val) => result.keypairId = decodeTagValue(0x01, val),
            0x02: (val) => result.publicKeyRaw = decodeTagValue(0x02, val),
            0x03: (val) => result.curve = decodeTagValue(0x03, val),
            0x04: (val) => result.constraints.minLength = decodeTagValue(0x04, val),
            0x05: (val) => result.constraints.maxLength = decodeTagValue(0x05, val),
            0x06: (val) => Object.assign(result.constraints, flagsToConstraints(decodeTagValue(0x06, val))),
            0x07: (val) => result.constraints.excluded = decodeTagValue(0x07, val),
            0x08: (val) => result.partnerKeypairId = decodeTagValue(0x08, val),
            0x09: (val) => result.versions.crypto = decodeTagValue(0x09, val),
            0x0A: (val) => result.versions.password = decodeTagValue(0x0A, val),
            0x0B: (val) => result.versions.app = decodeTagValue(0x0B, val)
        };

        let offset = 0;
        while (offset < buffer.byteLength) {
            const tlv = decodeTLV(buffer, offset);
            if (!tlv) break;
            
            const handler = handlers[tlv.tag];
            if (handler) handler(tlv.value);
            
            offset = tlv.nextOffset;
        }

        return result;
    } catch (e) {
        console.error('Failed to parse token:', e);
        return null;
    }
}
