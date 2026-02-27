// ========================================
// Crypto Module
// ========================================
// This module handles core cryptographic operations including:
// - Keypair generation (ECDH)
// - Key derivation utilities (HKDF, PBKDF2)
// - Utility functions for encoding/decoding and ID generation
//

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
// Key Derivation Utilities
// ========================================
function xorStringsToBytes(a, b) {
    if (!a || !b) {
        return new Uint8Array([]);
    }
    const encoder = new TextEncoder();
    const aBytes = encoder.encode(a);
    const bBytes = encoder.encode(b);
    const maxLen = Math.max(aBytes.length, bBytes.length);
    const result = new Uint8Array(maxLen);
    for (let i = 0; i < maxLen; i++) {
        const aByte = i < aBytes.length ? aBytes[i] : 0;
        const bByte = i < bBytes.length ? bBytes[i] : 0;
        result[i] = aByte ^ bByte;
    }
    return result;
}

async function deriveHkdfSaltFromKeyIds(myKeypairId, partnerKeypairId, bits = 256) {
    if (!myKeypairId || !partnerKeypairId) {
        return new Uint8Array([]);
    }
    const xorBytes = xorStringsToBytes(myKeypairId, partnerKeypairId);
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        xorBytes,
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );
    const salt = new TextEncoder().encode('dhkex-keyid-salt');
    const derived = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            hash: 'SHA-256',
            salt,
            iterations: 10000
        },
        keyMaterial,
        bits
    );
    return new Uint8Array(derived);
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

async function deriveSharedSecret(privateKey, publicKey, curveName, infoBytes, saltBytes, curveBits, bits = 256) {
    const sharedSecret = await crypto.subtle.deriveBits(
        {
            name: 'ECDH',
            public: publicKey
        },
        privateKey,
        curveBits
    );
    const result = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: saltBytes || new Uint8Array([]),
            info: infoBytes || new Uint8Array([])
        },
        await crypto.subtle.importKey('raw', sharedSecret, { name: 'HKDF' }, false, ['deriveBits']),
        bits
    );
    return new Uint8Array(result);
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
