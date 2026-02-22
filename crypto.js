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

// ========================================
// Persistent Storage (localStorage with optional encryption)
// ========================================

async function deriveKeyFromPassword(password, salt) {
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );
    
    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptData(data, password) {
    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKeyFromPassword(password, salt);
    
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encoder.encode(JSON.stringify(data))
    );
    
    return {
        encrypted: arrayBufferToBase64(encrypted),
        salt: arrayBufferToBase64(salt),
        iv: arrayBufferToBase64(iv)
    };
}

async function decryptData(encryptedData, password) {
    const decoder = new TextDecoder();
    const salt = base64ToArrayBuffer(encryptedData.salt);
    const iv = base64ToArrayBuffer(encryptedData.iv);
    const key = await deriveKeyFromPassword(password, new Uint8Array(salt));
    
    try {
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: new Uint8Array(iv) },
            key,
            base64ToArrayBuffer(encryptedData.encrypted)
        );
        return JSON.parse(decoder.decode(decrypted));
    } catch (e) {
        throw new Error('Incorrect password or corrupted data');
    }
}

async function loadPersistentKeypairs() {
    try {
        const savedKeys = JSON.parse(localStorage.getItem('dhkex_persistent_keys') || '{}');
        
        for (const [keypairId, storageData] of Object.entries(savedKeys)) {
            // Skip if already loaded in session
            if (state.keypairs.find(k => k.id === keypairId)) continue;
            
            let keyData;
            
            if (storageData.encrypted) {
                // Skip encrypted keys - user must manually load them
                continue;
            } else {
                keyData = storageData.data;
            }
            
            // Import the keys
            const publicKey = await crypto.subtle.importKey(
                'jwk',
                keyData.publicKeyJWK,
                { name: 'ECDH', namedCurve: keyData.curve },
                true,
                []
            );
            
            const privateKey = await crypto.subtle.importKey(
                'jwk',
                keyData.privateKeyJWK,
                { name: 'ECDH', namedCurve: keyData.curve },
                true,
                ['deriveBits']
            );
            
            const publicKeyRaw = base64ToArrayBuffer(keyData.publicKeyRaw);
            
            state.keypairs.push({
                id: keyData.id,
                curve: keyData.curve,
                publicKey: publicKey,
                privateKey: privateKey,
                publicKeyRaw: publicKeyRaw,
                timestamp: keyData.timestamp
            });
        }
        
        if (state.keypairs.length > 0 && !state.activeKeypairId) {
            state.activeKeypairId = state.keypairs[state.keypairs.length - 1].id;
        }
    } catch (e) {
        console.error('Error loading persistent keypairs:', e);
    }
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

function getDeterministicConstraints(constraints) {
    return {
        minLength: constraints.minLength,
        maxLength: constraints.maxLength,
        uppercase: constraints.uppercase,
        lowercase: constraints.lowercase,
        numbers: constraints.numbers,
        special: constraints.special,
        similar: constraints.similar,
        whitespace: constraints.whitespace,
        diacritics: constraints.diacritics,
        emoji: constraints.emoji,
        excluded: constraints.excluded
    };
}

function buildConstraintsInfoBytes(constraints) {
    const deterministic = getDeterministicConstraints(constraints);
    const encoder = new TextEncoder();
    return encoder.encode(JSON.stringify(deterministic));
}

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

function generateVerificationToken(myPublicKeyRaw, partnerPublicKeyRaw, constraints, bits = 24) {
    const myBytes = new Uint8Array(myPublicKeyRaw);
    const partnerBytes = new Uint8Array(partnerPublicKeyRaw);

    // XOR the public keys
    const maxLen = Math.max(myBytes.length, partnerBytes.length);
    const xorResult = new Uint8Array(maxLen);
    
    for (let i = 0; i < maxLen; i++) {
        const myByte = i < myBytes.length ? myBytes[i] : 0;
        const partnerByte = i < partnerBytes.length ? partnerBytes[i] : 0;
        xorResult[i] = myByte ^ partnerByte;
    }

    // Incorporate constraints into the verification token
    // Serialize constraints to bytes
    const constraintsBytes = buildConstraintsInfoBytes(constraints);

    // XOR constraints into the result
    for (let i = 0; i < constraintsBytes.length; i++) {
        xorResult[i % xorResult.length] ^= constraintsBytes[i];
    }

    // Divide into blocks and XOR them together
    const blockSize = Math.ceil(bits / 8);
    let finalBlock = new Uint8Array(blockSize);
    
    for (let i = 0; i < xorResult.length; i++) {
        finalBlock[i % blockSize] ^= xorResult[i];
    }

    // Convert to hex string (limited to requested bits)
    let hexString = '';
    const numBytes = Math.ceil(bits / 8);
    for (let i = 0; i < numBytes; i++) {
        hexString += finalBlock[i].toString(16).padStart(2, '0');
    }

    // Trim to exact bit count
    const hexChars = Math.ceil(bits / 4);
    return hexString.substring(0, hexChars).toUpperCase();
}

function derivePassword(sharedSecret, charset, targetLength) {
    if (charset.length === 0) {
        throw new Error('No character set selected');
    }

    // Use the shared secret to generate a password
    // We'll use the bytes of the shared secret to index into the charset
    let password = '';
    let byteOffset = 0;

    for (let i = 0; i < targetLength; i++) {
        // Use each byte to select a character from the charset
        // For better distribution, we'll use multiple bytes if charset is large
        let index;
        if (charset.length <= 256) {
            index = sharedSecret[byteOffset] % charset.length;
            byteOffset++;
        } else {
            // Use two bytes for larger charsets
            const byte1 = sharedSecret[byteOffset];
            const byte2 = sharedSecret[byteOffset + 1];
            index = ((byte1 << 8) | byte2) % charset.length;
            byteOffset += 2;
        }
        password += charset[index];
    }

    return password;
}

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
            }

            offset = tlv.nextOffset;
        }

        return result;
    } catch (e) {
        console.error('Failed to parse token:', e);
        return null;
    }
}


// ========================================
// Session Storage Restoration
// ========================================
async function restoreKeypairsFromSession() {
    try {
        const savedKeypairs = sessionStorage.getItem('dhkex_keypairs');
        const savedActive = sessionStorage.getItem('dhkex_active');
        
        if (savedKeypairs) {
            const sessionData = JSON.parse(savedKeypairs);
            
            for (const data of sessionData) {
                // Import keys from JWK
                const publicKey = await crypto.subtle.importKey(
                    'jwk',
                    data.publicKeyJWK,
                    { name: 'ECDH', namedCurve: data.curve },
                    true,
                    []
                );
                
                const privateKey = await crypto.subtle.importKey(
                    'jwk',
                    data.privateKeyJWK,
                    { name: 'ECDH', namedCurve: data.curve },
                    true,
                    ['deriveBits']
                );
                
                const keypairData = {
                    id: data.id,
                    curve: data.curve,
                    publicKey: publicKey,
                    privateKey: privateKey,
                    publicKeyRaw: base64ToArrayBuffer(data.publicKeyRaw),
                    timestamp: data.timestamp
                };
                
                state.keypairs.push(keypairData);
            }
            
            if (savedActive) {
                state.activeKeypairId = savedActive;
            }
            
            updateKeypairList();
            if (state.activeKeypairId) {
                updateShareSection();
            }
            
            console.log('Restored ' + state.keypairs.length + ' keypair(s) from session');
        }
    } catch (e) {
        console.error('Failed to restore session:', e);
    }
}

