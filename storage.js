// ========================================
// Browser Storage Module
// ========================================
// This module handles all browser storage operations including:
// - Persistent storage (localStorage) with optional AES-GCM encryption
// - Session storage (sessionStorage) for temporary keypair persistence
// - Keypair encryption/decryption with password protection

// Note: This file depends on utilities from crypto.js:
// - arrayBufferToBase64()
// - base64ToArrayBuffer()

// ========================================
// Password-Based Encryption (PBKDF2 + AES-GCM)
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

// ========================================
// Session Storage (sessionStorage)
// ========================================
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

// ========================================
// Persistent Storage (localStorage)
// ========================================
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
