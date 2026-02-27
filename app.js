// ========================================
// Main Application Logic
// ========================================
// This file manages the application state:
// - Keypair management and storage (in-memory and storage.js)
// - Partner token processing and compatibility checking
// - UI updates based on state changes
// - Integration of crypto.js and password.js functionalities

// ========================================
// Version Constants
// ========================================
const APP_VERSION = 1;

// ========================================
// State Management
// ========================================
const state = {
    keypairs: [],
    activeKeypairId: null,
    partnerPublicKey: null,
    partnerPublicKeyRaw: null,
    partnerKeypairId: null,
    partnerCurve: null,
    myKeypairIdForPartner: null,
    constraints: null
};

const MAX_TOKEN_LENGTH = 8192;

// ========================================
// Bit Security UI Updates
// ========================================
function updateBitSecurityUI(constraints) {
    if (!constraints) return;
    
    const charset = buildCharacterSet(constraints);
    const targetLength = Math.min(constraints.maxLength, Math.floor((constraints.minLength + constraints.maxLength) / 2));
    const bitSecurity = calculateBitSecurity(charset, targetLength);
    
    // Update estimate indicator
    const estimateEl = document.getElementById('bitSecurityEstimate');
    if (estimateEl) {
        const valueEl = estimateEl.querySelector('.security-value');
        if (valueEl) {
            valueEl.textContent = bitSecurity;
        }
        
        // Apply color coding
        estimateEl.classList.remove('weak', 'moderate', 'strong');
        if (bitSecurity < 80) {
            estimateEl.classList.add('weak');
        } else if (bitSecurity < 128) {
            estimateEl.classList.add('moderate');
        } else {
            estimateEl.classList.add('strong');
        }
    }
}

// ========================================
// Version Compatibility Checking
// ========================================
function checkVersionCompatibility(theirVersions) {
    const myVersions = {
        crypto: CRYPTO_VERSION,
        password: PASSWORD_VERSION,
        app: APP_VERSION
    };

    // Check for critical version mismatches (crypto/password)
    // These affect password generation algorithms - incompatible!
    const criticalMismatches = [];
    
    if (theirVersions.crypto !== myVersions.crypto) {
        criticalMismatches.push(`crypto v${theirVersions.crypto} vs v${myVersions.crypto}`);
    }
    
    if (theirVersions.password !== myVersions.password) {
        criticalMismatches.push(`password v${theirVersions.password} vs v${myVersions.password}`);
    }
    
    // Critical mismatches mean different algorithms - passwords will differ!
    if (criticalMismatches.length > 0) {
        return {
            compatible: false,
            reason: `Algorithm version mismatch (${criticalMismatches.join(', ')}). You are running different versions - your generated passwords will differ!`
        };
    }
    
    // Check for app version mismatch (non-critical, UX only)
    if (theirVersions.app !== myVersions.app) {
        return {
            compatible: true,
            reason: `App version mismatch (theirs: v${theirVersions.app}, yours: v${myVersions.app}). This only affects user experience - passwords will still match.`
        };
    }

    // All versions match
    return {
        compatible: true,
        reason: 'All versions match'
    };
}

// ========================================
// Utility Functions
// ========================================
function getConstraints() {
    return {
        minLength: parseInt(document.getElementById('minLength').value),
        maxLength: parseInt(document.getElementById('maxLength').value),
        uppercase: document.getElementById('charUppercase').checked,
        lowercase: document.getElementById('charLowercase').checked,
        numbers: document.getElementById('charNumbers').checked,
        special: document.getElementById('charSpecial').checked,
        similar: document.getElementById('charSimilar').checked,
        whitespace: document.getElementById('charWhitespace').checked,
        diacritics: document.getElementById('charDiacritics').checked,
        emoji: document.getElementById('charEmoji').checked,
        excluded: document.getElementById('excludedChars').value
    };
}

// Note: buildCharacterSet moved to password.js

function copyToClipboard(text, buttonId) {
    navigator.clipboard.writeText(text).then(() => {
        const button = document.getElementById(buttonId);
        const originalText = button.textContent;
        button.textContent = '✓ Copied!';
        setTimeout(() => {
            button.textContent = originalText;
        }, 2000);
    });
}

function highlightCommonConstraints(mergedConstraints) {
    // Add highlighting to checkboxes that are active in merged constraints
    const checkboxes = ['charUppercase', 'charLowercase', 'charNumbers', 'charSpecial', 'charSimilar', 'charWhitespace', 'charDiacritics', 'charEmoji'];
    const constraintKeys = ['uppercase', 'lowercase', 'numbers', 'special', 'similar', 'whitespace', 'diacritics', 'emoji'];
    
    checkboxes.forEach((id, index) => {
        const checkbox = document.getElementById(id);
        const label = checkbox.parentElement;
        const key = constraintKeys[index];
        
        if (mergedConstraints[key]) {
            // Highlight as common
            label.style.backgroundColor = '#c8e6c9';
            label.style.padding = '5px';
            label.style.borderRadius = '4px';
            label.style.fontWeight = 'bold';
        } else {
            // Reset highlighting
            label.style.backgroundColor = '';
            label.style.padding = '';
            label.style.borderRadius = '';
            label.style.fontWeight = '';
        }
    });
}

// ========================================
// Persistent Storage UI Handlers
// ========================================

window.toggleStorageControls = function(keypairId) {
    const controls = document.getElementById(`storage-${keypairId}`);
    controls.classList.toggle('visible');
};

window.saveKeypairToPersistent = async function(keypairId) {
    const kp = state.keypairs.find(k => k.id === keypairId);
    if (!kp) return;
    
    const password = document.getElementById(`pwd-${keypairId}`).value;
    
    try {
        const publicKeyJWK = await crypto.subtle.exportKey('jwk', kp.publicKey);
        const privateKeyJWK = await crypto.subtle.exportKey('jwk', kp.privateKey);
        
        const keyData = {
            id: kp.id,
            curve: kp.curve,
            publicKeyRaw: arrayBufferToBase64(kp.publicKeyRaw),
            publicKeyJWK: publicKeyJWK,
            privateKeyJWK: privateKeyJWK,
            timestamp: kp.timestamp
        };
        
        let storageData;
        if (password) {
            const encrypted = await encryptData(keyData, password);
            storageData = {
                encrypted: true,
                data: encrypted
            };
        } else {
            storageData = {
                encrypted: false,
                data: keyData
            };
        }
        
        const savedKeys = JSON.parse(localStorage.getItem('dhkex_persistent_keys') || '{}');
        savedKeys[keypairId] = storageData;
        localStorage.setItem('dhkex_persistent_keys', JSON.stringify(savedKeys));
        
        document.getElementById(`pwd-${keypairId}`).value = '';
        updateKeypairList();
        showToast('Keypair saved to persistent storage!', 'success');
    } catch (e) {
        showToast('Error saving keypair: ' + e.message, 'error');
    }
};

window.deleteKeypairFromPersistent = function(keypairId) {
    showConfirm('Remove this keypair from persistent storage?', () => {
        const savedKeys = JSON.parse(localStorage.getItem('dhkex_persistent_keys') || '{}');
        delete savedKeys[keypairId];
        localStorage.setItem('dhkex_persistent_keys', JSON.stringify(savedKeys));
        updateKeypairList();
        showToast('Keypair removed from storage', 'info');
    });
};


// ========================================
// Intelligent Key Management
// ========================================
async function ensureKeypairForCurve(curveName) {
    // Find the latest keypair for this curve
    const matchingKeys = state.keypairs.filter(kp => kp.curve === curveName);
    
    if (matchingKeys.length > 0) {
        // Sort by timestamp, newest first
        matchingKeys.sort((a, b) => b.timestamp - a.timestamp);
        const latestKey = matchingKeys[0];
        state.activeKeypairId = latestKey.id;
        updateKeypairList();
        updateShareSection();
        return latestKey;
    } else {
        // No matching keypair, generate one
        console.log('Auto-generating keypair for curve: ' + curveName);
        const newKeypair = await generateKeypair(curveName);
        updateKeypairList();
        updateShareSection();
        return newKeypair;
    }
}

// ========================================
// DOM Helper Functions
// ========================================
function createParagraphWithLabel(labelText, valueText) {
    const p = document.createElement('p');
    p.style.marginBottom = '10px';
    const strong = document.createElement('strong');
    strong.textContent = labelText;
    p.appendChild(strong);
    p.appendChild(document.createTextNode(' ' + valueText));
    return p;
}

function createConstraintGrid(constraints) {
    const grid = document.createElement('div');
    grid.style.marginTop = '10px';
    grid.style.display = 'grid';
    grid.style.gridTemplateColumns = '1fr 1fr';
    grid.style.gap = '5px';

    const addRow = (label, value) => {
        const row = document.createElement('div');
        row.textContent = label + ': ' + (value ? '✓' : '✗');
        grid.appendChild(row);
    };

    addRow('🔤 Uppercase', constraints.uppercase);
    addRow('🔡 Lowercase', constraints.lowercase);
    addRow('🔢 Numbers', constraints.numbers);
    addRow('🔣 Special', constraints.special);
    addRow('👁️ Similar', constraints.similar);
    addRow('␣ Whitespace', constraints.whitespace);
    addRow('é Diacritics', constraints.diacritics);
    addRow('😀 Emoji', constraints.emoji);

    if (constraints.excluded) {
        const excludedRow = document.createElement('div');
        excludedRow.style.gridColumn = '1 / -1';
        excludedRow.textContent = '🚫 Excluded: ' + constraints.excluded;
        grid.appendChild(excludedRow);
    }

    return grid;
}

function showPartnerConstraints(parsed) {
    const partnerPanel = document.getElementById('partnerConstraintsContent');
    partnerPanel.textContent = '';
    
    const wrapper = document.createElement('div');
    wrapper.style.padding = '10px';
    wrapper.style.background = 'white';
    wrapper.style.borderRadius = '6px';

    wrapper.appendChild(createParagraphWithLabel('🆔 Keypair ID:', parsed.keypairId));
    wrapper.appendChild(createParagraphWithLabel('📐 Curve:', parsed.curve));
    wrapper.appendChild(createParagraphWithLabel('📏 Length:', parsed.constraints.minLength + '-' + parsed.constraints.maxLength + ' chars'));
    wrapper.appendChild(createConstraintGrid(parsed.constraints));
    
    partnerPanel.appendChild(wrapper);
}

function showMissingKeypairError(partnerKeypairId) {
    const partnerPanel = document.getElementById('partnerConstraintsContent');
    partnerPanel.textContent = '';

    const alert = document.createElement('div');
    alert.className = 'alert';
    alert.style.background = '#ffebee';
    alert.style.border = '1px solid #ef5350';
    alert.style.color = '#c62828';

    const title = document.createElement('strong');
    title.textContent = '⚠️ Error: Missing Keypair';
    alert.appendChild(title);
    alert.appendChild(document.createElement('br'));

    const line1 = document.createElement('span');
    line1.textContent = 'Partner requested keypair ID ';
    alert.appendChild(line1);

    const idStrong = document.createElement('strong');
    idStrong.textContent = partnerKeypairId;
    alert.appendChild(idStrong);
    alert.appendChild(document.createTextNode(' but it was not found in your key history.'));
    alert.appendChild(document.createElement('br'));

    const line2 = document.createElement('span');
    line2.textContent = 'This token was meant as a response to a specific keypair you previously shared.';
    alert.appendChild(line2);

    partnerPanel.appendChild(alert);
}

// ========================================
// UI Update Functions
// ========================================
function updateKeypairList() {
    const container = document.getElementById('keypairListContainer');
    const list = document.getElementById('keypairList');
    const noKeysMsg = document.getElementById('noKeypairsMessage');

    if (state.keypairs.length === 0) {
        container.classList.add('hidden');
        noKeysMsg.classList.remove('hidden');
        return;
    }

    container.classList.remove('hidden');
    noKeysMsg.classList.add('hidden');
    list.innerHTML = '';

    state.keypairs.forEach(kp => {
        const item = document.createElement('div');
        item.className = 'keypair-item' + (kp.id === state.activeKeypairId ? ' active' : '');
        const timestamp = new Date(kp.timestamp).toLocaleString();
        
        // Check if this key is saved in localStorage
        const savedKeys = JSON.parse(localStorage.getItem('dhkex_persistent_keys') || '{}');
        const isSaved = savedKeys.hasOwnProperty(kp.id);
        const isEncrypted = isSaved && savedKeys[kp.id].encrypted;
        
        item.innerHTML = `
            <div class="keypair-item-header">
                <div class="keypair-info">
                    <span class="keypair-id">ID: ${kp.id}</span>
                    <span class="keypair-curve">Curve: ${kp.curve}</span>
                    <span class="keypair-curve">Created: ${timestamp}</span>
                </div>
                <div class="keypair-actions">
                    <button class="icon-button ${isSaved ? 'saved' : ''}" 
                            onclick="toggleStorageControls('${kp.id}')" 
                            title="${isSaved ? (isEncrypted ? 'Saved with password' : 'Saved') : 'Save to persistent storage'}">
                        ${isEncrypted ? '🔒' : (isSaved ? '💾' : '💾')}
                    </button>
                    <button class="copy-button" onclick="setActiveKeypair('${kp.id}')">
                        ${kp.id === state.activeKeypairId ? 'Active' : 'Select'}
                    </button>
                </div>
            </div>
            <div id="storage-${kp.id}" class="keypair-storage-controls">
                <div class="storage-input-group">
                    <input type="password" 
                           id="pwd-${kp.id}" 
                           placeholder="Password (optional)" />
                    <button onclick="saveKeypairToPersistent('${kp.id}')">
                        ${isSaved ? 'Update' : 'Save'}
                    </button>
                    ${isSaved ? `<button onclick="deleteKeypairFromPersistent('${kp.id}')">Delete</button>` : ''}
                </div>
                <div class="storage-hint">
                    ${isSaved ? 'Saved in browser storage' : 'Leave password blank for unencrypted storage'}
                </div>
            </div>
        `;
        list.appendChild(item);
    });
}

function updateShareSection() {
    const activeKeypair = state.keypairs.find(kp => kp.id === state.activeKeypairId);
    if (!activeKeypair) {
        document.getElementById('shareSection').classList.add('hidden');
        return;
    }

    const constraints = getConstraints();
    const token = createToken(
        activeKeypair.id,
        activeKeypair.publicKeyRaw,
        activeKeypair.curve,
        constraints,
        state.myKeypairIdForPartner
    );

    document.getElementById('myToken').textContent = token;
    
    const baseUrl = window.location.href.split('#')[0].split('?')[0];
    const link = baseUrl + '#token=' + encodeURIComponent(token);
    document.getElementById('shareLink').value = link;

    document.getElementById('shareSection').classList.remove('hidden');
}

async function processPartnerToken(tokenString) {
    const parsed = parseToken(tokenString);
    if (!parsed) {
        showToast('Invalid token format', 'error');
        return;
    }

    // Check version compatibility
    if (parsed.versions) {
        const compatibility = checkVersionCompatibility(parsed.versions);
        if (!compatibility.compatible) {
            // Critical mismatch - algorithms differ, cannot proceed
            showToast('🚫 ' + compatibility.reason, 'error', 10000);
            return;
        } else if (compatibility.reason && !compatibility.reason.includes('match')) {
            // Non-critical warning (app version mismatch only)
            console.warn('Version compatibility:', compatibility.reason);
            showToast('ℹ️ ' + compatibility.reason, 'warning', 6000);
        }
    }

    // Import the partner's public key
    const partnerPublicKey = await crypto.subtle.importKey(
        'raw',
        parsed.publicKeyRaw,
        {
            name: 'ECDH',
            namedCurve: parsed.curve
        },
        false,
        []
    );

    state.partnerPublicKey = partnerPublicKey;
    state.partnerPublicKeyRaw = parsed.publicKeyRaw;
    state.partnerKeypairId = parsed.keypairId;
    state.partnerCurve = parsed.curve;
    
    // If partner specified which keypair we should use, check if we have it
    if (parsed.partnerKeypairId) {
        const targetKeypair = state.keypairs.find(kp => kp.id === parsed.partnerKeypairId);
        if (targetKeypair) {
            state.activeKeypairId = parsed.partnerKeypairId;
            updateKeypairList(); // Update UI to show active keypair
        } else {
            // Show error - we don't have the requested keypair
            showMissingKeypairError(parsed.partnerKeypairId);
            return; // Don't proceed with password generation
        }
    }
    
    // Store partner's keypair ID so our response token includes it
    state.myKeypairIdForPartner = parsed.keypairId;
    
    // Merge constraints (take the most restrictive)
    const currentConstraints = getConstraints();
    state.constraints = {
        minLength: Math.max(parsed.constraints.minLength, currentConstraints.minLength),
        maxLength: Math.min(parsed.constraints.maxLength, currentConstraints.maxLength),
        uppercase: parsed.constraints.uppercase && currentConstraints.uppercase,
        lowercase: parsed.constraints.lowercase && currentConstraints.lowercase,
        numbers: parsed.constraints.numbers && currentConstraints.numbers,
        special: parsed.constraints.special && currentConstraints.special,
        similar: parsed.constraints.similar && currentConstraints.similar,
        whitespace: parsed.constraints.whitespace && currentConstraints.whitespace,
        diacritics: parsed.constraints.diacritics && currentConstraints.diacritics,
        emoji: parsed.constraints.emoji && currentConstraints.emoji,
        excluded: (parsed.constraints.excluded + currentConstraints.excluded).split('').filter((v, i, a) => a.indexOf(v) === i).join('')
    };

    // Show partner constraints in the side panel
    showPartnerConstraints(parsed);
    
    // Highlight common constraints
    highlightCommonConstraints(state.constraints);

    // Update bit security indicator with merged constraints
    updateBitSecurityUI(state.constraints);

    // Update our share section to include partner's keypair ID in our token
    updateShareSection();

    // If we have an active keypair, derive the password
    if (state.activeKeypairId) {
        await deriveAndDisplayPassword();
    }
}

async function deriveAndDisplayPassword() {
    const activeKeypair = state.keypairs.find(kp => kp.id === state.activeKeypairId);
    if (!activeKeypair || !state.partnerPublicKey) {
        return;
    }

    // Check curve compatibility
    if (activeKeypair.curve !== state.partnerCurve) {
        showToast('Curve mismatch! You are using ' + activeKeypair.curve + ' but partner is using ' + state.partnerCurve, 'error', 6000);
        return;
    }

    try {
        // Use password.js to derive password with metadata
        const result = await derivePasswordWithMetadata(
            activeKeypair.privateKey,
            state.partnerPublicKey,
            activeKeypair.curve,
            activeKeypair.id,
            state.partnerKeypairId,
            state.constraints
        );

        // Generate verification token
        const verificationToken = generateVerificationToken(
            activeKeypair.publicKeyRaw,
            state.partnerPublicKeyRaw,
            state.constraints,
            24
        );

        // Display results
        document.getElementById('sharedPassword').textContent = result.password;
        document.getElementById('verificationToken').textContent = verificationToken;
        document.getElementById('resultsSection').classList.remove('hidden');

        // Update actual bit security in results section
        const actualSecurityEl = document.getElementById('bitSecurityActual');
        if (actualSecurityEl) {
            const valueEl = actualSecurityEl.querySelector('.security-value');
            const descEl = actualSecurityEl.querySelector('.security-description');
            
            if (valueEl) {
                valueEl.textContent = result.bitSecurity;
            }
            
            if (descEl) {
                descEl.textContent = `Equivalent to ${result.bitSecurity}-bit symmetric key`;
            }
            
            // Apply color coding
            actualSecurityEl.classList.remove('weak', 'moderate', 'strong');
            if (result.bitSecurity < 80) {
                actualSecurityEl.classList.add('weak');
            } else if (result.bitSecurity < 128) {
                actualSecurityEl.classList.add('moderate');
            } else {
                actualSecurityEl.classList.add('strong');
            }
        }
    } catch (e) {
        showToast('Failed to derive password: ' + e.message, 'error');
        console.error('Password derivation error:', e);
    }
}

// ========================================
// Global Functions (for onclick handlers)
// ========================================
window.setActiveKeypair = function(keypairId) {
    state.activeKeypairId = keypairId;
    saveKeypairsToSession();
    updateKeypairList();
    updateShareSection();
};

// ========================================
// Event Handlers
// ========================================
document.getElementById('generateKeypair').addEventListener('click', async function() {
    const curve = document.getElementById('ecCurve').value;
    const button = this;
    button.disabled = true;
    button.textContent = 'Generating...';

    try {
        await generateKeypair(curve);
        updateKeypairList();
        updateShareSection();
    } catch (e) {
        showToast('Failed to generate keypair: ' + e.message, 'error');
    } finally {
        button.disabled = false;
        button.textContent = 'Generate New Keypair';
    }
});

// Auto-select or generate keypair when curve changes
document.getElementById('ecCurve').addEventListener('change', async function() {
    const curve = this.value;
    await ensureKeypairForCurve(curve);
});

document.getElementById('copyToken').addEventListener('click', function() {
    const token = document.getElementById('myToken').textContent;
    copyToClipboard(token, 'copyToken');
});

document.getElementById('copyLink').addEventListener('click', function() {
    const link = document.getElementById('shareLink').value;
    copyToClipboard(link, 'copyLink');
});

document.getElementById('loadPartnerToken').addEventListener('click', async function() {
    await loadPartnerTokenFromTextarea();
});

// Auto-import partner tokens when pasted
let partnerTokenTimeout;
document.getElementById('partnerToken').addEventListener('input', function() {
    clearTimeout(partnerTokenTimeout);
    partnerTokenTimeout = setTimeout(async () => {
        const tokenString = this.value.trim();
        if (tokenString && tokenString.length > 20) { // Basic validation
            try {
                // Try to parse to see if it's valid
                const parsed = parseToken(tokenString);
                if (parsed && parsed.publicKeyRaw) {
                    console.log('Auto-importing partner token...');
                    await loadPartnerTokenFromTextarea();
                }
            } catch (e) {
                // Invalid token, don't auto-import
            }
        }
    }, 500); // Wait 500ms after user stops typing
});

async function loadPartnerTokenFromTextarea() {
    const tokenString = document.getElementById('partnerToken').value.trim();
    if (!tokenString) {
        showToast('Please paste a token first', 'warning');
        return;
    }

    const button = document.getElementById('loadPartnerToken');
    button.disabled = true;
    button.textContent = 'Loading...';

    try {
        await processPartnerToken(tokenString);
    } catch (e) {
        showToast('Failed to process token: ' + e.message, 'error');
    } finally {
        button.disabled = false;
        button.textContent = "Load Partner's Token";
    }
}

document.getElementById('copyPassword').addEventListener('click', function() {
    const password = document.getElementById('sharedPassword').textContent;
    copyToClipboard(password, 'copyPassword');
});

document.getElementById('copyVerification').addEventListener('click', function() {
    const token = document.getElementById('verificationToken').textContent;
    copyToClipboard(token, 'copyVerification');
});

// Update share section when constraints change
['minLength', 'maxLength', 'charUppercase', 'charLowercase', 'charNumbers', 'charSpecial', 'charSimilar', 'charWhitespace', 'charDiacritics', 'charEmoji', 'excludedChars'].forEach(id => {
    const element = document.getElementById(id);
    element.addEventListener('change', async function() {
        // Update bit security estimate
        const constraints = state.partnerPublicKey ? state.constraints : getConstraints();
        updateBitSecurityUI(constraints);
        
        if (state.activeKeypairId) {
            updateShareSection();
            if (state.partnerPublicKey) {
                await processPartnerToken(document.getElementById('partnerToken').value.trim());
            }
        }
    });
});


// ========================================
// Initialization
// ========================================
window.addEventListener('DOMContentLoaded', async function() {
    // Load persistent keypairs from localStorage (unencrypted only)
    await loadPersistentKeypairs();
    
    // Restore keypairs from session storage
    await restoreKeypairsFromSession();

    // Check for token in URL fragment or query and show welcome banner if appropriate
    const hashParams = new URLSearchParams(window.location.hash.startsWith('#') ? window.location.hash.slice(1) : '');
    const urlParams = new URLSearchParams(window.location.search);
    const tokenParam = hashParams.get('token') || hashParams.get('t') || urlParams.get('token') || urlParams.get('t');
    
    if (tokenParam) {
        // Show welcome banner if not previously dismissed
        if (!sessionStorage.getItem('welcomeBannerDismissed')) {
            document.getElementById('welcomeWrapper').classList.remove('hidden');
        }
        
        // Auto-fill the partner token field
        const partnerTokenField = document.getElementById('partnerToken');
        if (partnerTokenField && !partnerTokenField.value) {
            partnerTokenField.value = tokenParam;
            // Trigger auto-import
            partnerTokenField.dispatchEvent(new Event('input'));
        }
    }

    // Ensure we have a keypair for the default curve
    const defaultCurve = document.getElementById('ecCurve').value;
    await ensureKeypairForCurve(defaultCurve);
    
    // Initialize bit security indicator
    updateBitSecurityUI(getConstraints());
});

// ========================================
// Help Modal Functions
// ========================================
function openHelpModal() {
    document.getElementById('helpModal').classList.add('active');
}

function closeHelpModal() {
    document.getElementById('helpModal').classList.remove('active');
}

function closeHelpModalOnOverlay(event) {
    if (event.target === event.currentTarget) {
        closeHelpModal();
    }
}

function closeWelcomeBanner() {
    document.getElementById('welcomeWrapper').classList.add('hidden');
    sessionStorage.setItem('welcomeBannerDismissed', 'true');
}

// ========================================
// Toast Notification System
// ========================================
function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };
    
    toast.innerHTML = `
        <div class="toast-icon">${icons[type] || icons.info}</div>
        <div class="toast-message">${message}</div>
        <button class="toast-close" onclick="closeToast(this)">&times;</button>
    `;
    
    container.appendChild(toast);
    
    if (duration > 0) {
        setTimeout(() => {
            closeToast(toast.querySelector('.toast-close'));
        }, duration);
    }
}

function closeToast(button) {
    const toast = button.parentElement;
    toast.classList.add('removing');
    setTimeout(() => {
        toast.remove();
    }, 300);
}

window.showConfirm = function(message, onConfirm, title = 'Confirm Action') {
    const overlay = document.getElementById('confirmOverlay');
    const messageEl = document.getElementById('confirmMessage');
    const titleEl = document.getElementById('confirmTitle');
    
    messageEl.textContent = message;
    titleEl.textContent = title;
    overlay.classList.add('active');
    
    // Store callback for when user confirms
    window._confirmCallback = onConfirm;
};

window.closeConfirm = function(confirmed) {
    const overlay = document.getElementById('confirmOverlay');
    overlay.classList.remove('active');
    
    if (confirmed && window._confirmCallback) {
        window._confirmCallback();
    }
    
    window._confirmCallback = null;
};

// Close confirm on overlay click
document.getElementById('confirmOverlay')?.addEventListener('click', function(event) {
    if (event.target === this) {
        closeConfirm(false);
    }
});
