// ========================================
// Password Generation Module
// ========================================
// This module handles all password generation logic including:
// - Shared secret derivation (ECDH + HKDF)
// - Character set building from constraints
// - Password generation from shared secrets
// - Verification token generation
// - Bit-equivalent security calculations

// ========================================
// Version Constants
// ========================================
const PASSWORD_VERSION = 1;

// ========================================
// Constraint Bitfield Conversion
// ========================================
// Convert constraints object to integer bitfield
function constraintsToFlags(constraints) {
    let flags = 0;
    if (constraints.uppercase) flags |= 0x01;
    if (constraints.lowercase) flags |= 0x02;
    if (constraints.numbers) flags |= 0x04;
    if (constraints.special) flags |= 0x08;
    if (constraints.similar) flags |= 0x10;
    if (constraints.whitespace) flags |= 0x20;
    if (constraints.diacritics) flags |= 0x40;
    if (constraints.emoji) flags |= 0x80;
    return flags;
}

// Convert integer bitfield to constraints object
function flagsToConstraints(flags) {
    return {
        uppercase: !!(flags & 0x01),
        lowercase: !!(flags & 0x02),
        numbers: !!(flags & 0x04),
        special: !!(flags & 0x08),
        similar: !!(flags & 0x10),
        whitespace: !!(flags & 0x20),
        diacritics: !!(flags & 0x40),
        emoji: !!(flags & 0x80)
    };
}

// ========================================
// Character Set Building
// ========================================
function buildCharacterSet(constraints) {
    let charset = '';
    if (constraints.uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (constraints.lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (constraints.numbers) charset += '0123456789';
    if (constraints.special) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    if (constraints.whitespace) charset += ' \t';
    if (constraints.diacritics) charset += 'àáâäèéêëìíîïòóôöùúûüçñãõÀÁÂÄÈÉÊËÌÍÎÏÒÓÔÖÙÚÛÜÇÑÃÕ';
    if (constraints.emoji) {
      charset += '😀😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞😟😠😡😢😣😤😥😦😧😨😩😪😫😬😭😮😯😰😱😲😳😴😵😶😷😸😹😺😻😼😽😾😿🙀🙁🙂🙃🙄';
      charset += '🙅🙆🙇🙈🙉🙊🙋🙌🙍🙎🙏';
      charset += '🚀🚁🚂🚃🚄🚅🚆🚇🚈🚉🚊🚋🚌🚍🚎🚏🚐🚑🚒🚓🚔🚕🚖🚗🚘🚙🚚🚛🚜🚝🚞🚟🚠🚡🚢🚣🚤🚥🚦🚧🚨🚩🚪🚫🚬🚭🚮🚯🚰🚱🚲🚳🚴🚵🚶🚷🚸🚹🚺🚻🚼🚽🚾🚿';
      charset += '🛀🛁🛂🛃🛄🛅';
      charset += '🤐🤑🤒🤓🤔🤕🤖🤗🤘🤙🤚🤛🤜🤝🤞🤟🤠🤡🤢🤣🤤🤥🤦🤧🤨🤩🤪🤫🤬🤭🤮🤯🤰🤱🤲🤳🤴🤵🤶🤷🤸🤹🤺🤼🤽🤾';
      charset += '🥀🥁🥂🥃🥄🥅🥇🥈🥉🥊🥋🥌🥍🥎🥏🥐🥑🥒🥓🥔🥕🥖🥗🥘🥙🥚🥛🥜🥝🥞🥟🥠🥡🥢🥣🥤🥥🥦🥧🥨🥩🥪🥫🥬🥭🥮🥯🥰🥱🥳🥴🥵🥶🥺🥻🥼🥽🥾🥿';
      charset += '🦀🦁🦂🦃🦄🦅🦆🦇🦈🦉🦊🦋🦌🦍🦎🦏🦐🦑🦒🦓🦔🦕🦖🦗🦘🦙🦚🦛🦜🦝🦞🦟🦠🦡🦢🦸🦹🦺🦻🦼🦽🦾🦿';
      charset += '🧀🧁🧂🧐🧑🧒🧓🧔🧕🧖🧗🧘🧙🧚🧛🧜🧝🧞🧟🧠🧡🧢🧣🧤🧥🧦🧧🧨🧩🧪🧫🧬🧭🧮🧯🧰🧱🧲🧳🧴🧵🧶🧷🧸🧹🧺🧻🧼🧽🧾🧿';
      charset += '🌀🌁🌂🌃🌄🌅🌆🌇🌈🌉🌊🌋🌌🌍🌎🌏🌐🌑🌒🌓🌔🌕🌖🌗🌘🌙🌚🌛🌜🌝🌞🌟🌠🌭🌮🌯🌰🌱🌲🌳🌴🌵🌶🌷🌸🌹🌺🌻🌼🌽🌾🌿🍀🍁🍂🍃';
      charset += '🍄🍅🍆🍇🍈🍉🍊🍋🍌🍍🍎🍏🍐🍑🍒🍓🍔🍕🍖🍗🍘🍙🍚🍛🍜🍝🍞🍟🍠🍡🍢🍣🍤🍥🍦🍧🍨🍩🍪🍫🍬🍭🍮🍯🍰🍱🍲🍳🍴🍵🍶🍷🍸🍹🍺🍻🍼🎁🎂🎃🎄🎅🎆🎇🎈🎉🎊🎋🎌🎍🎎🎏🎐🎑🎒🎓';
      charset += '🎠🎡🎢🎣🎤🎥🎦🎧🎨🎩🎪🎫🎬🎭🎮🎯🎰🎱🎲🎳🎴🎵🎶🎷🎸🎹🎺🎻🎼🎽🎾🎿🏀🏁🏂🏃🏄🏅🏆🏇🏈🏉🏊🏋🏌🏏🏐🏑🏒🏓🏡🏢🏣🏤🏥🏦🏧🏨🏩🏪🏫🏬🏭🏮🏯🏰';
      charset += '🐀🐁🐂🐃🐄🐅🐆🐇🐈🐉🐊🐋🐌🐍🐎🐏🐐🐑🐒🐓🐔🐕🐖🐗🐘🐙🐚🐛🐜🐝🐞🐟🐠🐡🐢🐣🐤🐥🐦🐧🐨🐩🐪🐫🐬🐭🐮🐯🐰🐱🐲🐳🐴🐵🐶🐷🐸🐹🐺🐻🐼🐽🐾🐿';
      charset += '👀👁👂👃👄👅👆👇👈👉👊👋👌👍👎👏👐👑👒👓👔👕👖👗👘👙👚👛👜👝👞👟👠👡👢👣👤👥👦👧👨👩👪👫👬👭👮👯👰👱👲👳👴👵👶👷👸👹👺👻👼👽👾👿💀';
      charset += '💁💂💃💄💅💆💇💈💉💊💋💌💍💎💏💐💑💒💓💔💕💖💗💘💙💚💛💜💝💞💟💠💡💢💣💤💥💦💧💨💩💪💫💬💭💮💯💰💱💲💳💴💵💶💷💸💹💺💻💼💽💾💿📀📁📂📃📄📅📆📇📈📉📊📋📌📍📎📏';
      charset += '📐📑📒📓📔📕📖📗📘📙📚📛📜📝📞📟📠📡📢📣📤📥📦📧📨📩📪📫📬📭📮📯📰📱📲📳📴📵📶📷📸📹📺📻📼📽📿🔀🔁🔂🔃🔄🔅🔆🔇🔈🔉🔊🔋🔌🔍🔎🔏🔐🔑🔒🔓🔔🔕🔖🔗🔘🔙🔚🔛🔜🔝🔞🔟🔠🔡🔢🔣🔤';
      charset += '🔥🔦🔧🔨🔩🔪🔫🔬🔭🔮🔯🔰🔱🔲🔳🔴🔵🔶🔷🔸🔹🔺🔻🔼🔽🕌🕍🕎🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚🕛🕜🕝🕞🕟🕠🕡🕢🕣🕤🕥🕦🕧';
    }

    if (!constraints.similar) {
        charset = charset.replace(/[O0Il1|]/g, '');
    }

    if (constraints.excluded) {
        const excluded = constraints.excluded.split('');
        return Array.from(charset).filter(c => !excluded.includes(c));
    } else {
        return Array.from(charset);
    }
}

// ========================================
// Constraint Processing
// ========================================
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
// Shared Secret Derivation
// ========================================
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

// ========================================
// Password Generation
// ========================================
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
// Verification Token
// ========================================
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

// ========================================
// Bit-Equivalent Security Calculation
// ========================================
function calculateBitSecurity(charset, length) {
    if (!charset || charset.length === 0 || !length || length <= 0) {
        return 0;
    }
    // Entropy = length × log₂(charset size)
    return Math.floor(length * Math.log2(charset.length));
}

// ========================================
// High-Level Password Derivation with Metadata
// ========================================
async function derivePasswordWithMetadata(privateKey, publicKey, curveName, myKeypairId, partnerKeypairId, constraints) {
    // Build character set and calculate bytes needed
    const charset = buildCharacterSet(constraints);
    const targetLength = Math.min(constraints.maxLength, Math.floor((constraints.minLength + constraints.maxLength) / 2));
    const bytesPerChar = charset.length <= 256 ? 1 : 2;
    const bitsNeeded = targetLength * bytesPerChar * 8;

    // Derive shared secret with exactly the number of bits we need
    const curveBits = curveName === 'P-384' ? 384 : (curveName === 'P-521' ? 521 : 256);
    const infoBytes = buildConstraintsInfoBytes(constraints);
    const saltBytes = await deriveHkdfSaltFromKeyIds(myKeypairId, partnerKeypairId, curveBits);
    const sharedSecret = await deriveSharedSecret(
        privateKey,
        publicKey,
        curveName,
        infoBytes,
        saltBytes,
        curveBits,
        bitsNeeded
    );

    // Generate password
    const password = derivePassword(sharedSecret, charset, targetLength);

    // Calculate bit security
    const bitSecurity = calculateBitSecurity(charset, targetLength);

    return {
        password,
        charset,
        targetLength,
        bitSecurity
    };
}
