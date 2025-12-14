/**
 * DataDome Decryption Implementation
 * 
 * This file contains a decryption implementation for DataDome's custom encryption format.
 * It reverses the steps performed in encryption_rewrite.js:
 * 1. Decodes the custom base64-like string
 * 2. Reverses the cidPrng XOR step
 * 3. Parses the buffer entries (key-value pairs)
 * 4. Returns the parsed data
 */

// Create a helper class that exactly replicates the DataDomeEncryptor's PRNG functionality
class PRNGHelper {
    /**
     * Bitwise mixing function for PRNG state.
     * @param {number} value
     * @returns {number}
     */
    _mixInt(value) {
        // IMPORTANT: This needs to match exactly the implementation in DataDomeEncryptor
        // The exact order of operations matters for the sequence to match
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        return value;
    }

    /**
     * Creates a PRNG function with internal state, used for obfuscation.
     * @param {number} seed
     * @param {number} salt
     * @param {boolean} useAlt
     * @returns {Array<Function>}
     */
    _createPrng(seed, salt, useAlt = true) {
        let state = seed, round = -1, saltState = salt;
        // Important: In the original implementation, this._useAlt is captured as a local variable
        // and then reset to false immediately (see encryption_rewrite.js line 136)
        let useAltCopy = useAlt;
        let cache = null;

        return [function (flag) {
            let result;
            if (cache !== null) {
                result = cache;
                cache = null;
            } else {
                if (++round > 2) {
                    state = PRNGHelper.prototype._mixInt(state);
                    round = 0;
                }
                result = state >> (16 - 8 * round);
                if (useAltCopy) {
                    result ^= --saltState;
                }
                result &= 255;
                if (flag) {
                    cache = result;
                }
            }
            return result;
        }];
    }
}

// Helper function to create a PRNG
function createPrng(seed, salt, useAlt = true) {
    return new PRNGHelper()._createPrng(seed, salt, useAlt);
}

/**
 * Decode UTF-8 bytes to a string
 * @param {Array<number>} bytes - UTF-8 encoded bytes
 * @returns {string} - Decoded string
 */
function utf8Decode(bytes) {
    let str = '';
    for (let i = 0; i < bytes.length;) {
        let b = bytes[i++];
        if (b < 128) {
            str += String.fromCharCode(b);
        } else if (b >= 192 && b < 224) {
            let b2 = bytes[i++];
            str += String.fromCharCode(((b & 31) << 6) | (b2 & 63));
        } else if (b >= 224 && b < 240) {
            let b2 = bytes[i++], b3 = bytes[i++];
            str += String.fromCharCode(((b & 15) << 12) | ((b2 & 63) << 6) | (b3 & 63));
        } else if (b >= 240) {
            let b2 = bytes[i++], b3 = bytes[i++], b4 = bytes[i++];
            let codepoint = ((b & 7) << 18) | ((b2 & 63) << 12) | ((b3 & 63) << 6) | (b4 & 63);
            codepoint -= 0x10000;
            str += String.fromCharCode(0xD800 + (codepoint >> 10));
            str += String.fromCharCode(0xDC00 + (codepoint & 0x3FF));
        }
    }
    return str;
}

/**
 * Custom hash function used by DataDome
 * @param {string} str - Input string to hash
 * @returns {number} - Hash value
 */
function customHash(str) {
    if (!str) return 1789537805;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = (hash << 5) - hash + str.charCodeAt(i) | 0;
    }
    return hash !== 0 ? hash : 1789537805;
}

/**
 * DataDome Decryptor class
 */
class DataDomeDecryptor {
    /**
     * Create a new DataDomeDecryptor instance
     * @param {string} hash - Hash value used for encryption
     * @param {string} cid - Client ID used for encryption
     * @param {number} salt - Salt value used for encryption
     * @param {string} challengeType - Type of challenge: 'captcha' or 'interstitial' (default: 'captcha')
     */
    constructor(hash, cid, salt, challengeType = 'captcha') {
        this.hash = hash;
        this.cid = cid;
        this.salt = salt || 0;
        this.challengeType = challengeType.toLowerCase();

        // Set constants based on challenge type
        this._mainPrngConstant = 9959949970;
        this._hashXorConstant = -1748112727;
        this._cidPrngConstant = 1809053797;
        if (this.challengeType === 'interstitial') {
            this._hashXorConstant = -883841716;
        }

        // Calculate seeds for PRNGs
        this.prngSeed = this._mainPrngConstant ^ customHash(hash) ^ this._hashXorConstant;
        this.cidPrngSeed = this._cidPrngConstant ^ customHash(cid);

        // Create PRNGHelper for PRNG creation
        this.prngHelper = new PRNGHelper();
    }

    /**
     * Decode a 6-bit encoded character according to DataDome's custom encoding
     * @param {number} charCode - Character code to decode
     * @returns {number} - Decoded 6-bit value
     * @private
     */
    _decode6Bits(charCode) {
        if (charCode >= 97 && charCode <= 122) return charCode - 59;      // 'a'..'z' → 38..63
        if (charCode >= 65 && charCode <= 90) return charCode - 53;      // 'A'..'Z' → 12..37
        if (charCode >= 48 && charCode <= 57) return charCode - 46;      // '0'..'9' → 2..11
        if (charCode === 45) return 0;                                    // '-' → 0
        if (charCode === 95) return 1;                                    // '_' → 1
        return 0; // fallback
    }

    /**
     * Decode the custom base64-like string
     * @param {string} encoded - Encoded string
     * @returns {Array<number>} - Array of decoded bytes
     * @private
     */
    _decodeCustomBase64(encoded) {
        let bytes = [];
        let n = this.salt;
        let i = 0;

        // Process full groups of 4 characters (3 bytes each)
        while (i + 4 <= encoded.length) {
            let c1 = this._decode6Bits(encoded.charCodeAt(i));
            let c2 = this._decode6Bits(encoded.charCodeAt(i + 1));
            let c3 = this._decode6Bits(encoded.charCodeAt(i + 2));
            let c4 = this._decode6Bits(encoded.charCodeAt(i + 3));

            let chunk = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;

            bytes.push(((chunk >> 16) & 255) ^ (--n & 255));
            bytes.push(((chunk >> 8) & 255) ^ (--n & 255));
            bytes.push((chunk & 255) ^ (--n & 255));
            i += 4;
        }

        // Handle remaining characters (padding case)
        let remaining = encoded.length - i;
        if (remaining === 2) {
            // 2 chars encode 1 byte
            let c1 = this._decode6Bits(encoded.charCodeAt(i));
            let c2 = this._decode6Bits(encoded.charCodeAt(i + 1));
            let chunk = (c1 << 18) | (c2 << 12);
            bytes.push(((chunk >> 16) & 255) ^ (--n & 255));
        } else if (remaining === 3) {
            // 3 chars encode 2 bytes
            let c1 = this._decode6Bits(encoded.charCodeAt(i));
            let c2 = this._decode6Bits(encoded.charCodeAt(i + 1));
            let c3 = this._decode6Bits(encoded.charCodeAt(i + 2));
            let chunk = (c1 << 18) | (c2 << 12) | (c3 << 6);
            bytes.push(((chunk >> 16) & 255) ^ (--n & 255));
            bytes.push(((chunk >> 8) & 255) ^ (--n & 255));
        }

        return bytes;
    }

    /**
     * Decrypt the encoded data
     * @param {string} encoded - Base64-like encoded data
     * @returns {Array<Array>} - Array of key-value pairs
     */
    decrypt(encoded) {
        // Step 1: Decode the custom base64-like string to get the XORed buffer
        const bufferCidPrng = this._decodeCustomBase64(encoded);

        // Step 2: Reverse the cidPrng XOR to get the original buffer
        const cidPrng = this.prngHelper._createPrng(this.cidPrngSeed, this.salt, false)[0];
        const bufferWithMarker = bufferCidPrng.map(b => b ^ cidPrng());

        // Step 3: Parse the buffer to extract key-value pairs
        return this._parseBuffer(bufferWithMarker);
    }

    /**
     * Parse the buffer to extract key-value pairs
     * @param {Array<number>} bufferWithMarker - Buffer to parse (with marker byte)
     * @returns {Array<Array>} - Array of key-value pairs
     * @private
     */
    _parseBuffer(bufferWithMarker) {
        // The last byte is a marker, remove it
        const buffer = bufferWithMarker.slice(0, -1);

        // Create PRNG for buffer parsing
        // This must match exactly how the encryption process creates its PRNG
        const prng = this.prngHelper._createPrng(this.prngSeed, this.salt, true)[0];

        // Decrypt the entire buffer to get the raw JSON structure
        const decodedBytes = [];
        for (let i = 0; i < buffer.length; i++) {
            const b = buffer[i] ^ prng();
            decodedBytes.push(b);
        }

        // Decode UTF-8 bytes properly (encryption encodes strings as UTF-8)
        const jsonStr = utf8Decode(decodedBytes);

        // Now parse this string to extract entries
        return this._parseJsonString(jsonStr);
    }

    /**
     * Parse the decrypted JSON string into key-value pairs
     * @param {string} jsonStr - Decrypted JSON string
     * @returns {Array<Array>} - Array of key-value pairs
     * @private
     */
    _parseJsonString(jsonStr) {
        const result = [];
        let i = 0;

        // Process each character
        while (i < jsonStr.length) {
            try {
                // Find the start of an entry ('{' or ',')
                if (jsonStr[i] === '{' || jsonStr[i] === ',') {
                    i++; // Skip the start marker

                    // Skip whitespace
                    while (i < jsonStr.length && /\s/.test(jsonStr[i])) i++;

                    // Look for key (which should be a JSON string)
                    if (jsonStr[i] !== '"') {
                        i++; // Skip non-quote character
                        continue;
                    }

                    i++; // Skip the opening quote
                    const keyStart = i;

                    // Read the key content
                    while (i < jsonStr.length && jsonStr[i] !== '"') {
                        // Handle escaped characters
                        if (jsonStr[i] === '\\') {
                            i += 2; // Skip escape sequence
                        } else {
                            i++;
                        }
                    }

                    if (i >= jsonStr.length) break;

                    const key = jsonStr.substring(keyStart, i);
                    i++; // Skip the closing quote

                    // Look for the separator (':')
                    while (i < jsonStr.length && jsonStr[i] !== ':') i++;
                    if (i >= jsonStr.length) break;
                    i++; // Skip the separator

                    // Skip whitespace
                    while (i < jsonStr.length && /\s/.test(jsonStr[i])) i++;
                    if (i >= jsonStr.length) break;

                    // Process the value based on its type
                    let value;
                    const valueStart = i;

                    if (jsonStr[i] === '"') {
                        // String value
                        i++; // Skip opening quote
                        let valueContent = '';
                        let escaped = false;

                        while (i < jsonStr.length) {
                            if (escaped) {
                                valueContent += jsonStr[i];
                                escaped = false;
                            } else if (jsonStr[i] === '\\') {
                                valueContent += jsonStr[i];
                                escaped = true;
                            } else if (jsonStr[i] === '"') {
                                break;
                            } else {
                                valueContent += jsonStr[i];
                            }
                            i++;
                        }

                        if (i < jsonStr.length) i++; // Skip closing quote
                        
                        // Try to properly parse the string with JSON.parse to handle escapes
                        try {
                            value = JSON.parse(`"${valueContent.replace(/"/g, '\\"')}"`);
                        } catch (e) {
                            // If parsing fails, use the raw string
                            value = this._unescapeString(valueContent);
                        }
                    } else if (jsonStr[i] === '{') {
                        // Object value - more complex handling needed, but for now just extract as string
                        let nestLevel = 1;
                        i++; // Skip opening brace
                        let objectStr = '{';

                        while (i < jsonStr.length && nestLevel > 0) {
                            if (jsonStr[i] === '{') {
                                nestLevel++;
                            } else if (jsonStr[i] === '}') {
                                nestLevel--;
                            } else if (jsonStr[i] === '"') {
                                // Skip the entire string including any braces inside it
                                objectStr += jsonStr[i++];
                                while (i < jsonStr.length && jsonStr[i] !== '"') {
                                    if (jsonStr[i] === '\\') {
                                        objectStr += jsonStr[i++];
                                        if (i < jsonStr.length) objectStr += jsonStr[i++];
                                    } else {
                                        objectStr += jsonStr[i++];
                                    }
                                }
                                if (i < jsonStr.length) objectStr += jsonStr[i]; // Add closing quote
                            }

                            if (i < jsonStr.length) {
                                objectStr += jsonStr[i];
                                i++;
                            }
                        }

                        try {
                            value = JSON.parse(objectStr);
                        } catch (e) {
                            value = objectStr;
                        }
                    } else if (jsonStr[i] === '[') {
                        // Array value - similar to object handling
                        let nestLevel = 1;
                        i++; // Skip opening bracket
                        let arrayStr = '[';

                        while (i < jsonStr.length && nestLevel > 0) {
                            if (jsonStr[i] === '[') {
                                nestLevel++;
                            } else if (jsonStr[i] === ']') {
                                nestLevel--;
                            } else if (jsonStr[i] === '"') {
                                // Skip the entire string including any brackets inside it
                                arrayStr += jsonStr[i++];
                                while (i < jsonStr.length && jsonStr[i] !== '"') {
                                    if (jsonStr[i] === '\\') {
                                        arrayStr += jsonStr[i++];
                                        if (i < jsonStr.length) arrayStr += jsonStr[i++];
                                    } else {
                                        arrayStr += jsonStr[i++];
                                    }
                                }
                                if (i < jsonStr.length) arrayStr += jsonStr[i]; // Add closing quote
                            }

                            if (i < jsonStr.length) {
                                arrayStr += jsonStr[i];
                                i++;
                            }
                        }

                        try {
                            value = JSON.parse(arrayStr);
                        } catch (e) {
                            value = arrayStr;
                        }
                    } else if (/[0-9-]/.test(jsonStr[i])) {
                        // Number value
                        let numStr = '';
                        while (i < jsonStr.length && /[0-9.eE+-]/.test(jsonStr[i])) {
                            numStr += jsonStr[i++];
                        }
                        value = parseFloat(numStr);
                    } else if (jsonStr.substring(i, i + 4) === 'true') {
                        value = true;
                        i += 4;
                    } else if (jsonStr.substring(i, i + 5) === 'false') {
                        value = false;
                        i += 5;
                    } else if (jsonStr.substring(i, i + 4) === 'null') {
                        value = null;
                        i += 4;
                    } else {
                        // Unknown value type - just skip this character
                        i++;
                        continue;
                    }
                    // Add entry to result
                    result.push([this._unescapeString(key), value]);
                } else {
                    // Skip any other characters
                    i++;
                }
            } catch (error) {
                // If any parsing error occurs, skip to the next character
                console.log("Error parsing JSON", error);
                i++;
            }
        }

        return result;
    }

    /**
     * Unescape a string similarly to how JavaScript would with JSON.parse
     * but without throwing errors on invalid escape sequences
     * @param {string} str - String to unescape
     * @returns {string} - Unescaped string
     * @private
     */
    _unescapeString(str) {
        if (typeof str !== 'string') return str;
        
        return str.replace(/\\(.)/g, function(match, char) {
            switch (char) {
                case 'n': return '\n';
                case 'r': return '\r';
                case 't': return '\t';
                case 'b': return '\b';
                case 'f': return '\f';
                case '\\': return '\\';
                case '"': return '"';
                default: return char; // For \u sequences, just keep as is
            }
        });
    }

    /**
     * Gets the challenge type currently being used
     * @returns {string}
     */
    getChallengeType() {
        return this.challengeType;
    }

    /**
     * Updates the challenge type and recalculates PRNG seeds
     * @param {string} challengeType - 'captcha' or 'interstitial'
     */
    setChallengeType(challengeType) {
        this.challengeType = challengeType.toLowerCase();

        // Update constants based on challenge type
        if (this.challengeType === 'interstitial') {
            this._mainPrngConstant = 9959949970;
            this._hashXorConstant = -883841716;
            this._cidPrngConstant = 1809053797;
        } else {
            this._mainPrngConstant = 9959949970;
            this._hashXorConstant = -1748112727;
            this._cidPrngConstant = 1809053797;
        }

        // Recalculate seeds
        this.prngSeed = this._mainPrngConstant ^ customHash(this.hash) ^ this._hashXorConstant;
        this.cidPrngSeed = this._cidPrngConstant ^ customHash(this.cid);
    }
}