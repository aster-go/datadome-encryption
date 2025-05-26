const fs = require('fs');

/**
 * DataDomeEncryptor
 * Implements a custom encryption/obfuscation routine for key-value data pairs.
 * The encryption logic is intentionally complex and mimics a real-world obfuscated payload builder.
 */
class DataDomeEncryptor {
    /**
     * @param {string} hash - The hash string used as part of the encryption seed.
     * @param {string} cid - The client/session identifier used in the payload.
     * @param {number|null} salt - Optional external salt for the encryption process.
     * @param {string} challengeType - Type of challenge: 'captcha' or 'interstitial' (default: 'captcha')
     */
    constructor(hash, cid, salt = null, challengeType = 'captcha') {
        this.hash = hash;
        this.cid = cid;
        this.challengeType = challengeType.toLowerCase();
        
        // Set correct constants based on challenge type
        if (this.challengeType === 'interstitial') {
            // Interstitial challenge constants
            this._mainPrngConstant = 9959949970;
            this._hashXorConstant = -883841716; // Interstitial uses a different hash XOR constant
            this._cidPrngConstant = 1809053797;
            this._hsv = this._generateHsv();
        } else {
            // Default captcha challenge constants
            this._mainPrngConstant = 9959949970;
            this._hashXorConstant = -1748112727;
            this._cidPrngConstant = 1809053797;
            this._hsv = this._generateHsv();
        }
        
        this._externalSalt = salt; // Store the externally provided salt
        this._initEncryptor();
    }

    /**
     * Generates a pseudo-random HSV string based on the hash and random values.
     * Used as a hidden value in the encryption process.
     * @returns {string}
     */
    _generateHsv() {
        const last4 = this.hash.slice(-4);
        const randIndex = Math.floor(Math.random() * 9);
        const randHex = Math.random().toString(16).slice(2, 10).toUpperCase();
        return randHex.slice(0, randIndex) + last4 + randHex.slice(randIndex);
    }

    /**
     * Hashes a string using a custom algorithm, returns a 32-bit integer or a fallback constant.
     * @param {string} str
     * @returns {number}
     */
    _customHash(str) {
        if (!str) return 1789537805;
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = (hash << 5) - hash + str.charCodeAt(i) | 0;
        }
        return hash !== 0 ? hash : 1789537805;
    }

    /**
     * Encodes a 6-bit value into a custom character code for the payload.
     * @param {number} value
     * @returns {number}
     */
    _encode6Bits(value) {
        if (value > 37) {
            return 59 + value;
        } else if (value > 11) {
            return 53 + value;
        } else if (value > 1) {
            return 46 + value;
        } else {
            return 50 * value + 45;
        }
    }

    /**
     * Bitwise mixing function for PRNG state.
     * @param {number} value
     * @returns {number}
     */
    _mixInt(value) {
        value ^= value << 13;
        value ^= value >> 17;
        return value ^ value << 5;
    }

    /**
     * Creates a PRNG function with internal state, used for obfuscation.
     * @param {number} seed
     * @param {number} salt
     * @returns {function(boolean): number}
     */
    _createPrng(seed, salt) {
        let state = seed, round = -1, saltState = salt, useAlt = this._useAlt;
        this._useAlt = false;
        let cache = null;
        return [function (flag) {
            let result;
            if (cache !== null) {
                result = cache;
                cache = null;
            } else {
                if (++round > 2) {
                    state = DataDomeEncryptor.prototype._mixInt(state);
                    round = 0;
                }
                result = state >> (16 - 8 * round);
                if (useAlt) {
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

    /**
     * Converts a string to a UTF-8 byte array and XORs each byte with the PRNG.
     * @param {string} str
     * @param {function(): number} prng
     * @returns {number[]}
     */
    _utf8Xor(str, prng) {
        let utf8Bytes = [];
        let idx = 0;
        for (let i = 0; i < str.length; i++) {
            let code = str.charCodeAt(i);
            if (code < 128) {
                utf8Bytes[idx++] = code;
            } else if (code < 2048) {
                utf8Bytes[idx++] = code >> 6 | 192;
                utf8Bytes[idx++] = 63 & code | 128;
            } else if (55296 == (64512 & code) && i + 1 < str.length && 56320 == (64512 & str.charCodeAt(i + 1))) {
                // Surrogate pair
                code = 65536 + ((1023 & code) << 10) + (1023 & str.charCodeAt(++i));
                utf8Bytes[idx++] = code >> 18 | 240;
                utf8Bytes[idx++] = code >> 12 & 63 | 128;
                utf8Bytes[idx++] = code >> 6 & 63 | 128;
                utf8Bytes[idx++] = 63 & code | 128;
            } else {
                utf8Bytes[idx++] = code >> 12 | 224;
                utf8Bytes[idx++] = code >> 6 & 63 | 128;
                utf8Bytes[idx++] = 63 & code | 128;
            }
        }
        // XOR each byte with prng()
        for (let j = 0; j < utf8Bytes.length; j++) {
            utf8Bytes[j] ^= prng();
        }
        return utf8Bytes;
    }

    /**
     * Safely JSON-stringifies a value, returns undefined on error.
     * @param {any} value
     * @returns {string|undefined}
     */
    _safeJson(value) {
        try {
            if (typeof value === 'string') {
                // Ensure string escaping is consistent
                return JSON.stringify(value);
            }
            return JSON.stringify(value);
        } catch (e) {
            return;
        }
    }

    /**
     * Encodes an array of bytes into a custom base64-like string.
     * @param {number[]} byteArr
     * @param {number} salt
     * @param {function(number): number} encode6Bits
     * @returns {string}
     */
    _encodePayload(byteArr, salt, encode6Bits) {
        let i = 0;
        let output = [];
        let n = salt;
        // Process each group of 3 bytes
        while (i < byteArr.length) {
            // Combine 3 bytes into a 24-bit number, with obfuscation
            let chunk = (255 & --n ^ byteArr[i++]) << 16 |
                        (255 & --n ^ byteArr[i++]) << 8  |
                        (255 & --n ^ byteArr[i++]);
            // Split into 4 groups of 6 bits and encode
            output.push(
                String.fromCharCode(encode6Bits((chunk >> 18) & 63)),
                String.fromCharCode(encode6Bits((chunk >> 12) & 63)),
                String.fromCharCode(encode6Bits((chunk >> 6) & 63)),
                String.fromCharCode(encode6Bits(chunk & 63))
            );
        }
        // Handle padding if input length is not a multiple of 3
        let mod = byteArr.length % 3;
        if (mod) output.length -= 3 - mod;
        return output.join('');
    }

    /**
     * Initializes or resets the encryption state (PRNG, buffer, etc.).
     */
    _resetEncryptionState() {
        this._useAlt = true;
        this._prngSeed = this._mainPrngConstant ^ this._customHash(this.hash) ^ this._hashXorConstant;
        if (this._externalSalt !== null && this._externalSalt !== undefined) {
            this._salt = this._externalSalt;
        } else {
            this._salt = this._mixInt(this._mixInt((Date.now() >> 3) ^ 11027890091) * this._mainPrngConstant);
        }
        this.salt = this._salt; // Expose the salt used
        this._prng = this._createPrng(this._prngSeed, this._salt)[0];
        this._buffer = [];
        this._isFirst = true;
        this._seenKeys = new Set();
        
        // Expose seed values for testing/debugging (without changing encryption logic)
        this.prngSeed = this._prngSeed;
        this.cidPrngSeed = this._cidPrngConstant ^ this._customHash(this.cid);
    }

    /**
     * Initializes the encryption engine and sets up the addSignal and buildPayload methods.
     */
    _initEncryptor() {
        this._resetEncryptionState();
        this.addSignal = this._addSignal.bind(this);
        this.buildPayload = this._buildPayload.bind(this);
    }

    /**
     * Adds a key-value pair to the buffer, obfuscated and encoded.
     * @param {string} key
     * @param {string|number|boolean} value
     */
    _addSignal(key, value) {
        const allowedTypes = ['number', 'string', 'boolean'];
        if (typeof key === 'string' && key.length !== 0 && (!value || allowedTypes.includes(typeof value))) {
            let hsvTemp;
            const keyStr = this._safeJson(key);
            const valueStr = this._safeJson(value);
            if (key && valueStr !== undefined && key !== 'xt1') {
                const startByte = this._prng() ^ (this._buffer.length ? 44 : 123);
                this._buffer.push(startByte);
                const keyBytes = this._utf8Xor(keyStr, this._prng);
                Array.prototype.push.apply(this._buffer, keyBytes);
                const sepByte = 58 ^ this._prng();
                this._buffer.push(sepByte);
                const valueBytes = this._utf8Xor(valueStr, this._prng);
                Array.prototype.push.apply(this._buffer, valueBytes);
                if (this._isFirst) {
                    this._isFirst = false;
                    if ((typeof this._hsv === 'string' && this._hsv.length > 0) ||
                        (typeof this._hsv === 'number' && !isNaN(this._hsv))) {
                        hsvTemp = this._hsv;
                    }
                }
            }
        }
    }

    /**
     * Builds the final encrypted payload string for a given cid.
     * @param {string} cid
     * @returns {string}
     */
    _buildPayload(cid) {
        const cidPrng = this._createPrng(this._cidPrngConstant ^ this._customHash(cid), this._salt)[0];
        // Write buffer before cidPrng XOR
        // fs.writeFileSync('debug_encrypt_buffer.json', JSON.stringify(this._buffer));
        let output = [];
        for (let i = 0; i < this._buffer.length; i++) output.push(this._buffer[i] ^ cidPrng());
        output.push(125 ^ this._prng(true) ^ cidPrng());
        const encoded = this._encodePayload(output, this._salt, this._encode6Bits.bind(this));
        return encoded;
    }

    /**
     * Adds a key-value pair to the encryption buffer (public method).
     * @param {string} key
     * @param {string|number|boolean} value
     */
    add(key, value) {
        this.addSignal(key, value);
    }

    /**
     * Builds the encrypted payload for the current cid (public method).
     * @returns {string}
     */
    encrypt() {
        return this.buildPayload(this.cid);
    }

    /**
     * Checks if the encrypted result matches the expected output.
     * @param {string} encrypted
     * @param {string} exceptedPath
     * @returns {boolean}
     */
    static checkResult(encrypted, exceptedPath) {
        const excepted = fs.readFileSync(exceptedPath, 'utf-8');
        const isCorrect = encrypted === excepted;
        return isCorrect;
    }

    /**
     * Gets the challenge type currently being used
     * @returns {string}
     */
    getChallengeType() {
        return this.challengeType;
    }

    /**
     * Updates the challenge type
     * @param {string} challengeType - 'captcha' or 'interstitial'
     */
    setChallengeType(challengeType) {
        this.challengeType = challengeType.toLowerCase();
        
        // Set the correct constants based on challenge type
        this._mainPrngConstant = 9959949970;
        this._cidPrngConstant = 1809053797;
        
        if (this.challengeType === 'interstitial') {
            this._hashXorConstant = -883841716;
        } else {
            this._hashXorConstant = -1748112727;
            this._hsv = this._generateHsv();
        }
        
        this._initEncryptor();
    }
}

// Export the DataDomeEncryptor class
module.exports = { DataDomeEncryptor };

