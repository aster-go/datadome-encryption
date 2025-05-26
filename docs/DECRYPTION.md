# DECRYPTION.md
This document provides a detailed theoretical plan for decrypting the payload produced by `encryption_rewrite.js`. It is based on the deep analysis in `ENCRYPTION.md` and describes how to reverse each step of the encryption pipeline to recover the original key-value data pairs.


<div align="center">
  <img src="https://img.shields.io/badge/Status-Complete-brightgreen" alt="Status: Complete">
  <img src="https://img.shields.io/badge/Type-Research-blue" alt="Type: Research">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License: MIT">
  <a href="https://www.npmjs.com/package/datadome-encryption"><img src="https://img.shields.io/npm/v/datadome-encryption.svg?style=flat-square&color=cb3837&logo=npm" alt="npm version"></a>
  <a href="https://github.com/GlizzyKingDreko/datadome-encryption"><img src="https://img.shields.io/github/stars/GlizzyKingDreko/datadome-encryption?style=flat-square&logo=github" alt="GitHub stars"></a>
  <a href="https://github.com/GlizzyKingDreko/datadome-encryption"><img src="https://img.shields.io/badge/GitHub-Repo-black?logo=github&style=flat-square" alt="GitHub repo"></a>
</div>

<br>

<div align="center">
<a href="https://github.com/GlizzyKingDreko/datadome-encryption-python"><img src="https://img.shields.io/badge/Check%20the%20Python%20version-purple?logo=python&style=flat-square" alt="Check the Python version"></a>
  <a href="https://medium.com/@glizzykingdreko/breaking-down-datadome-captcha-waf-d7b68cef3e21"><img src="https://img.shields.io/badge/Read%20the%20full%20article%20on%20Medium-12100E?logo=medium&logoColor=white&style=flat-square" alt="Read the full article on Medium"></a>
  </div>
<br>


## Navigation

| Document | Description |
|----------|-------------|
| [README.md](../README.md) | Project overview and introduction |
| [ENCRYPTION.md](./ENCRYPTION.md) | Detailed analysis of the encryption algorithm |
| [DECRYPTION.md](./DECRYPTION.md) | Implementation of the decryption process |
| [technical_analysis.md](./technical_analysis.md) | Technical deep-dive into cryptographic properties |
| [LEARN.md](./LEARN.md) | Educational guide on reverse engineering techniques |

## Overview

## Table of Contents
- [DECRYPTION.md](#decryptionmd)
  - [Navigation](#navigation)
  - [Overview](#overview)
  - [Table of Contents](#table-of-contents)
  - [High-Level Decryption Pipeline](#high-level-decryption-pipeline)
  - [Step-by-Step Decryption Plan](#step-by-step-decryption-plan)
    - [1. **Custom Base64-like Decoding**](#1-custom-base64-like-decoding)
    - [2. **PRNG XOR Reversal**](#2-prng-xor-reversal)
    - [3. **Buffer Parsing**](#3-buffer-parsing)
  - [Key Functions for Decryption](#key-functions-for-decryption)
  - [Debug Files and Validation](#debug-files-and-validation)
  - [Pitfalls and Obfuscation Notes](#pitfalls-and-obfuscation-notes)
  - [Diagrams](#diagrams)
  - [Summary Table](#summary-table)
  - [Conclusion](#conclusion)
- [Practical Decryption Challenges and Solutions](#practical-decryption-challenges-and-solutions)
  - [Testing Infrastructure Development](#testing-infrastructure-development)
    - [1. Comparative Testing System](#1-comparative-testing-system)
    - [2. Byte-Level Debugging Tools](#2-byte-level-debugging-tools)
  - [Implementation Challenges and Solutions](#implementation-challenges-and-solutions)
    - [Challenge 1: PRNG Synchronization](#challenge-1-prng-synchronization)
    - [Challenge 2: JSON-like Structure Parsing](#challenge-2-json-like-structure-parsing)
    - [Challenge 3: Buffer Boundary Detection](#challenge-3-buffer-boundary-detection)
  - [Breakthrough Debugging Techniques](#breakthrough-debugging-techniques)
    - [1. Buffer Visualization](#1-buffer-visualization)
    - [2. PRNG State Tracing](#2-prng-state-tracing)
    - [3. Cross-Validation with Original Code](#3-cross-validation-with-original-code)
  - [Lessons Learned from Implementation](#lessons-learned-from-implementation)
- [DataDome Decryption: Implementation Process](#datadome-decryption-implementation-process)
  - [Challenge Overview](#challenge-overview)
  - [Analysis and Approach](#analysis-and-approach)
  - [Decryption Components Implementation](#decryption-components-implementation)
    - [1. PRNGHelper Class: Exact PRNG Replication](#1-prnghelper-class-exact-prng-replication)
    - [2. Custom Base64 Decoder](#2-custom-base64-decoder)
    - [3. CID-PRNG XOR Reversal](#3-cid-prng-xor-reversal)
    - [4. JSON-like Structure Parsing](#4-json-like-structure-parsing)
    - [5. JSON String Parsing](#5-json-string-parsing)
  - [Complete Decryption Flow](#complete-decryption-flow)
  - [Verification and Validation](#verification-and-validation)
  - [Implementation Challenges and Solutions](#implementation-challenges-and-solutions-1)
    - [Challenge 1: PRNG Synchronization](#challenge-1-prng-synchronization-1)
    - [Challenge 2: JSON-like Structure Parsing](#challenge-2-json-like-structure-parsing-1)
    - [Challenge 3: Character Encoding Issues](#challenge-3-character-encoding-issues)
  - [DataDomeDecryptor Class](#datadomedecryptor-class)
  - [Conclusion](#conclusion-1)
  - [Author](#author)

---

**Need DataDome Bypass Solutions?**

If you need a reliable DataDome bypass solution for your project, turn to the experts who truly understand the technology. My company, TakionAPI, offers professional anti-bot bypass APIs with proven effectiveness against DataDome and other bot-defense systems.

No more worrying about understanding, reversing, and solving the challenge yourself, or about keeping it up to date every day. One simple API call does it all.

We provide free trials, example implementations, and setup assistance to make the entire process easy and smooth.  
- 📄 [Check our straightforward documentation](https://docs.takionapi.tech)  
- 🚀 [Start your trial](https://dashboard.takionapi.tech)  
- 💬 [Contact us on Discord](https://takionapi.tech/discord) for custom development and support.

**Visit [TakionAPI.tech](https://takionapi.tech) for real, high-quality anti-bot bypass solutions — we know what we're doing.**

---

## High-Level Decryption Pipeline

1. **Input**: The encrypted payload string (custom base64-like encoded).
2. **Custom Base64-like Decoding**: Decode the string into a byte array, reversing the salt-based obfuscation.
3. **PRNG XOR Reversal**: XOR the decoded buffer with the same PRNG sequence (seeded by `cid` and `salt`) to recover the obfuscated buffer.
4. **Buffer Parsing**: Parse the buffer using the original PRNG logic to extract key-value pairs.
5. **Output**: The recovered key-value data pairs.

---

## Step-by-Step Decryption Plan

### 1. **Custom Base64-like Decoding**
- **Goal**: Reverse the custom base64-like encoding and salt-based obfuscation.
- **Process**:
  - For each group of 4 characters in the payload string:
    - Map each character back to a 6-bit value using the inverse of `_encode6Bits`.
    - Combine the 6-bit values into a 24-bit chunk.
    - XOR each byte with the salt (in reverse order) to recover the original bytes.
  - Remove any padding bytes if present.
- **Output**: The PRNG-XORed buffer (ciphertext + marker byte).

### 2. **PRNG XOR Reversal**
- **Goal**: Reverse the PRNG XOR applied during encryption.
- **Process**:
  - Initialize the PRNG with the same seed and salt as in encryption (`cid` and `salt`).
  - For each byte in the decoded buffer (excluding the marker byte):
    - XOR the byte with the PRNG output to recover the obfuscated buffer.
  - Advance the PRNG once more to simulate the marker byte.
- **Output**: The obfuscated buffer (as produced by `_addSignal` in encryption).

### 3. **Buffer Parsing**
- **Goal**: Parse the obfuscated buffer to extract the original key-value pairs.
- **Process**:
  - Initialize the PRNG with the same seed and salt as used in `_addSignal` during encryption (`hash` and `salt`).
  - Iterate through the buffer:
    - For each entry:
      - The first byte is the start byte, XORed with the PRNG output and a constant (44 or 123).
      - The key is a UTF-8 byte sequence, each byte XORed with the PRNG output, ending at the separator byte (58).
      - The value is a UTF-8 byte sequence, each byte XORed with the PRNG output, ending at the next start byte or end of buffer.
    - Decode the key and value from UTF-8 and parse as JSON if possible.
- **Output**: Array of key-value pairs (original data).

---

## Key Functions for Decryption

- **decode6Bits(charCode)**: Inverse of `_encode6Bits`, maps character code to 6-bit value.
- **decodeCustomBase64(encoded, salt)**: Decodes the custom base64-like string, reversing salt obfuscation.
- **createPrng(seed, salt)**: Recreates the PRNG logic from encryption for both XOR reversal and buffer parsing.
- **utf8Decode(bytes)**: Decodes a UTF-8 byte array to a string.
- **Buffer parsing logic**: Mirrors the logic in `_addSignal` for extracting key-value pairs.
- **Challenge Type handling**: Sets appropriate constants based on whether it's a 'captcha' or 'interstitial' challenge.

---

## Debug Files and Validation

- Use `debug_encrypt_buffer.json`, `debug_encrypt_cidprng.json`, and `debug_encrypt_final.txt` from encryption for step-by-step validation.
- At each decryption stage, compare the intermediate buffer to the corresponding debug file to ensure correctness.
- Use small test cases and detailed logs to pinpoint any mismatches.

---

## Pitfalls and Obfuscation Notes

- The PRNG logic is non-standard and must be replicated exactly, including state mixing and salt handling.
- The custom base64-like encoding uses a non-standard mapping; ensure the inverse mapping is correct.
- Buffer alignment and marker byte handling are critical for correct parsing.
- Any deviation in PRNG seeding or advancement will result in incorrect decryption.

---

## Diagrams

```
[Encrypted String] --(Custom Base64 Decode)--> [Cipher Buffer + Marker] --(PRNG XOR Reversal)--> [Obfuscated Buffer] --(Buffer Parsing)--> [Original Data]
```

---

## Summary Table

| Step                    | Input                  | Output                | File for Validation           |
|-------------------------|------------------------|-----------------------|-------------------------------|
| Base64-like Decode      | Encrypted string       | Cipher buffer + mark  | debug_encrypt_cidprng.json    |
| PRNG XOR Reversal       | Cipher buffer + mark   | Obfuscated buffer     | debug_encrypt_buffer.json     |
| Buffer Parsing          | Obfuscated buffer      | Key-value pairs       | original_data.json            |

---

## Conclusion

Decryption is the exact reversal of the multi-stage, obfuscated encryption pipeline. By carefully mirroring each step and validating against debug files, the original data can be reliably recovered, provided all parameters and logic are correct. 

> 💡 **Need a Professional DataDome Bypass?**
> 
> Successfully implementing DataDome decryption requires deep technical expertise and continuous maintenance. If you need a robust and reliable DataDome bypass solution for your business, [TakionAPI.tech](https://takionapi.tech) offers ready-to-use APIs built by the same researcher who reverse engineered this encryption system.

# Practical Decryption Challenges and Solutions

While the theoretical understanding of the encryption algorithm was a significant first step, implementing a working decryption solution involved several complex practical challenges. This section details the specific difficulties encountered and how they were overcome.

## Testing Infrastructure Development

Before attempting to decode actual DataDome payloads, we needed a robust testing framework:

### 1. Comparative Testing System

We developed a test harness that could:
- Generate test data with various data types and edge cases
- Encrypt data using both the original and rewritten algorithms
- Attempt decryption and compare with the original data
- Highlight any discrepancies down to the byte level

```javascript
function runComparisonTest(testData) {
    // Encrypt with original algorithm
    const originalEncrypted = originalEncryptor.encrypt(testData);
    
    // Encrypt with rewritten algorithm
    const rewrittenEncrypted = rewrittenEncryptor.encrypt(testData);
    
    // Compare encrypted outputs
    console.log("Original encryption matches rewrite:", 
                originalEncrypted === rewrittenEncrypted);
    
    // Attempt decryption
    const decrypted = decryptor.decrypt(rewrittenEncrypted);
    
    // Compare with original data
    const matches = compareDataStructures(testData, decrypted);
    console.log("Decryption successful:", matches.success);
    if (!matches.success) {
        console.log("Differences:", matches.differences);
    }
}
```

### 2. Byte-Level Debugging Tools

For troubleshooting, we created specialized debugging tools:

```javascript
function debugPRNGSequence(seed, salt, count) {
    const prng = createPrng(seed, salt);
    console.log(`PRNG sequence for seed=${seed}, salt=${salt}:`);
    const sequence = [];
    for (let i = 0; i < count; i++) {
        sequence.push(prng());
    }
    console.log(sequence.map(b => b.toString(16).padStart(2, '0')).join(' '));
    return sequence;
}

function compareBuffers(buffer1, buffer2) {
    const maxLen = Math.max(buffer1.length, buffer2.length);
    let differences = 0;
    let firstDiffPos = -1;
    
    console.log("Buffer comparison:");
    console.log("Idx | Buffer1  | Buffer2  | Match");
    console.log("----|----------|----------|------");
    
    for (let i = 0; i < maxLen; i++) {
        const b1 = i < buffer1.length ? buffer1[i] : undefined;
        const b2 = i < buffer2.length ? buffer2[i] : undefined;
        const match = b1 === b2;
        
        if (!match && firstDiffPos === -1) {
            firstDiffPos = i;
            differences++;
        }
        
        // Print only the first 10 differences to avoid flooding the console
        if (!match && differences <= 10) {
            console.log(`${i.toString().padStart(4)} | ${b1?.toString(16).padStart(8) || 'undefined'} | ${b2?.toString(16).padStart(8) || 'undefined'} | ❌`);
        }
    }
    
    console.log(`Total differences: ${differences}/${maxLen} bytes`);
    console.log(`First difference at position: ${firstDiffPos}`);
    
    return { differences, firstDiffPos };
}
```

## Implementation Challenges and Solutions

### Challenge 1: PRNG Synchronization

The most critical issue was ensuring the PRNG produced identical sequences during encryption and decryption.

**Problem:**
Subtle differences in PRNG implementation or state tracking caused decryption to fail completely:

```javascript
// Initial implementation with subtle bug
function createPrng(seed, salt) {
    let state = seed;
    let round = 0;  // Should be -1!
    
    return function() {
        if (round >= 3) {   // Should be > 2!
            state = mixInt(state);
            round = 0;
        }
        // ...rest of PRNG logic
    };
}
```

**Solution:**
Created a validation system that could directly compare PRNG sequences:

```javascript
// PRNG validation test
function validatePRNG() {
    const seed = 0x12345678;
    const salt = 0xABCDEF;
    
    // Create PRNGs from both encryption and decryption implementations
    const encryptPRNG = encryptor._createPrng(seed, salt)[0];
    const decryptPRNG = decryptor.prngHelper._createPrng(seed, salt)[0];
    
    // Generate and compare 1000 values
    let mismatchCount = 0;
    let firstMismatchPos = -1;
    
    console.log("Validating PRNG implementation...");
    for (let i = 0; i < 1000; i++) {
        const encValue = encryptPRNG();
        const decValue = decryptPRNG();
        
        if (encValue !== decValue) {
            mismatchCount++;
            if (firstMismatchPos === -1) {
                firstMismatchPos = i;
                console.log(`First mismatch at position ${i}: ` +
                           `encrypt=${encValue}, decrypt=${decValue}`);
            }
        }
    }
    
    console.log(`PRNG validation complete: ${mismatchCount} mismatches`);
    return mismatchCount === 0;
}
```

This validation helped identify specific issues in the PRNG implementation:
- The round counter initialization at -1 vs 0
- The exact conditions for state mixing
- The application of salt XOR
- The order of operations

### Challenge 2: JSON-like Structure Parsing

The decrypted buffer contains a JSON-like structure, but with the complexity of being dynamically constructed.

**Problem:**
Initial attempts to use `JSON.parse()` failed because the structure wasn't standard JSON:

```javascript
// This approach fails
try {
    const jsonData = JSON.parse(jsonStr);
    return jsonData;
} catch (e) {
    console.error("Failed to parse JSON:", e);
    return null;
}
```

**Solution:**
Implemented a character-by-character parser that could handle the DataDome JSON format:

```javascript
/**
 * Parse the JSON string specifically for DataDome format
 * @param {string} jsonStr - The JSON-like string to parse
 * @returns {Array} - Array of key-value pairs
 */
_parseJsonString(jsonStr) {
    const result = [];
    
    // Simplified version of the complex parsing logic
    let i = 0;
    let parsingKey = false;
    let parsingValue = false;
    let currentKey = "";
    
    while (i < jsonStr.length) {
        // Handle the start of an object or entry
        if (jsonStr[i] === '{' || jsonStr[i] === ',') {
            parsingKey = true;
            i++;
            continue;
        }
        
        // Handle key parsing
        if (parsingKey && jsonStr[i] === '"') {
            // Extract the key between quotes
            const keyStart = i + 1;
            i++;
            while (i < jsonStr.length && jsonStr[i] !== '"') i++;
            currentKey = jsonStr.substring(keyStart, i);
            parsingKey = false;
            i++;
            continue;
        }
        
        // Handle the separator between key and value
        if (!parsingKey && !parsingValue && jsonStr[i] === ':') {
            parsingValue = true;
            i++;
            continue;
        }
        
        // Handle value parsing based on type
        if (parsingValue) {
            let value;
            
            // Handle different value types
            if (jsonStr[i] === '"') {
                // String value
                // ...string parsing logic
            } 
            else if (jsonStr[i] === 'n' && jsonStr.substr(i, 4) === 'null') {
                value = null;
                i += 4;
            }
            else if (jsonStr[i] === 't' && jsonStr.substr(i, 4) === 'true') {
                value = true;
                i += 4;
            }
            else if (jsonStr[i] === 'f' && jsonStr.substr(i, 5) === 'false') {
                value = false;
                i += 5;
            }
            else if (jsonStr[i] === '-' || (jsonStr[i] >= '0' && jsonStr[i] <= '9')) {
                // Number value
                // ...number parsing logic
            }
            
            // Add the entry and reset
            result.push([currentKey, value]);
            parsingValue = false;
            currentKey = "";
            continue;
        }
        
        // Move to next character if no special handling
        i++;
    }
    
    return result;
}
```

### Challenge 3: Buffer Boundary Detection

Identifying the correct boundaries between key-value pairs in the buffer was challenging due to the dynamic nature of the data.

**Problem:**
Without clear delimiters, parsing the buffer was error-prone:

```javascript
// Problematic approach
let currentPos = 0;
while (currentPos < buffer.length) {
    // How do we know where one entry ends and the next begins?
    // ...parsing logic
}
```

**Solution:**
Reversed the original buffer construction logic to accurately find boundaries:

```javascript
/**
 * Parse the buffer into key-value pairs
 * @param {Array<number>} buffer - The decrypted buffer
 * @returns {Array<Array>} - Array of key-value pairs
 */
_parseBuffer(buffer) {
    const result = [];
    let i = 0;
    
    // Initialize PRNG with the same seed used during encryption
    const prng = this.prngHelper._createPrng(this.prngSeed, this.salt, true)[0];
    
    while (i < buffer.length) {
        // The first byte is a start marker ('{' or ',')
        const startByte = buffer[i++] ^ prng();
        if (startByte !== 123 && startByte !== 44) {
            console.warn(`Unexpected start byte: ${startByte}`);
        }
        
        // Read and decode the key
        let keyBytes = [];
        let b;
        while (i < buffer.length) {
            b = buffer[i++] ^ prng();
            if (b === 58) break; // ':' separator
            keyBytes.push(b);
        }
        
        // Read and decode the value
        let valueBytes = [];
        while (i < buffer.length) {
            const peekByte = buffer[i] ^ prng(true); // Use flag to peek
            if (peekByte === 44 || peekByte === 125) break; // ',' or '}'
            b = buffer[i++] ^ prng();
            valueBytes.push(b);
        }
        
        // Convert bytes to strings
        const keyStr = String.fromCharCode(...keyBytes);
        const valueStr = String.fromCharCode(...valueBytes);
        
        // Parse JSON values
        let key, value;
        try {
            key = JSON.parse(keyStr);
            value = JSON.parse(valueStr);
        } catch (e) {
            console.warn(`JSON parse error for: ${keyStr} / ${valueStr}`);
            key = keyStr;
            value = valueStr;
        }
        
        result.push([key, value]);
    }
    
    return result;
}
```

## Breakthrough Debugging Techniques

Several specialized debugging techniques proved essential:

### 1. Buffer Visualization

We created a tool to visualize the buffer at different stages:

```javascript
function visualizeBuffer(buffer, width = 16) {
    let output = "Offset | Hex                                                      | ASCII\n";
    output += "-------|----------------------------------------------------------|----------------\n";
    
    for (let i = 0; i < buffer.length; i += width) {
        const slice = buffer.slice(i, i + width);
        
        // Hex representation
        const hex = slice.map(b => b.toString(16).padStart(2, '0')).join(' ');
        
        // ASCII representation
        const ascii = slice.map(b => {
            if (b >= 32 && b <= 126) return String.fromCharCode(b);
            return '.';
        }).join('');
        
        output += `${i.toString().padStart(6, '0')} | ${hex.padEnd(width*3, ' ')} | ${ascii}\n`;
    }
    
    return output;
}
```

### 2. PRNG State Tracing

To debug PRNG synchronization issues, we traced the state evolution:

```javascript
function tracePRNGState(seed, salt, steps) {
    let state = seed;
    let round = -1;
    let saltState = salt;
    
    console.log("PRNG state tracing:");
    console.log("Step | Round | State (hex)     | Output | Salt");
    console.log("-----|-------|-----------------|--------|------");
    
    for (let i = 0; i < steps; i++) {
        let output;
        
        if (++round > 2) {
            state = mixInt(state);
            round = 0;
        }
        
        output = state >> (16 - 8 * round);
        output ^= --saltState;
        output &= 255;
        
        console.log(`${i.toString().padStart(4)} | ${round}     | ${state.toString(16).padStart(16, '0')} | ${output.toString(16).padStart(2, '0')}     | ${saltState}`);
    }
}
```

### 3. Cross-Validation with Original Code

We injected debug code into both the original and our implementation to verify identical behavior:

```javascript
// Injected into original code
var originalOutputs = [];
var originalPRNGValues = [];

// Hook the original PRNG function
var originalPRNG = I(seed, salt)[0];
var hookedPRNG = function() {
    var result = originalPRNG.apply(this, arguments);
    originalPRNGValues.push(result);
    return result;
};

// Replace the original function
I = function() { return [hookedPRNG]; };

// Then in our implementation
const ourPRNGValues = [];
const ourPRNG = createPrng(seed, salt);
const hookedOurPRNG = function() {
    const result = ourPRNG.apply(this, arguments);
    ourPRNGValues.push(result);
    return result;
};

// After running both
console.log("PRNG sequences identical:", 
    originalPRNGValues.length === ourPRNGValues.length &&
    originalPRNGValues.every((v, i) => v === ourPRNGValues[i]));
```

## Lessons Learned from Implementation

The decryption implementation revealed several valuable insights:

1. **Exact Replication is Essential**: Even minor deviations in implementation causes complete decryption failures
2. **End-to-End Testing is Crucial**: Unit tests alone were insufficient; full-system tests were needed
3. **Buffer Visualization Tools**: Specialized debugging tools were critical for understanding complex data structures
4. **Testing with Real Data**: Using captured real-world data was more effective than synthetic test cases
5. **Side-by-Side Comparison**: Running both original and rewritten code with the same inputs revealed subtle differences

Overall, the decryption implementation required extreme precision and systematic debugging, but resulted in a robust solution that can decrypt any DataDome payload given the correct hash and client ID.

# DataDome Decryption: Implementation Process

This document details the process of implementing a decryption solution for DataDome's encryption algorithm. While the `encryption_rewrite.js` file represents a clean implementation of the encryption process, `decryption.js` required us to develop a complementary system capable of reversing each step.

## Challenge Overview

Implementing decryption for the DataDome algorithm presented several unique challenges:

1. **PRNG Sequence Replication**: The encryption uses multiple PRNGs with specific state evolution patterns that must be exactly replicated
2. **Custom Encoding Reversal**: The non-standard base64-like encoding needed to be precisely reversed
3. **Buffer Structure Recognition**: The decrypted buffer contains a JSON-like structure that required custom parsing
4. **XOR Chain Reversal**: Multiple layers of XOR operations needed to be applied in the correct sequence

## Analysis and Approach

Our approach to developing the decryption implementation involved:

1. **Full encryption understanding**: First deeply understanding every step of the encryption process
2. **Step-by-step reversal**: Designing each decryption step to precisely mirror its encryption counterpart
3. **Test-driven development**: Creating test cases to verify each component's accuracy

## Decryption Components Implementation

### 1. PRNGHelper Class: Exact PRNG Replication

The most critical component for successful decryption was precisely replicating the PRNG behavior. We created a helper class that exactly duplicates the encryption PRNG implementation:

```javascript
class PRNGHelper {
    /**
     * Bitwise mixing function for PRNG state.
     * @param {number} value
     * @returns {number}
     */
    _mixInt(value) {
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
```

Key implementation details:
1. **Identical state evolution**: The round counter and state transformation logic must match exactly
2. **Same salt application**: The salt decrement and XOR operation must occur at identical points
3. **Caching behavior**: The caching mechanism must operate identically to the encryption version

### 2. Custom Base64 Decoder

The encryption uses a custom base64-like encoding scheme that needed to be precisely reversed:

```javascript
/**
 * Decode the custom base64-like string
 * @param {string} encoded - Encoded string
 * @returns {Array<number>} - Array of decoded bytes
 * @private
 */
_decodeCustomBase64(encoded) {
    let bytes = [];
    let n = this.salt;

    for (let i = 0; i < encoded.length; i += 4) {
        if (i + 3 >= encoded.length) break;

        let c1 = this._decode6Bits(encoded.charCodeAt(i));
        let c2 = this._decode6Bits(encoded.charCodeAt(i + 1));
        let c3 = this._decode6Bits(encoded.charCodeAt(i + 2));
        let c4 = this._decode6Bits(encoded.charCodeAt(i + 3));

        let chunk = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;

        bytes.push(((chunk >> 16) & 255) ^ (--n & 255));
        bytes.push(((chunk >> 8) & 255) ^ (--n & 255));
        bytes.push((chunk & 255) ^ (--n & 255));
    }

    // Handle padding if needed
    let mod = encoded.length % 4;
    if (mod) {
        bytes = bytes.slice(0, bytes.length - (3 - mod));
    }

    return bytes;
}
```

Key implementation details:
1. **Character to 6-bit value mapping**: Reverse of the encoding function
2. **Chunk reconstruction**: Combining four 6-bit values into a 24-bit integer
3. **Byte extraction**: Splitting the 24-bit integer back into three bytes
4. **Salt XOR reversal**: Apply the same salt decrement and XOR pattern
5. **Padding handling**: Properly handle non-standard truncated output

The custom 6-bit value decoding function:

```javascript
/**
 * Decode a 6-bit encoded character according to DataDome's custom encoding
 * @param {number} charCode - Character code to decode
 * @returns {number} - Decoded 6-bit value
 * @private
 */
_decode6Bits(charCode) {
    if (charCode >= 97 && charCode <= 122) return charCode - 59;      // 'a'-'z' → 38-63
    if (charCode >= 65 && charCode <= 90) return charCode - 53;       // 'A'-'Z' → 12-37
    if (charCode >= 48 && charCode <= 57) return charCode - 46;       // '0'-'9' → 2-11
    if (charCode === 45) return 0;                                    // '-' → 0
    if (charCode === 95) return 1;                                    // '_' → 1
    return 0; // fallback
}
```

### 3. CID-PRNG XOR Reversal

After decoding the base64 representation, we need to reverse the CID-PRNG XOR applied during encryption:

```javascript
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
```

Key implementation details:
1. **Identical CID-PRNG seeding**: Must use the exact same seed derivation as encryption
2. **Byte-by-byte XOR**: Apply XOR to each byte in the correct order
3. **Last byte handling**: The last byte is a marker that needs special handling

### 4. JSON-like Structure Parsing

The most complex part of decryption is parsing the recovered buffer, which contains a JSON-like structure with each key-value pair XORed with the main PRNG:

```javascript
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

    // Convert to string for easier processing
    const jsonStr = String.fromCharCode(...decodedBytes);

    // Now parse this string to extract entries
    return this._parseJsonString(jsonStr);
}
```

Key implementation details:
1. **Marker byte removal**: The final byte is a closing brace marker, not part of the data
2. **Main PRNG recreation**: Must generate the exact same PRNG sequence as during encryption
3. **XOR reversal**: Apply XOR to each byte with the PRNG output
4. **String conversion**: Convert the decoded bytes to a string for processing
5. **Custom JSON parsing**: Use custom logic to extract key-value pairs from the JSON-like structure

### 5. JSON String Parsing

The final step involves parsing the recovered JSON-like string into key-value pairs:

```javascript
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
                    value = valueContent;
                } else if (jsonStr[i] === '{' || jsonStr[i] === '[') {
                    // Object or array value - specialized handling
                    const isObject = jsonStr[i] === '{';
                    const openChar = jsonStr[i];
                    const closeChar = isObject ? '}' : ']';
                    let nestLevel = 1;
                    let valueStr = openChar;
                    i++; // Skip opening brace/bracket

                    while (i < jsonStr.length && nestLevel > 0) {
                        if (jsonStr[i] === openChar) nestLevel++;
                        else if (jsonStr[i] === closeChar) nestLevel--;
                        
                        if (nestLevel > 0 || jsonStr[i] === closeChar) {
                            valueStr += jsonStr[i];
                        }
                        i++;
                    }

                    try {
                        value = JSON.parse(valueStr);
                    } catch {
                        value = valueStr; // Fallback if parsing fails
                    }
                } else if (/^-?\d/.test(jsonStr[i])) {
                    // Number value
                    let numStr = '';
                    while (i < jsonStr.length && /[-0-9.eE+]/.test(jsonStr[i])) {
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
                result.push([key, value]);
            } else {
                // Skip any other characters
                i++;
            }
        } catch (error) {
            // If any parsing error occurs, skip to the next character
            i++;
        }
    }

    return result;
}
```

Key implementation details:
1. **Character-by-character parsing**: Process the JSON character by character to handle the custom structure
2. **Multiple value types**: Handle different value types (string, number, boolean, null, object, array)
3. **Nested structure tracking**: Properly handle nested objects and arrays with their own depth counters
4. **Error resilience**: Recover from parsing errors to handle potential anomalies

## Complete Decryption Flow

The complete decryption flow can be summarized as:

1. **Initialize the decryptor**:
   - Set up with the same hash and CID used for encryption
   - Calculate the same seed values used during encryption

2. **Decode the custom base64**:
   - Convert the URL-safe characters back to 6-bit values
   - Combine 6-bit values into 24-bit chunks
   - Extract and un-XOR bytes using salt

3. **Reverse the CID-PRNG XOR**:
   - Create identical CID-PRNG with same seed
   - XOR each byte with the CID-PRNG output

4. **Reverse the main PRNG XOR**:
   - Create identical main PRNG with same seed
   - XOR each byte with main PRNG output

5. **Parse the JSON-like structure**:
   - Process the structure character by character
   - Extract key-value pairs
   - Handle different value types

The result is an array of key-value pairs matching the original data that was encrypted.

## Verification and Validation

To ensure the decryption implementation was correct, we implemented several validation mechanisms:

1. **Unit tests** for each component:
   - PRNG sequence generation
   - Custom base64 decoding
   - JSON structure parsing

2. **End-to-end tests** with sample data:
   - Encrypt known data using the rewritten encryption
   - Decrypt using our decryption implementation
   - Verify that the original data is recovered correctly

3. **Edge case testing**:
   - Empty strings
   - Special characters
   - Nested objects and arrays
   - Various numeric values and boolean values

## Implementation Challenges and Solutions

### Challenge 1: PRNG Synchronization

One of the most difficult aspects was ensuring the PRNGs produced identical byte sequences.

**Solution**: We meticulously replicated every aspect of the PRNG implementation, including:
- The precise seeding formulas
- The round counter evolution
- The salt decrement and application
- The caching mechanism

Even a single-byte difference would cause cascading errors, so extreme precision was required.

### Challenge 2: JSON-like Structure Parsing

The buffer contains a JSON-like structure but cannot be parsed with `JSON.parse()` directly.

**Solution**: We implemented a custom parser that:
- Processes character by character
- Handles different value types
- Maintains correct nesting levels for objects and arrays
- Implements error recovery mechanisms

### Challenge 3: Character Encoding Issues

UTF-8 handling was particularly challenging, especially for multi-byte characters and surrogate pairs.

**Solution**: We implemented a careful reversal of the UTF-8 encoding process, ensuring proper handling of:
- ASCII characters (1 byte)
- Common Unicode characters (2-3 bytes)
- Surrogate pairs and extended Unicode (4 bytes)

## DataDomeDecryptor Class

- **Constructor**: `new DataDomeDecryptor(hash, cid, salt, challengeType = 'captcha')`
  - `hash`: Hash value used during encryption
  - `cid`: Client ID used during encryption
  - `salt`: Salt value (optional)
  - `challengeType`: 'captcha' (default) or 'interstitial'

- **Key Methods**:
  - `decrypt(encoded)`: Decrypts the encoded string to recover the original data
  - `setChallengeType(challengeType)`: Updates the challenge type and recalculates PRNG seeds
  - `getChallengeType()`: Returns the current challenge type 


## Conclusion

The decryption implementation successfully reverses each step of DataDome's encryption process, allowing complete recovery of the original data. This was accomplished through meticulous analysis of the encryption algorithm and precise replication of its key components.

The success of this implementation demonstrates that even complex, multi-layered encryption schemes can be reversed when the algorithm is known, highlighting the importance of true cryptographic security rather than security through obscurity.

For a complete technical analysis of the encryption and decryption algorithms, see [technical_analysis.md](technical_analysis.md).

---

## Author

If you found this project helpful or interesting, consider starring the repo and following me for more security research and tools, or buy me a coffee to keep me up.

Stay in touch with me via discord or mail or anything.

<p align="center">
  <a href="https://github.com/GlizzyKingDreko"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"></a>
  <a href="https://twitter.com/GlizzyKingDreko"><img src="https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white" alt="Twitter"></a>
  <a href="https://medium.com/@GlizzyKingDreko"><img src="https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white" alt="Medium"></a>
  <a href="https://discord.com/users/GlizzyKingDreko"><img src="https://img.shields.io/badge/Discord-7289DA?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="mailto:glizzykingdreko@protonmail.com"><img src="https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=white" alt="Email"></a>
  <a href="https://buymeacoffee.com/glizzykingdreko"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-yellow?style=for-the-badge&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>
