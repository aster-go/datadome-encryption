# ENCRYPTION.md

This document provides a deep-dive analysis of the encryption logic implemented in `encryption_rewrite.js`. The script is designed to obfuscate and encrypt key-value data pairs using a custom, multi-stage process involving PRNGs, custom base64-like encoding, and several layers of XOR and mixing operations. The logic is intentionally complex and mimics real-world obfuscated payload builders.

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

![encryption](../assets/encryption.jpg)

## Navigation

| Document | Description |
|----------|-------------|
| [README.md](../README.md) | Project overview and introduction |
| [ENCRYPTION.md](./ENCRYPTION.md) | Detailed analysis of the encryption algorithm |
| [DECRYPTION.md](./DECRYPTION.md) | Implementation of the decryption process |
| [technical_analysis.md](./technical_analysis.md) | Technical deep-dive into cryptographic properties |
| [LEARN.md](./LEARN.md) | Educational guide on reverse engineering techniques |

## High-Level Encryption Pipeline

1. **Initialization**: The encryptor is initialized with a `hash`, `cid`, and optional `salt`.
2. **Buffer Construction**: Each key-value pair is encoded and obfuscated, then appended to an internal buffer.
3. **PRNG XOR**: The buffer is XORed with a PRNG sequence seeded by the `cid` and `salt`.
4. **Marker Byte**: A marker byte is appended, also obfuscated with the PRNG.
5. **Custom Base64-like Encoding**: The resulting byte array is encoded into a string using a custom 6-bit mapping and further obfuscated with the salt.
6. **Output**: The final string is the encrypted payload.

**Note** What the salt is doing (in really simplified terms) is to change the last char of the encryption string. It will be so "based on timestamp" for this reason when comparing 2 encrypted strings made with the same `cid`, `hash` and signals, be sure to remove the last char before comparing them (unless you are using the same salt). Take a look into [validity_check.js](../tests/validity_check.js)

---

## Table of Contents
- [ENCRYPTION.md](#encryptionmd)
  - [Navigation](#navigation)
  - [High-Level Encryption Pipeline](#high-level-encryption-pipeline)
  - [Table of Contents](#table-of-contents)
  - [Class: `DataDomeEncryptor`](#class-datadomeencryptor)
    - [Constructor](#constructor)
    - [Key Methods](#key-methods)
      - [`_generateHsv()`](#_generatehsv)
      - [`_customHash(str)`](#_customhashstr)
      - [`_encode6Bits(value)`](#_encode6bitsvalue)
      - [`_mixInt(value)`](#_mixintvalue)
      - [`_createPrng(seed, salt)`](#_createprngseed-salt)
      - [`_utf8Xor(str, prng)`](#_utf8xorstr-prng)
      - [`_safeJson(value)`](#_safejsonvalue)
      - [`_encodePayload(byteArr, salt, encode6Bits)`](#_encodepayloadbytearr-salt-encode6bits)
      - [`_resetEncryptionState()`](#_resetencryptionstate)
      - [`_addSignal(key, value)`](#_addsignalkey-value)
      - [`_buildPayload(cid)`](#_buildpayloadcid)
      - [`add(key, value)`](#addkey-value)
      - [`encrypt()`](#encrypt)
      - [`setChallengeType(challengeType)`](#setchallengetypechallengetype)
      - [`getChallengeType()`](#getchallengetype)
  - [Step-by-Step Encryption Example](#step-by-step-encryption-example)
  - [Debug Files](#debug-files)
  - [Notes on Obfuscation](#notes-on-obfuscation)
  - [Diagrams](#diagrams)
  - [Summary Table](#summary-table)
  - [Conclusion](#conclusion)
- [Challenges and Methodologies in Reverse Engineering DataDome](#challenges-and-methodologies-in-reverse-engineering-datadome)
  - [Methodology and Testing Approach](#methodology-and-testing-approach)
    - [1. Initial Reconnaissance and Capture](#1-initial-reconnaissance-and-capture)
    - [2. Static Analysis Challenges](#2-static-analysis-challenges)
    - [3. Dynamic Analysis and Testing Methods](#3-dynamic-analysis-and-testing-methods)
    - [4. Specific Difficulties Encountered](#4-specific-difficulties-encountered)
      - [4.1 PRNG Analysis Challenges](#41-prng-analysis-challenges)
      - [4.2 Buffer Construction Issues](#42-buffer-construction-issues)
      - [4.3 Verification Challenges](#43-verification-challenges)
  - [Test Cases and Validation](#test-cases-and-validation)
    - [1. Component-Level Testing](#1-component-level-testing)
    - [2. Intermediate Output Verification](#2-intermediate-output-verification)
    - [3. Full End-to-End Verification](#3-full-end-to-end-verification)
    - [4. Edge Case Testing](#4-edge-case-testing)
  - [Learnings and Insights](#learnings-and-insights)
- [DataDome Encryption: Reverse Engineering Process](#datadome-encryption-reverse-engineering-process)
  - [Original Code Analysis](#original-code-analysis)
    - [Obfuscation Techniques Identified](#obfuscation-techniques-identified)
    - [Main Encryption Function Extraction](#main-encryption-function-extraction)
  - [Core Functions Decomposition](#core-functions-decomposition)
    - [Function 1: Custom Hash Function (d)](#function-1-custom-hash-function-d)
    - [Function 2: Bitwise Mixing Function (D)](#function-2-bitwise-mixing-function-d)
    - [Function 3: 6-bit Encoding (N)](#function-3-6-bit-encoding-n)
    - [Function 4: PRNG Generator (I)](#function-4-prng-generator-i)
  - [Main Encryption Logic Analysis](#main-encryption-logic-analysis)
    - [Key Function 1: UTF-8 Conversion and XOR (x)](#key-function-1-utf-8-conversion-and-xor-x)
    - [Key Function 2: JSON Stringify (z)](#key-function-2-json-stringify-z)
    - [Key Function 3: Signal Addition (y)](#key-function-3-signal-addition-y)
    - [Key Function 4: Payload Building](#key-function-4-payload-building)
    - [Key Function 5: Custom Base64 Encoding (A)](#key-function-5-custom-base64-encoding-a)
  - [Structuring the Clean Implementation](#structuring-the-clean-implementation)
  - [Verification Process](#verification-process)
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

## Class: `DataDomeEncryptor`

### Constructor
- **Inputs**: `hash`, `cid`, `salt` (optional), `challengeType` (optional, default: 'captcha')
- **Purpose**: Sets up the encryption state, including PRNG seeds and internal buffer.
- **Challenge Types**: 
  - `captcha`: Default challenge type, uses standard DataDome CAPTCHA parameters
  - `interstitial`: Alternative challenge type with different XOR constants and fixed HSV value

### Key Methods

#### `_generateHsv()`
- Generates a pseudo-random HSV string based on the hash and random values.
- Used as a hidden value in the encryption process (not directly in the buffer).

#### `_customHash(str)`
- Custom string hashing function, returns a 32-bit integer.
- Used to seed PRNGs.

#### `_encode6Bits(value)`
- Maps a 6-bit value (0-63) to a custom character code for the payload.
- The mapping is non-standard and intentionally obfuscated.

#### `_mixInt(value)`
- Bitwise mixing function for PRNG state.
- Used to further obfuscate PRNG state transitions.

#### `_createPrng(seed, salt)`
- Returns a PRNG function with internal state.
- The PRNG is used for both buffer obfuscation and the final XOR step.
- The PRNG state is advanced and mixed in a non-standard way, with salt affecting the output.

#### `_utf8Xor(str, prng)`
- Converts a string to a UTF-8 byte array, then XORs each byte with the PRNG output.
- Used for both keys and values.

#### `_safeJson(value)`
- Safely JSON-stringifies a value, returns undefined on error.

#### `_encodePayload(byteArr, salt, encode6Bits)`
- Encodes an array of bytes into a custom base64-like string.
- Each group of 3 bytes is obfuscated with the salt, then split into 4 groups of 6 bits, and mapped to characters.

#### `_resetEncryptionState()`
- Initializes or resets the encryption state (PRNG, buffer, etc.).
- Sets up the PRNG seeds and buffer.

#### `_addSignal(key, value)`
- Encodes and obfuscates a key-value pair, then appends it to the buffer.
- Steps:
  1. Compute a start byte: `prng() ^ (buffer.length ? 44 : 123)`
  2. Encode the key as UTF-8, XOR with PRNG, append to buffer
  3. Add a separator byte: `58 ^ prng()`
  4. Encode the value as UTF-8, XOR with PRNG, append to buffer

#### `_buildPayload(cid)`
- Finalizes the buffer and produces the encrypted payload string.
- Steps:
  1. Create a PRNG seeded with `cid` and `salt`
  2. XOR each buffer byte with the PRNG output
  3. Append a marker byte: `125 ^ prng(true) ^ cidPrng()`
  4. Encode the result with `_encodePayload`
  5. Write debug files for each stage

#### `add(key, value)`
- Public method to add a key-value pair (calls `_addSignal`).

#### `encrypt()`
- Public method to build the encrypted payload (calls `_buildPayload`).

#### `setChallengeType(challengeType)`
- Updates the challenge type and resets the encryption state with appropriate parameters.
- Valid values are 'captcha' or 'interstitial'.

#### `getChallengeType()`
- Returns the current challenge type being used.

---

## Step-by-Step Encryption Example

1. **Initialization**
   - PRNG seeds are derived from the hash, cid, and salt.
   - Internal buffer is empty.

2. **Adding Key-Value Pairs**
   - For each pair:
     - Start byte is computed and added.
     - Key is UTF-8 encoded, XORed with PRNG, and added.
     - Separator byte is added.
     - Value is UTF-8 encoded, XORed with PRNG, and added.

3. **Finalizing Buffer**
   - Buffer is written to `debug_encrypt_buffer.json` (plaintext, obfuscated but not yet PRNG-XORed).

4. **PRNG XOR**
   - Each buffer byte is XORed with a PRNG seeded by `cid` and `salt`.
   - Result is written to `debug_encrypt_cidprng.json` (ciphertext, ready for encoding).
   - Marker byte is appended (also PRNG-XORed).

5. **Custom Base64-like Encoding**
   - The PRNG-XORed buffer is encoded using `_encodePayload`:
     - Each group of 3 bytes is obfuscated with the salt, then split into 4 groups of 6 bits.
     - Each 6-bit group is mapped to a character using `_encode6Bits`.
   - The final string is written to `debug_encrypt_final.txt`.

6. **Output**
   - The encrypted payload string is returned.

---

## Debug Files

- `debug_encrypt_buffer.json`: Buffer after all key-value pairs are added, before PRNG XOR.
- `debug_encrypt_cidprng.json`: Buffer after PRNG XOR and marker byte, before base64-like encoding.
- `debug_encrypt_final.txt`: Final encoded string (the encrypted payload).

---

## Notes on Obfuscation

- The PRNG logic is intentionally non-standard, with state mixing and salt affecting output.
- The custom base64-like encoding uses a non-standard 6-bit to char mapping.
- Multiple layers of XOR and mixing make reverse engineering non-trivial.

---

## Diagrams

```
[Input Data] --(addSignal)--> [Obfuscated Buffer] --(PRNG XOR)--> [Cipher Buffer + Marker] --(Custom Base64)--> [Final String]
```

---

## Summary Table

| Step                | Input                | Output                | File (if any)                |
|---------------------|----------------------|-----------------------|------------------------------|
| Buffer Construction | key-value pairs      | Obfuscated buffer     | debug_encrypt_buffer.json    |
| PRNG XOR           | Obfuscated buffer    | Cipher buffer + mark  | debug_encrypt_cidprng.json   |
| Base64-like Encode  | Cipher buffer + mark | Final string          | debug_encrypt_final.txt      |

---

## Conclusion

The encryption process in `encryption_rewrite.js` is a multi-stage, obfuscated pipeline involving custom PRNGs, XOR, and encoding. Each step is carefully designed to make decryption non-trivial without full knowledge of the process and parameters. 

# Challenges and Methodologies in Reverse Engineering DataDome

## Methodology and Testing Approach

The reverse engineering of DataDome's encryption algorithm required a systematic approach involving multiple stages of testing and validation:

### 1. Initial Reconnaissance and Capture

- **Dynamic Capture**: Intercepted encrypted payloads during live DataDome captcha challenges
- **Client-Side Debugging**: Used browser developer tools to locate the encryption functions in obfuscated JavaScript
- **Format Identification**: Analyzed patterns in the encrypted outputs to identify the encoding scheme

### 2. Static Analysis Challenges

- **Excessive Code Obfuscation**: Variable names like `Le`, `qe`, `Ta`, and `ya` provided no semantic meaning
- **Dead Code Injection**: Large portions of the code were never executed but existed to confuse analysis
- **Control Flow Obfuscation**: Function calls were wrapped in complex conditions and indirect references
- **Dynamic Value Generation**: Many critical constants were generated through mathematical operations rather than directly stated

### 3. Dynamic Analysis and Testing Methods

- **Function Isolation**: Extracted key functions and tested them individually with controlled inputs
- **Breakpoint Analysis**: Set strategic breakpoints to observe internal values at critical points
- **Input-Output Mapping**: Created test cases to map specific inputs to their encrypted outputs
- **Differential Analysis**: Made small changes to inputs to observe how they affected the output

### 4. Specific Difficulties Encountered

#### 4.1 PRNG Analysis Challenges

- **State Tracking Complexity**: The PRNG maintains internal state across multiple calls, making single function analysis insufficient
- **Dual PRNG Interaction**: The interaction between the main PRNG and CID-PRNG was particularly difficult to trace
- **Cache Timing Issues**: The PRNG caching mechanism caused non-obvious output patterns that initially appeared random

#### 4.2 Buffer Construction Issues

- **Mixed Encoding Types**: Both strings and numeric values had different encoding paths
- **Invisible Markers**: The buffer contains invisible markers (start bytes, separators) that were difficult to identify
- **Nested XOR Operations**: Each byte undergoes multiple XOR operations, making it hard to isolate the effect of each

#### 4.3 Verification Challenges

- **Exact Reproduction Requirement**: Even a single-byte difference in any stage would cascade into completely different output
- **Parameter Sensitivity**: Small changes to inputs like salt or hash would drastically alter the output
- **Edge Case Handling**: Special cases like empty values, null values, and complex nested structures required specific testing

## Test Cases and Validation

To ensure our reverse engineering was accurate, we developed a comprehensive testing framework:

### 1. Component-Level Testing

Each function was isolated and tested with controlled inputs:

```javascript
// Example test for the _customHash function
const testHash = (input) => {
    const originalResult = originalCode.hash(input);
    const rewrittenResult = rewrite._customHash(input);
    console.log(`Input: "${input}"`);
    console.log(`Original hash: ${originalResult}`);
    console.log(`Rewritten hash: ${rewrittenResult}`);
    console.log(`Match: ${originalResult === rewrittenResult}`);
};

// Test cases
testHash(""); // Empty string
testHash("abc"); // Simple string
testHash("!@#$%^&*()"); // Special characters
testHash("A".repeat(1000)); // Long string
```

### 2. Intermediate Output Verification

For multi-stage processes, we verified each intermediate step:

```javascript
// Add debug outputs at each stage
fs.writeFileSync('debug_encrypt_buffer.json', JSON.stringify(this._buffer));
fs.writeFileSync('debug_encrypt_cidprng.json', JSON.stringify(output));
fs.writeFileSync('debug_encrypt_final.txt', encoded);
```

### 3. Full End-to-End Verification

For complete validation, we:
- Created test fixtures with known inputs and outputs
- Processed a variety of data types and structures
- Compared outputs with the original algorithm byte-by-byte
- Verified that our decryption could reverse both the original and rewritten encryption

### 4. Edge Case Testing

We identified and tested numerous edge cases:
- Empty strings and null values
- Unicode characters including multi-byte and surrogate pairs
- Very large numbers and scientific notation
- Nested objects and arrays
- Boolean values and special JSON values

## Learnings and Insights

The reverse engineering process yielded several key insights about DataDome's approach:

1. **Intentional Complexity**: The algorithm appears deliberately over-engineered to deter analysis
2. **Layered Obfuscation**: Rather than relying on strong cryptography, multiple layers of weak obfuscation are stacked
3. **Performance Constraints**: The algorithm makes trade-offs that favor execution speed over security
4. **Browser Compatibility**: The implementation avoids modern APIs, likely for broader compatibility with older browsers
5. **Evolution Patterns**: Comparing versions across time showed minimal changes to the core algorithm, suggesting a lack of security iterations

These methodical testing approaches and careful analysis were essential to successfully reverse engineering the complete encryption system, enabling us to create both a clean implementation and a working decryption solution.

# DataDome Encryption: Reverse Engineering Process

This document details the step-by-step process of reverse engineering DataDome's obfuscated encryption algorithm from `encryption_original.js` to the clean implementation in `encryption_rewrite.js`.

## Original Code Analysis

### Obfuscation Techniques Identified

The original code employs multiple layers of sophisticated obfuscation:

```javascript
//const _hsv = "93440349C6C6";

let cid = "f5plrtBvWRjaAknic6efnfeti1YCvwXlZYI_tK~4OUEKH_w6OgQEA6NyAMgf1CeWCTaKdySlOVR_uIbSV2yv~WwLUperWQAqpqOWFZyfnM2RYuPz5LgCLTKo4Khv~bdv"
let hash = "14D062F60A4BDE8CE8647DFC720349"

var n = hash.slice(-4),
    t = Math.floor(Math.random() * 9),
    e = Math.random().toString(16).slice(2, 10).toUpperCase();
const _hsv = e.slice(0, t) + n + e.slice(t);
var Le = Math.ceil(2554.92),
    qe = Math.floor(1.69);
var ra = parseInt(747.75);
var Ma = parseInt(-816.33);
```

The most confusing elements include:
1. **Nonsensical variable names** (`Le`, `qe`, `ra`, `Ma`, etc.)
2. **Floating-point constants** that get rounded to integers, making their purpose unclear
3. **Dead code branches** with complex conditions that always evaluate to the same result
4. **Multiple nested closures** to hide the actual functionality

### Main Encryption Function Extraction

The core encryption functionality is buried in a complex closure pattern:

```javascript
var Ea = function () {
    // Unreachable condition check
    if (Ta && s[150][460] != s[467][62]) return ya;
    
    // Meaningless operations
    Math.ceil(4.1), Math.ceil(0.25), Ta = 1;
    
    // Important constants hidden among noise
    var e = 1789537805,  // Default hash result
        t = Math.floor(1.29),  // Useless
        a = parseInt(1567.97), // Useless
        M = 9959949970,  // PRNG seed component
        g = !0;  // Alt mode flag
    
    // Function d: Hash function
    function d(r) { /* ... */ }
    
    // Function D: Mixing function 
    function D(e) { /* ... */ }
    
    // Function N: Encoding function
    function N(e) { /* ... */ }
    
    // Function I: PRNG creator
    function I(e, t) { /* ... */ }
    
    // The actual returned encryption function
    return ya = function (e, t) { /* ... */ };
}()
```

The main encryption function is created by the IIFE (Immediately Invoked Function Expression) and stored in `ya`, which is then accessed through `Ea`.

## Core Functions Decomposition

### Function 1: Custom Hash Function (d)

```javascript
function d(r) {
    if (!r) return e;
    for (var M = 0, g = Math.ceil(-981.04), d = Number(-1638), h = 0; h < r.length; h++) 
        M = (M << 5) - M + r.charCodeAt(h) | 0;
    return (2 * (Le | a) + 3 * ~(Le | a) - 2 * (~Le | a) - ~(Le & a) > 
            -1 * (ra & ~s) + 2 * ~(ra & s) + 1 * ~(ra ^ s) - 3 * ~(ra | s) - 2 * ~(ra | ~s) ? 
            0 != M : (d | g) - 2 * (~d & g) + ~g - (d | ~g) > 331) ? M : e;
}
```

**Reverse engineering steps:**

1. **Identifying the algorithm**: This is a variant of the djb2 hash algorithm
2. **Removing noise variables**: `g` and `d` are unused in the actual computation
3. **Simplifying the conditional**: The complex condition evaluates to `0 != M ? M : e`
4. **Determining the fallback value**: `e` (1789537805) is returned if the input is empty or the hash is 0

**Rewritten as:**

```javascript
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
```

### Function 2: Bitwise Mixing Function (D)

```javascript
function D(e) {
    e ^= e << 13;
    e ^= e >> 17;
    return e ^ e << 5;
}
```

This function was relatively straightforward - it's a bitwise mixing function using XOR and shifts. It creates non-linear transformations of the input value.

**Rewritten as:**

```javascript
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
```

### Function 3: 6-bit Encoding (N)

```javascript
function N(e) {
    return e > 37 ? 59 + e : e > 11 ? 53 + e : e > 1 ? 46 + e : 50 * e + 45;
}
```

This function maps 6-bit values (0-63) to ASCII character codes.

**Analysis:**
- Values 0-1: Special cases mapping to '-' (45) and '_' (95)
- Values 2-11: Map to ASCII '0'-'9' (48-57)
- Values 12-37: Map to ASCII 'A'-'Z' (65-90)
- Values 38-63: Map to ASCII 'a'-'z' (97-122)

**Rewritten as:**

```javascript
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
```

### Function 4: PRNG Generator (I)

```javascript
function I(e, t) {
    var a = e,
        n = -1,
        c = t,
        i = g;
    g = !1;
    var r = null;
    return [function (e) {
        var t;
        if (null !== r) {
            t = r;
            r = null;
        } else {
            ++n > 2 && (a = D(a), n = 0);
            t = a >> 16 - 8 * n;
            t ^= i ? --c : 0;
            t &= 255;
            e && (r = t);
        }
        return t;
    }];
}
```

This was one of the most complex functions to understand. It creates a stateful PRNG that:
1. Maintains an internal state `a` that evolves through the `D` function
2. Uses a round counter `n` to extract different 8-bit segments of the state
3. Optionally XORs the output with a decrementing salt counter `c`
4. Includes a caching mechanism triggered by the `e` parameter

**Rewritten as:**

```javascript
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
```

## Main Encryption Logic Analysis

The core encryption functions were nested inside another function:

```javascript
return ya = function (e, t) {
    var a = M ^ d(e) ^ t,
        s = D(D(Date.now() >> 3 ^ 11027890091) * M),
        g = I(a, s)[0],
        h = [],
        j = !0,
        p = 0,
        x = function (e) { /* UTF-8 conversion and XOR */ },
        z = function (e) { /* JSON stringify */ },
        A = function (e) { /* Custom base64 encoding */ };
        
    function y(e, t) { /* Adds a key-value pair to the buffer */ }
    
    var T = new Set();
    
    return [y, function (e, t) { /* Deduplicating key-value addition */ }, 
            function (e) { /* Builds the final payload */ }];
}
```

### Key Function 1: UTF-8 Conversion and XOR (x)

```javascript
x = function (e) {
    for (var t = [], a = 0, c = 0; c < e.length; c++) {
        var r = e.charCodeAt(c);
        r < 128 ? t[a++] = r : r < 2048 ? (t[a++] = r >> 6 | 192, t[a++] = 63 & r | 128) : 
        55296 == (64512 & r) && c + 1 < e.length && 56320 == (64512 & e.charCodeAt(c + 1)) ? 
        (r = 65536 + ((1023 & r) << 10) + (1023 & e.charCodeAt(++c)), t[a++] = r >> 18 | 240, 
        t[a++] = r >> 12 & 63 | 128, t[a++] = r >> 6 & 63 | 128, t[a++] = 63 & r | 128) : 
        (t[a++] = r >> 12 | 224, t[a++] = r >> 6 & 63 | 128, t[a++] = 63 & r | 128);
    }
    for (var o = 0; o < t.length; o++) t[o] ^= g();
    return t;
}
```

This function:
1. Converts a JavaScript string to UTF-8 bytes
2. XORs each byte with the output of the PRNG function `g`

**Rewritten as:**

```javascript
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
```

### Key Function 2: JSON Stringify (z)

```javascript
z = function (e) {
    try {
        return JSON.stringify(e);
    } catch (e) {
        return;
    }
}
```

A simple wrapper around JSON.stringify with error handling.

**Rewritten as:**

```javascript
/**
 * Safely JSON-stringifies a value, returns undefined on error.
 * @param {any} value
 * @returns {string|undefined}
 */
_safeJson(value) {
    try {
        return JSON.stringify(value);
    } catch (e) {
        return;
    }
}
```

### Key Function 3: Signal Addition (y)

```javascript
function y(e, t) {
    if (`string` == typeof e && 0 != e.length && (!t || -1 != [`number`, `string`, `boolean`].indexOf(ga(t)))) {
        var a, c = z(e), s = z(t);
        if (e && void 0 !== s && e !== String.fromCharCode(120, 116, 49)) {
            h.push(g() ^ (h.length ? 44 : 123));
            Array.prototype.push.apply(h, x(c));
            h.push(58 ^ g());
            Array.prototype.push.apply(h, x(s));
            if (j) {
                j = !1;
                (`string` == typeof _hsv && _hsv.length > 0 || 
                `number` == typeof _hsv && !isNaN(_hsv)) && (a = _hsv);
            }
        }
    }
}
```

This is the core function that adds a key-value pair to the encryption buffer. It:
1. Validates the key and value types
2. Adds a start marker ('{'/',' XORed with PRNG)
3. Adds the key as UTF-8 bytes, XORed with PRNG
4. Adds a separator (':' XORed with PRNG)
5. Adds the value as UTF-8 bytes, XORed with PRNG
6. Has special handling for the first entry

**Rewritten as:**

```javascript
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
```

### Key Function 4: Payload Building

```javascript
function (e) {
    var t = I(1809053797 ^ d(e), s)[0];
    for (var a = [], n = 0; n < h.length; n++) a.push(h[n] ^ t());
    a.push(125 ^ g(!0) ^ t());
    return A(a);
}
```

This function finalizes the encryption process:
1. Creates a new PRNG based on the client ID
2. XORs each byte in the buffer with this CID-PRNG
3. Adds a closing brace ('}' XORed with both PRNGs)
4. Encodes the result using the custom base64-like function `A`

**Rewritten as:**

```javascript
/**
 * Builds the final encrypted payload string for a given cid.
 * @param {string} cid
 * @returns {string}
 */
_buildPayload(cid) {
    const cidPrng = this._createPrng(1809053797 ^ this._customHash(cid), this._salt)[0];
    let output = [];
    for (let i = 0; i < this._buffer.length; i++) output.push(this._buffer[i] ^ cidPrng());
    output.push(125 ^ this._prng(true) ^ cidPrng());
    const encoded = this._encodePayload(output, this._salt, this._encode6Bits.bind(this));
    return encoded;
}
```

### Key Function 5: Custom Base64 Encoding (A)

```javascript
A = function (e) {
    for (var t = 0, a = [], n = s; t < e.length;) {
        var r = (255 & --n ^ e[t++]) << 16 | (255 & --n ^ e[t++]) << 8 | 255 & --n ^ e[t++];
        a.push(
            String.fromCharCode(N(r >> 18 & 63)),
            String.fromCharCode(N(r >> 12 & 63)),
            String.fromCharCode(N(r >> 6 & 63)),
            String.fromCharCode(N(63 & r))
        );
    }
    var M = e.length % 3;
    return M && (a.length -= 3 - M), a.join('');
}
```

This function performs the final encoding:
1. Groups bytes into 3-byte chunks, XORing each with a decrementing salt value
2. Converts each chunk to 4 characters using the 6-bit encoding function `N`
3. Handles padding for incomplete chunks through truncation

**Rewritten as:**

```javascript
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
```

## Structuring the Clean Implementation

After understanding all the components, the final step was to structure them into a proper class:

```javascript
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
     */
    constructor(hash, cid, salt = null) {
        this.hash = hash;
        this.cid = cid;
        this._hsv = this._generateHsv();
        this._externalSalt = salt; // Store the externally provided salt
        this._initEncryptor();
    }
    
    // ... all the rewritten methods added here ...
    
    /**
     * Initializes the encryption engine and sets up the addSignal and buildPayload methods.
     */
    _initEncryptor() {
        this._resetEncryptionState();
        this.addSignal = this._addSignal.bind(this);
        this.buildPayload = this._buildPayload.bind(this);
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
}
```

## Verification Process

To ensure the rewritten code was functionally identical to the original, several verification steps were taken:

1. **Debug logging**: Adding logging points in both versions to compare intermediate values
2. **Test data encryption**: Encrypting the same data with both versions and comparing outputs
3. **Roundtrip testing**: Encrypting data, then decrypting it to verify the original values are recovered
4. **Edge case testing**: Testing with various input types, empty values, and special characters

The verification confirmed that the clean implementation produces identical results to the original obfuscated code, while being much more readable and maintainable.

## Conclusion

The reverse engineering process transformed a heavily obfuscated, difficult-to-understand implementation into a clean, well-structured class that preserves the exact functionality while making it clear how each part of the encryption process works.

This demonstrates that even sophisticated obfuscation techniques can be methodically reversed with careful analysis, and that complex algorithms can be rewritten in a more maintainable form without sacrificing functionality.

For a detailed technical analysis of the encryption algorithm itself, including cryptographic properties and security considerations, see [technical_analysis.md](technical_analysis.md). 

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
