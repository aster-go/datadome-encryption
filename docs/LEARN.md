# Learning Reverse Engineering through DataDome's Encryption

This document provides an educational guide on JavaScript reverse engineering, using the DataDome encryption system as a practical case study. Whether you're a security researcher, a developer interested in understanding obfuscation techniques, or someone looking to learn about cryptographic implementations, this guide offers insights into the methodical process of understanding and reimplementing complex obfuscated code.


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

## Table of Contents

1. [Understanding JavaScript Obfuscation](#understanding-javascript-obfuscation)
2. [Tools of the Trade](#tools-of-the-trade)
3. [Reverse Engineering Methodology](#reverse-engineering-methodology)
4. [Case Study: DataDome's Encryption](#case-study-datadomes-encryption)
5. [Common Challenges and Solutions](#common-challenges-and-solutions)
6. [Ethical Considerations](#ethical-considerations)
7. [Learning Resources](#learning-resources)

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

## Understanding JavaScript Obfuscation

JavaScript obfuscation refers to techniques that make code difficult to understand while preserving its functionality. Here are common obfuscation techniques identified in the DataDome code:

### 1. Meaningless Variable and Function Names

Original obfuscated code uses non-descriptive identifiers:

```javascript
var Ta = 1, ya;
var Ea = function () {
    if (Ta && s[150][460] != s[467][62]) return ya;
    Math.ceil(4.1), Math.ceil(0.25), Ta = 1;
    var e = 1789537805,
        t = Math.floor(1.29),
        a = parseInt(1567.97),
        M = 9959949970,
        g = !0;
    // ...
}
```

### 2. Dead Code Injection

Obfuscators add code that never executes or has no effect:

```javascript
// Meaningless operations that don't affect results
Math.ceil(4.1), Math.ceil(0.25);

// Complex conditions that always evaluate to the same result
if (2 * (Le | a) + 3 * ~(Le | a) - 2 * (~Le | a) - ~(Le & a) > 
    -1 * (ra & ~s) + 2 * ~(ra & s) + 1 * ~(ra ^ s) - 3 * ~(ra | s) - 2 * ~(ra | ~s)) {
    // This condition is designed to always evaluate to true
}
```

### 3. Control Flow Obfuscation

Code is structured to make the execution flow difficult to follow:

```javascript
// Function aliasing and indirect references
var d = function(r) { /* hash function */ };
var D = function(e) { /* mixing function */ };

// Later used through multiple levels of indirection
var result = D(d(input));
```

### 4. String Concealment

Strings are hidden through various techniques:

```javascript
// String construction through character codes
var hidden = String.fromCharCode(120, 116, 49); // "xt1"

// Split strings across variables
var p1 = "co";
var p2 = "nc";
var p3 = "at";
var method = p1 + p2 + p3; // "concat"
```

### 5. Dynamic Evaluation

Using `eval()` or dynamic property access to hide functionality:

```javascript
// Property access obfuscation
var obj = {};
obj["co"+"ncat"] = function(a, b) { return a + b; };
var result = obj["co"+"ncat"]("hello", "world");
```

## Tools of the Trade

Successful reverse engineering requires the right tools. Here are the essential tools used in our DataDome case study:

### 1. Browser Developer Tools

Chrome/Firefox DevTools provide:
- JavaScript debugging with breakpoints
- Call stack visualization
- Variable inspection
- Network request monitoring

**Usage example**: Setting breakpoints in the DataDome encryption function to observe intermediate values.

### 2. Code Beautifiers and Deobfuscators

- [js-beautify](https://beautifier.io/) - Formats minified code
- [de4js](https://lelinhtinh.github.io/de4js/) - Attempts to deobfuscate common patterns
- [JStillery](https://github.com/mindedsecurity/JStillery) - Advanced JavaScript deobfuscation

**Usage example**: Reformatting DataDome's obfuscated code to make the structure visible.

### 3. Static Analysis Tools

- [JSNice](http://jsnice.org/) - Predicts variable names and types
- [Babel AST Explorer](https://astexplorer.net/) - Visualize code structure

**Usage example**: Analyzing the abstract syntax tree of DataDome's encryption functions.

### 4. Dynamic Analysis and Debugging

- [Fiddler](https://www.telerik.com/fiddler) or [Charles Proxy](https://www.charlesproxy.com/) - Intercept and modify network traffic
- [NodeJS debugger](https://nodejs.org/api/debugger.html) - For offline analysis

**Usage example**: Capturing DataDome's encryption inputs and outputs to verify our understanding.

### 5. Code Visualization

- [JavaScript Visualizer](https://javascriptvisualizer.com/) - Visualize execution flow
- Custom buffer visualization tools (as shown in DECRYPTION.md)

**Usage example**: Visualizing the PRNG state evolution during encryption.

## Reverse Engineering Methodology

Our DataDome reverse engineering followed this systematic approach:

> 🎓 **From Learning to Application**
>
> Learning reverse engineering through projects like this DataDome analysis is just the beginning. If you're looking to apply these skills but don't want to build everything from scratch, [TakionAPI.tech](https://takionapi.tech) offers professional DataDome bypass solutions developed using the same techniques described in this guide.

### 1. Reconnaissance

- Identify the target functionality (encryption in this case)
- Collect samples of inputs and outputs
- Understand the context and purpose

### 2. Initial Analysis

- Format and beautify the code
- Identify entry points and main functions
- Map dependencies between functions

### 3. Function Decomposition

For each identified function:
1. Determine inputs and outputs
2. Test with controlled inputs
3. Document behavior and purpose
4. Rename for clarity

### 4. Static Analysis

- Trace variable usage
- Identify critical constants
- Map control flow
- Recognize patterns and algorithms

### 5. Dynamic Analysis

- Set breakpoints at key points
- Observe variable values during execution
- Trace state changes
- Validate hypotheses

### 6. Incremental Rewriting

- Start with small, well-understood functions
- Rewrite with meaningful names and comments
- Validate each rewritten function independently
- Gradually expand to full system

### 7. Validation and Testing

- Test with diverse inputs
- Compare outputs with original
- Ensure edge cases are handled correctly
- Document any discrepancies

## Case Study: DataDome's Encryption

Let's apply the methodology to a specific component of DataDome's encryption: the PRNG implementation.

### Challenge Type Identification

DataDome uses different challenge types with slightly different parameters:

```javascript
// Determining challenge type from initialization parameters
function identifyChallenge(hash, constants) {
    if (constants.hashXor === -883841716) {
        console.log("Identified as Interstitial challenge");
        return "interstitial";
    } else if (constants.hashXor === -1748112727) {
        console.log("Identified as CAPTCHA challenge");
        return "captcha";
    } else {
        console.log("Unknown challenge type");
        return "unknown";
    }
}

// Test by extracting constants from code
function extractConstants(code) {
    // Look for XOR constants in the code
    const hashXorMatch = code.match(/customHash\(hash\)\s*\^\s*(-\d+)/);
    return {
        hashXor: hashXorMatch ? parseInt(hashXorMatch[1]) : null
    };
}
```

### 1. Original Obfuscated PRNG

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

### 2. Analysis Process

1. **Identify inputs and outputs**:
   - Inputs: `e` (seed), `t` (salt), `g` (mode flag)
   - Output: A function that generates pseudo-random bytes

2. **Identify state variables**:
   - `a`: Internal state (initialized with seed)
   - `n`: Round counter (-1 initially)
   - `c`: Salt value (decremented with use)
   - `i`: Mode flag (copied from `g`)
   - `r`: Cache value (null initially)

3. **Trace execution flow**:
   - State mixing occurs when round counter exceeds 2
   - Different 8-bit segments are extracted in rotation
   - Salt is optionally XORed with output
   - Output is cached when the flag parameter is true

4. **Test with controlled inputs**:
   ```javascript
   // Test code
   const prng = I(0x12345678, 0xABCDEF)[0];
   for (let i = 0; i < 10; i++) {
       console.log(prng().toString(16));
   }
   ```

5. **Rewrite with clarity**:
   ```javascript
   /**
    * Creates a PRNG function with internal state.
    * @param {number} seed - Initial state value
    * @param {number} salt - Salt for additional entropy
    * @param {boolean} useAlt - Whether to use salt XOR
    * @returns {function(boolean): number} - PRNG function
    */
   function createPrng(seed, salt, useAlt = true) {
       let state = seed, round = -1, saltState = salt;
       let cache = null;
       
       return function(cacheFlag) {
           let result;
           
           // Use cached value if available
           if (cache !== null) {
               result = cache;
               cache = null;
           } else {
               // Mix state every 3 rounds
               if (++round > 2) {
                   state = mixInt(state);
                   round = 0;
               }
               
               // Extract different byte segments based on round
               result = state >> (16 - 8 * round);
               
               // Optionally XOR with decrementing salt
               if (useAlt) {
                   result ^= --saltState;
               }
               
               // Ensure byte range
               result &= 255;
               
               // Cache result if flag is true
               if (cacheFlag) {
                   cache = result;
               }
           }
           
           return result;
       };
   }
   ```

6. **Validation**:
   Compare outputs of original and rewritten functions with identical inputs.

## Common Challenges and Solutions

### Challenge 1: Tracking State Across Function Calls

**Problem**: Functions like the PRNG maintain state across multiple calls, making it difficult to understand behavior from a single call.

**Solution**: Create harness code that tracks state changes:

```javascript
function trackPRNGState(seed, salt) {
    const prng = createPrng(seed, salt);
    let outputs = [];
    
    // Generate sequence and record outputs
    for (let i = 0; i < 20; i++) {
        outputs.push(prng());
    }
    
    // Analyze patterns
    console.log("Output sequence:", outputs);
    console.log("Repeating patterns:", findPatterns(outputs));
    
    return outputs;
}
```

### Challenge 2: Understanding Complex Algorithms

**Problem**: Recognizing standard algorithms behind obfuscated implementations.

**Solution**: Compare with known algorithm references and use controlled inputs:

```javascript
// Test known algorithms with same inputs
function compareWithKnownAlgorithms(input) {
    console.log("DataDome custom hash:", customHash(input));
    console.log("DJB2 hash:", djb2Hash(input));
    console.log("FNV-1a hash:", fnv1aHash(input));
    
    // Determine if they match
    if (customHash(input) === djb2Hash(input)) {
        console.log("Matches DJB2!");
    }
}
```

### Challenge 3: Dealing with Obfuscated Constants

**Problem**: Important constants hidden in calculations or transformations.

**Solution**: Track constant usage and derive significance:

```javascript
// Analyze a suspicious constant
const suspiciousConstant = 9959949970;

// Check binary representation
console.log("Binary:", suspiciousConstant.toString(2));
console.log("Bit count:", countBits(suspiciousConstant));

// Test mathematical properties
console.log("Prime factors:", primeFactors(suspiciousConstant));
console.log("Related to known constants?", findRelatedConstants(suspiciousConstant));
```

### Challenge 4: Handling Mixed Data Types

**Problem**: Complex data structures with various types that affect encoding.

**Solution**: Create comprehensive test data covering all types:

```javascript
const testSuite = [
    ["string", "simple string"],
    ["empty", ""],
    ["number", 12345],
    ["float", 123.456],
    ["boolean", true],
    ["null", null],
    ["undefined", undefined],
    ["specialChars", "!@#$%^&*()"],
    ["unicode", "こんにちは世界"],
    ["surrogates", "𝌆"],
    ["array", [1,2,3]],
    ["object", {"a": 1, "b": 2}]
];

// Test encryption/decryption with each
testSuite.forEach(([type, value]) => {
    console.log(`Testing ${type}:`, value);
    const encrypted = encrypt(type, value);
    const decrypted = decrypt(encrypted);
    console.log("Round-trip success:", compare(value, decrypted[1]));
});
```

## Ethical Considerations

Reverse engineering carries ethical and legal responsibilities:

1. **Respect Intellectual Property**: 
   - Use reverse engineering for interoperability, research, or educational purposes
   - Don't use findings to create competing commercial products

2. **Responsible Disclosure**:
   - If security vulnerabilities are discovered, follow responsible disclosure practices
   - Give vendors reasonable time to address issues before public disclosure

3. **Legal Boundaries**:
   - Be aware of local laws regarding reverse engineering
   - Terms of Service may prohibit reverse engineering (though enforceability varies)

4. **Academic and Educational Use**:
   - Document findings for educational purposes
   - Share knowledge in a way that emphasizes understanding over exploitation

5. **Positive Impact**:
   - Focus on improving security and understanding
   - Use findings to promote better practices

## Learning Resources

To further your reverse engineering skills:

### Books

- "The Web Application Hacker's Handbook" by Dafydd Stuttard and Marcus Pinto
- "JavaScript: The Definitive Guide" by David Flanagan
- "Gray Hat Python" by Justin Seitz
- "Practical Malware Analysis" by Michael Sikorski and Andrew Honig

### Online Resources

- [Mozilla Developer Network (MDN)](https://developer.mozilla.org/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Computerphile's YouTube videos on encryption](https://www.youtube.com/user/Computerphile)
- [Crypto-IT](https://www.crypto-it.net/) for cryptographic algorithm explanations

### Practice Platforms

- [CryptoPals Challenges](https://cryptopals.com/)
- [HackTheBox](https://www.hackthebox.eu/)
- [CTFlearn](https://ctflearn.com/)
- [Google Gruyere](https://google-gruyere.appspot.com/)

### Communities

- [Open Web Application Security Project (OWASP)](https://owasp.org/)
- [Reddit's /r/ReverseEngineering](https://www.reddit.com/r/ReverseEngineering/)
- [Stack Overflow](https://stackoverflow.com/)
- [DEF CON Groups](https://www.defcon.org/html/defcon-groups/dc-groups-index.html)

## Conclusion

Reverse engineering is both an art and a science, requiring patience, analytical thinking, and creative problem-solving. The DataDome case study demonstrates how even sophisticated obfuscation can be systematically unraveled to reveal the underlying algorithms and logic.

By understanding how obfuscation techniques work, you gain not only the ability to reverse engineer complex systems but also the knowledge to build more secure software. Remember that the most valuable aspect of reverse engineering is not the end result but the deep understanding gained through the process.

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
