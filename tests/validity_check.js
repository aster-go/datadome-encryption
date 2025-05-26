const { DataDomeDecryptor, DataDomeEncryptor } = require('../src');
const fs = require('fs');

console.log('==============================');
console.log(' DataDome Encryption Test Suite');
console.log('==============================\n');

const cid = "k6~sz7a9PBeHLjcxOOWjR162xQq2Uxsx6wLzxeGlO7~6k3JVwDkwAaQ04wdFEMm2Jt2s0y61mLfJdhWuqtqeJzFMuo7Lf8P5btYX0K4EeoLRcNAtNW04rGhTE3nKpMxi"
const hash_str = "14D062F60A4BDE8CE8647DFC720349"
const expected = fs.readFileSync(__dirname + '/excepted.txt', 'utf8');
const original_signals = JSON.parse(fs.readFileSync(__dirname + '/original.json', 'utf8'));

console.log('[1] Encrypting signals...');
const encryptor = new DataDomeEncryptor(
  hash_str,
  cid,
  salt=null, // generate it
  challengeType='captcha'
);

for (let i = 0; i < original_signals.length; i++) {
  let key = original_signals[i][0];
  let value = original_signals[i][1];
  encryptor.add(key, value);
}
let newEncrypted = encryptor.encrypt();
console.log('   > Encrypted string:', newEncrypted);

// We ignore the last char on compilation due to the 
// fact that is salt based, so unless you pass
// the same salt it will be a different char based
// on the timestamp
let decryptedData_wo_last_char = newEncrypted.slice(0, -1);
let expected_wo_last_char = expected.slice(0, -1);

if (decryptedData_wo_last_char === expected_wo_last_char) {
  console.log('[PASS] Encryption matches expected (ignoring last char).');
} else {
  console.log('[FAIL] Encryption does NOT match expected (ignoring last char).');
  console.log('   > Expected:', expected_wo_last_char);
  console.log('   > Got     :', decryptedData_wo_last_char);
}

console.log('\n[2] Decrypting and comparing data...');
const decryptor = new DataDomeDecryptor(
  hash_str,
  cid,
  salt=null, // generate it
  challengeType='captcha'
);

let originalData = decryptor.decrypt(expected);
let rebuiltData = decryptor.decrypt(newEncrypted);

let mismatch = false;
for (let i = 0; i < rebuiltData.length; i++) {
    const [rebuildKey, rebuildValue] = rebuiltData[i];
    const [originalKey, originalValue] = originalData[i];

    if (rebuildKey !== originalKey || rebuildValue !== originalValue) {
        mismatch = true;
        console.log(`\n[MISMATCH] Entry #${i}`);
        console.log(`   (ORIGINAL) Key:   ${originalKey}`);
        console.log(`   (ORIGINAL) Value: ${originalValue}`);
        console.log(`   (REBUILD ) Key:   ${rebuildKey}`);
        console.log(`   (REBUILD ) Value: ${rebuildValue}`);
        console.log("********************");
    }
}

if (!mismatch) {
  console.log('[PASS] Decryption: All entries match!');
} else {
  console.log('[FAIL] Decryption: There were mismatches in the decrypted data.');
}

console.log('\n==============================');
console.log(' Test Suite Complete');
console.log('==============================');