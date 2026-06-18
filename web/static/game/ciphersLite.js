// ciphersLite.js — Minimal JS ports of Python cipher encrypt() methods
// Source: cryptovault/ciphers/caesar.py, atbash.py, vigenere.py

export const CiphersLite = {

  // Caesar: C = (P + shift) mod 26, non-alpha pass-through, case preserved
  // Source: caesar.py → CaesarCipher.encrypt()
  caesar(word, shift) {
    return word.replace(/[a-zA-Z]/g, ch => {
      const base = ch <= 'Z' ? 65 : 97;
      return String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
    });
  },

  // Atbash: C = 25 - P (alphabet reversal), no key, involution
  // Source: atbash.py → AtbashCipher.encrypt()
  atbash(word) {
    return word.replace(/[a-zA-Z]/g, ch => {
      const base = ch <= 'Z' ? 65 : 97;
      return String.fromCharCode(25 - (ch.charCodeAt(0) - base) + base);
    });
  },

  // Vigenere: C[i] = (P[i] + K[i mod m]) mod 26, non-alpha preserved, no key consumed
  // Source: vigenere.py → VigenereCipher.encrypt()
  vigenere(word, key) {
    const K = key.replace(/[^a-zA-Z]/g, '').toUpperCase();
    if (!K) throw new Error('Vigenere key must contain at least one letter');
    let ki = 0;
    return word.replace(/[a-zA-Z]/g, ch => {
      const base = ch <= 'Z' ? 65 : 97;
      const kVal = K.charCodeAt(ki % K.length) - 65;
      ki++;
      return String.fromCharCode(((ch.charCodeAt(0) - base + kVal) % 26) + base);
    });
  }
};

// Validation tests — run on load, log PASS/FAIL to console
(function validate() {
  const tests = [
    ['caesar("HELLO", 3)',     () => CiphersLite.caesar('HELLO', 3),     'KHOOR'],
    ['caesar("hello", 3)',     () => CiphersLite.caesar('hello', 3),     'khoor'],
    ['caesar("Hello, World!", 3)', () => CiphersLite.caesar('Hello, World!', 3), 'Khoor, Zruog!'],
    ['atbash("HELLO")',        () => CiphersLite.atbash('HELLO'),        'SVOOL'],
    ['atbash("hello")',        () => CiphersLite.atbash('hello'),        'svool'],
    ['atbash("SVOOL")',        () => CiphersLite.atbash('SVOOL'),        'HELLO'],
    ['vigenere("HELLO", "KEY")', () => CiphersLite.vigenere('HELLO', 'KEY'), 'RIJVS'],
    ['vigenere("HELLO WORLD", "KEY")', () => CiphersLite.vigenere('HELLO WORLD', 'KEY'), 'RIJVS UYVJN'],
  ];
  let pass = 0, fail = 0;
  for (const [label, fn, expected] of tests) {
    const got = fn();
    if (got === expected) {
      pass++;
    } else {
      fail++;
      console.error(`FAIL: ${label} → got "${got}", expected "${expected}"`);
    }
  }
  console.log(`[ciphersLite] ${pass}/${pass + fail} tests passed`);
})();
