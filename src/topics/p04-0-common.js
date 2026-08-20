// Part 4, DES and the Feistel network: the families. The drawing helpers are S.SymT (topics/p03-0-common.js);
// pictures of DES's 64-bit blocks and tables live with the topics that draw them.
(function (S) {
  'use strict';
  S.family({ id: 'p04-feistel', part: 'des', order: 10, title: 'The Feistel network', blurb: 'Any round function makes an invertible cipher: decryption is the same ladder with the keys in reverse.' });
  S.family({ id: 'p04-des', part: 'des', order: 20, title: 'DES end to end', blurb: 'The initial permutation, sixteen rounds, the f-function with its eight S-boxes, the key schedule, decryption and the avalanche.' });
  S.family({ id: 'p04-weak', part: 'des', order: 30, title: 'Weaknesses and fixes', blurb: 'Weak keys and the complement, the price of exhaustive search, double DES met in the middle, 3DES and DESX.' });
  S.family({ id: 'p04-spn', part: 'des', order: 40, title: 'Breaking a toy SPN, and PRESENT', blurb: 'Difference and linear tables of an S-box, characteristics through the rounds, the last round key recovered by counting, and a real lightweight SPN.' });
})(globalThis.Sifer = globalThis.Sifer || {});
