// Part 6, modes of operation and block-cipher use: the families. The drawing helpers are those of part 5
// (S.P5, src/topics/p05-0-common.js), with the data-flow kit S.Kit.flow for the modes drawn as wires.
(function (S) {
  'use strict';
  S.family({ id: 'p06-modes', part: 'modes', order: 10, title: 'The modes as data flow', blurb: 'ECB, CBC, CFB, OFB, CTR and XTS drawn as wires between block-cipher boxes, with the value on every wire.' });
  S.family({ id: 'p06-gcm', part: 'modes', order: 20, title: 'Authenticated encryption: GCM', blurb: 'CTR for secrecy, and GHASH over GF(2¹²⁸) for a tag that catches any change.' });
  S.family({ id: 'p06-use', part: 'modes', order: 30, title: 'Padding, key length and block size', blurb: 'PKCS#7, ISO 7816-4 and ciphertext stealing; exhaustive key search over the years; and the birthday bound that block size sets.' });
  S.family({ id: 'p06-labs', part: 'modes', order: 40, title: 'Integrity and correct use', blurb: 'Why encryption alone is not integrity, why a nonce must never repeat, and why the tag is checked before anything is decrypted.' });
})(globalThis.Sifer = globalThis.Sifer || {});
