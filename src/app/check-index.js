// EXERCISE KINDS: the reference for content writers. An exercise is
//   S.Content.exercise({ id, chapter, title, level: 1..3, kind, text: ['paragraph' | lesson block, ...],
//     hints: [hint 1, hint 2, 'the worked answer'], solution: <an answer that passes>,
//     wrong: [<answers that fail>, ...], why: 'said after a right answer', whyNot: 'said after a wrong one',
//     ...the fields of its kind })
// tools/check-content.mjs runs the solution and every wrong answer through the checker: the solution must pass and
// every wrong answer must fail. Write a wrong answer for each mistake you expect, and read its message: it is what
// the student sees (node tools/check-content.mjs --verbose).
//
// Every checker returns { ok, message, details? }; message is one plain sentence with the actual values.
//
//   choice      options: ['..'], answer: index | [indexes]; whyNot: {index: 'why'}.              Answer: index(es)
//   string      answer: 'text' | [...] or accept(text); set, caseless, spaces.                    Answer: text
//   number      answer (a Number; a BigInt or a string of digits for big integers, compared exactly), tolerance,
//               higherLower (say whether the answer is more or less); whyNot: 'sentence' or
//               {value: 'why that slip', '*': 'any other value'}; − or - for a minus.           Answer: number
//   set         answer: '{2, 3, 5}' | '(1, 2), (2, 3)' | '{{a, b}, {c}}'; or accept(value, canonical).  Answer: text
//   hex         answer: 'hex' | ['hex', ...] (spaces, colons, 0x and case ignored); value: true lets leading zeros
//               go (a number in hex rather than bytes); accept(hex) -> true | false | 'why'.     Answer: hex text
//               The message counts the bytes that differ without showing them. bytes is the same kind.
//   table       rows: ['r0', ..], cols: ['c0', ..], cells: {'row|col': expected}, cellKind: 'text' | 'hex' | 'bit' |
//               'set', corner; or table: 'state' with state: '32 hex digits in column order' (a 4×4 byte state;
//               nibbles: true for Mini-AES, 16 hex digits), give: [byte indexes shown filled in].
//               Fill in a state or a round.                                                  Answer: {'row|col': text}
//   code        fn: 'squareMultiply', params: ['x', 'e', 'n'] (named in the message when the function is missing),
//               start: 'function squareMultiply(x, e, n) {\n  \n}' (the editor's first text), tests: [{args: [..],
//               want}] or ref: (...args) => want with cases: [[args], ...], timeLimit (ms, default 2000). Values may
//               be BigInt, Uint8Array and arrays. The code runs in a sandboxed worker (no page, no network), case by
//               case; the first failing case is the message, with its arguments, what came back and what should.
//               radix: 16 (and width: digits, default 2) writes numbers in that message in hex, as bytes and words;
//               decimalArgs: [argument indexes] that stay in decimal (a degree, a count).
//               prelude: 'helper source' is given code: shown read-only above the editor and run before the
//               student's code (so start and solution hold only the student's part).
//                                                                                       Answer: JavaScript source
//   flag        format: 'sifer{...}', flag: 'sifer{…}' | flagHash: SHA-256 of the flag in hex (S.Check.flagHash),
//               or accept(flag). A string in the wrong shape is told the format first.         Answer: the flag
//   break       target: 'key' | 'plaintext' | 'shift' | 'factor' | … (named in the messages); answer: one or several
//               (BigInt allowed); normalize: 'letters' (A–Z only) | 'text' | 'caseless' | 'hex' | 'int'; or
//               verify(value, raw) -> true | false | 'why not' (try the key: decrypt and compare, so every
//               equivalent key passes). A plaintext with most letters right is told how many.  Answer: what was recovered
//
// Hints: three, the last a worked answer. Lesson blocks: src/app/lessons.js. CTF challenges: src/app/ctf.js.
(function (S) {
  'use strict';
  const K = (S.Check = S.Check || {});
  /** the kinds this file documents, for tools that list them */
  K.kindNames = ['choice', 'string', 'number', 'set', 'hex', 'bytes', 'table', 'code', 'flag', 'break'];
})(globalThis.Sifer = globalThis.Sifer || {});
