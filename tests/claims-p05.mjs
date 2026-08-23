// Part 5's topics, run with every preset and random inputs: every value a frame's narration quotes is one of the
// frame's facts, and the facts are worked out again here without the topics' code path (an AES written apart from
// the engines in tests/claims-ref-aes.mjs, and node:crypto). Prints "claims-p05 N passed, M failed".
// Usage: node tests/claims-p05.mjs [topic id prefix ...]
import { runClaims } from './claims-lib-p05.mjs';
import { mods as a } from './claims-p05-a.mjs';
import { mods as b } from './claims-p05-b.mjs';

runClaims('claims-p05', ['p05-'], [...a, ...b], process.argv.slice(2));
