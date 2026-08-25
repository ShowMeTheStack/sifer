// Part 6's topics, run with every preset and random inputs: every value a frame's narration quotes is one of the
// frame's facts, and the facts are worked out again here without the topics' code path (an AES written apart from
// the engines in tests/claims-ref-aes.mjs, and node:crypto). Prints "claims-p06 N passed, M failed".
// Usage: node tests/claims-p06.mjs [topic id prefix ...]
import { runClaims } from './claims-lib-p05.mjs';
import { mods as a } from './claims-p06-a.mjs';
import { mods as b } from './claims-p06-b.mjs';

runClaims('claims-p06', ['p06-'], [...a, ...b], process.argv.slice(2));
