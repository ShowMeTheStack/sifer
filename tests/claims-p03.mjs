// Part 3, stream ciphers: every topic run with its presets and random inputs; every value a frame's narration quotes
// is one of the frame's facts, and the facts are worked out again here without the topic's code path (a plain
// recurrence, brute force, node:crypto where it has the algorithm). Prints "claims-p03 N passed, M failed".
// Usage: node tests/claims-p03.mjs [topic id prefix ...]
import { runClaims } from './claims-lib-p03.mjs';
import { mods as a } from './claims-p03-a.mjs';
import { mods as b } from './claims-p03-b.mjs';

runClaims('claims-p03', 'p03-', [...a, ...b], process.argv.slice(2));
