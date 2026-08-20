// Part 4, DES and the Feistel network: every topic run with its presets and random inputs; every value a frame's narration quotes
// is one of the frame's facts, and the facts are worked out again here without the topic's code path (a plain
// recurrence, brute force, node:crypto where it has the algorithm). Prints "claims-p04 N passed, M failed".
// Usage: node tests/claims-p04.mjs [topic id prefix ...]
import { runClaims } from './claims-lib-p03.mjs';
import { mods as a } from './claims-p04-a.mjs';
import { mods as b } from './claims-p04-b.mjs';

runClaims('claims-p04', 'p04-', [...a, ...b], process.argv.slice(2));
