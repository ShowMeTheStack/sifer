// Part 9, the discrete logarithm: every topic run with its presets and random inputs; every value a frame's narration
// quotes is one of the frame's facts, and the facts are worked out again independently.
// Prints "claims-p09 N passed, M failed". Usage: node tests/claims-p09.mjs [topic id prefix ...]
import { runClaims } from './claims-lib-pk.mjs';
import { mods as a } from './claims-p09-a.mjs';
import { mods as b } from './claims-p09-b.mjs';
runClaims('claims-p09', 'p09', a.concat(b), process.argv.slice(2));
