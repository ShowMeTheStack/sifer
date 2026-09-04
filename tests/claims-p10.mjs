// Part 10, elliptic curves: every topic run with its presets and random inputs; every value a frame's narration
// quotes is one of the frame's facts, and the facts are worked out again here with arithmetic of our own (closed
// forms, brute force over small fields, node:crypto where it has the curve). Prints "claims-p10 N passed, M failed".
// Usage: node tests/claims-p10.mjs [topic id prefix ...]
import { runClaims } from './claims-p10-lib.mjs';
import { mods as m1 } from './claims-p10-a.mjs';
import { mods as m2 } from './claims-p10-b.mjs';
import { mods as m3 } from './claims-p10-c.mjs';

runClaims('claims-p10', 'p10-', [...m1, ...m2, ...m3], process.argv.slice(2));
