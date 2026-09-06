// Part 11, digital signatures: every topic run with its presets and random inputs; every value a frame's narration
// quotes is one of the frame's facts, and the facts are worked out again independently: node:crypto signs and verifies
// Ed25519, ECDSA (P-256 and secp256k1), RSA-PSS and DSA, and computes HMAC and raw RSA; the presets are checked against
// the published vectors of RFC 6979 and RFC 8032.
// Prints "claims-p11 N passed, M failed". Usage: node tests/claims-p11.mjs [topic id prefix ...]
import { runClaims } from './claims-lib-pk.mjs';
import { mods as a } from './claims-p11-a.mjs';
import { mods as b } from './claims-p11-b.mjs';
runClaims('claims-p11', 'p11', a.concat(b), process.argv.slice(2));
