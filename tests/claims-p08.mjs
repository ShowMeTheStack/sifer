// Part 8, RSA: every topic run with its presets and random inputs; every value a frame's narration quotes is one of
// the frame's facts, and the facts are worked out again independently (node:crypto, a second method, brute force).
// Prints "claims-p08 N passed, M failed". Usage: node tests/claims-p08.mjs [topic id prefix ...]
import { runClaims } from './claims-lib-pk.mjs';
import { mods as a } from './claims-p08-a.mjs';
import { mods as b1 } from './claims-p08-b1.mjs';
import { mods as b2 } from './claims-p08-b2.mjs';
runClaims('claims-p08', 'p08', a.concat(b1, b2), process.argv.slice(2));

// the real-size numbers of p07-0-data.js: primes (by node:crypto), the congruences that let e = 3, 17 and 65537 work,
// the DSA group (q | p − 1, g of order q) and the MODP group's safe prime
import { S } from './claims-lib-pk.mjs';
import { harness } from './load.mjs';
import { checkPrimeSync, getDiffieHellman } from 'node:crypto';
import { pw } from './claims-lib-pk.mjs';
{
  const t = harness('p07-data');
  const D = S.PK.DATA, H = (h) => BigInt('0x' + h);
  for (const k of ['p512', 'p1024', 'p1536', 'p2048']) for (const h of D[k]) {
    const p = H(h), bits = +k.slice(1);
    t.ok(checkPrimeSync(p, { checks: 32 }), k + ' prime ' + h.slice(0, 12));
    t.ok(p.toString(2).length === bits && (p >> BigInt(bits - 2)) === 3n, k + ' size and top bits ' + h.slice(0, 12));
    t.ok(p % 3n === 2n && p % 17n !== 1n && p % 65537n !== 1n, k + ' congruences ' + h.slice(0, 12));
  }
  const p = H(D.dsa.p), q = H(D.dsa.q), g = H(D.dsa.g);
  t.ok(checkPrimeSync(p) && checkPrimeSync(q) && (p - 1n) % q === 0n && g > 1n && pw(g, q, p) === 1n && p.toString(2).length === 2048 && q.toString(2).length === 224, 'the DSA group');
  t.ok(D.modp14 === getDiffieHellman('modp14').getPrime('hex'), 'the MODP group of RFC 3526');
  t.done();
}
