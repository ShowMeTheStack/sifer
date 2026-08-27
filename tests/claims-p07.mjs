// Part 7, introduction to public-key cryptography: every topic run with its presets and random inputs; every value
// a frame's narration quotes is one of the frame's facts, and the facts are worked out again here independently.
// Prints "claims-p07 N passed, M failed". Usage: node tests/claims-p07.mjs [topic id prefix ...]
import { runClaims } from './claims-lib-pk.mjs';
import { mods as more } from './claims-p07-b.mjs';

const why = [
  {
    topic: 'p07-keydist', allow: [],
    random: (rnd) => ({ n: 2 + Math.floor(rnd() * 11), big: 13 + Math.floor(rnd() * 1e7) }),
    check({ input, r, fail }) {
      const n = input.n, N = BigInt(input.big);
      let seen = 0;
      for (const f of r.frames) {
        const x = f.facts;
        if (f.meta.phase === 'join') { seen++; if (x.added !== x.k - 1 || x.total !== x.k * (x.k - 1) / 2) fail('the keys when ' + x.k + ' have joined'); if (f.counters.keys !== x.total) fail('the counter of keys'); }
        if (f.meta.phase === 'all' && (x.all !== n * (n - 1) / 2 || x.keep !== n - 1)) fail('the total for n = ' + n);
        if (f.meta.phase === 'scale' && x.pairsN !== N * (N - 1n) / 2n) fail('the pairwise keys for ' + N);
      }
      if (seen !== n - 1) fail('one frame for each person who joins');
    },
  },
];

const only = process.argv.slice(2);
runClaims('claims-p07', 'p07', why.concat(more), only);
