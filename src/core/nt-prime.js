// Primes: trial division by a table of small primes, Fermat's test (and the Carmichael numbers that fool it for every
// coprime base), Miller–Rabin traced witness by witness, random primes of any size, safe primes p = 2q + 1, and the
// chunked form of each search so a page or a Web Worker can run it a few milliseconds at a time.
//   S.NT.SMALL_PRIMES                                     the primes below 2000
//   S.NT.fermatTest(n, a) -> {passes, value, trace}       a^(n−1) mod n
//   S.NT.millerRabin(n, bases|rounds) -> {probablePrime, witness, rounds: [{a, x: [...], verdict}], s, d, trace}
//   S.NT.isProbablePrime(n[, rounds])                    deterministic below 3.3·10^24, random bases above
//   S.NT.fermatLiars(n) / strongLiars(n)                  the bases that a test wrongly passes, for a small odd composite
//   S.NT.carmichael(limit) -> [n…]                        by Korselt's criterion
//   S.NT.primeSteps(bits[, opts])                         generator: yields {tried, candidate, outcome} per candidate,
//                                                         and finally returns {prime, tried, log, trace}
//   S.NT.safePrimeSteps(bits[, opts])                     the same for p = 2q + 1 with q prime
//   S.NT.randomPrime(bits[, opts]) / randomSafePrime(bits[, opts])   the searches run to the end
//   S.NT.runChunked(gen, {budget, onProgress}) -> Promise of the generator's result (a few ms per slice)
//   S.NT.nextPrime(n)
(function (S) {
  'use strict';
  const N = (S.NT = S.NT || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const B = (v) => (typeof v === 'bigint' ? v : BigInt(v));
  const sh = (v) => N.short(v);

  const SMALL = [];
  { const lim = 2000, sieve = new Uint8Array(lim); for (let i = 2; i < lim; i++) if (!sieve[i]) { SMALL.push(i); for (let j = i * i; j < lim; j += i) sieve[j] = 1; } }
  N.SMALL_PRIMES = SMALL;
  const SMALL_B = SMALL.map(BigInt);
  /** the first small prime that divides n (other than n itself), or 0 */
  N.smallFactor = (n, upto = 2000) => { n = B(n); for (let i = 0; i < SMALL_B.length && SMALL[i] < upto; i++) { const p = SMALL_B[i]; if (p >= n) return 0; if (n % p === 0n) return SMALL[i]; } return 0; };

  N.fermatTest = (n, a) => {
    n = B(n); a = B(a);
    const value = N.pow(a, n - 1n, n), passes = value === 1n;
    const trace = [step('fermat', `${sh(a)}^(${sh(n - 1n)}) mod ${sh(n)} = ${sh(value)}: ${passes ? `${sh(n)} passes for base ${sh(a)} (it may be prime)` : `${sh(a)} is a Fermat witness, so ${sh(n)} is composite`}.`, { n, a, value, passes })];
    return { passes, value, trace };
  };

  /** Miller–Rabin: write n − 1 = 2^s·d with d odd; a base a passes if a^d ≡ 1 or one of its next s − 1 squares is −1 */
  N.millerRabin = (n, bases = 8) => {
    n = B(n);
    const trace = [];
    if (n < 2n) return { probablePrime: false, witness: null, rounds: [], trace: [step('small', `${sh(n)} is below 2, not prime.`)] };
    if (n < 4n) return { probablePrime: true, witness: null, rounds: [], trace: [step('small', `${sh(n)} is prime.`)] };
    if (!(n & 1n)) return { probablePrime: false, witness: 2n, rounds: [], trace: [step('even', `${sh(n)} is even, so it is composite.`)] };
    let d = n - 1n, s = 0;
    while (!(d & 1n)) { d >>= 1n; s++; }
    trace.push(step('split', `n − 1 = ${sh(n - 1n)} = 2^${s}·${sh(d)}.`, { s, d }));
    const list = Array.isArray(bases) ? bases.map(B) : Array.from({ length: bases }, () => 2n + N.randBelow(n - 3n));
    const rounds = [];
    for (const a0 of list) {
      const a = N.mod(a0, n);
      if (a < 2n || a > n - 2n) { rounds.push({ a, x: [], verdict: 'skip' }); continue; }
      let x = N.pow(a, d, n);
      const xs = [x];
      let verdict = x === 1n || x === n - 1n ? 'pass' : null;
      for (let r = 1; r < s && !verdict; r++) {
        x = (x * x) % n; xs.push(x);
        if (x === n - 1n) verdict = 'pass';
        else if (x === 1n) verdict = 'fail';
      }
      if (!verdict) verdict = 'fail';
      rounds.push({ a, x: xs, verdict });
      const seq = xs.map(sh).join(' → ');
      trace.push(step('round', verdict === 'pass'
        ? `Base ${sh(a)}: ${seq}${xs[xs.length - 1] === 1n && xs.length === 1 ? ' (a^d ≡ 1)' : ' reaches −1'}, so ${sh(a)} is not a witness.`
        : xs.length > 1 && xs[xs.length - 1] === 1n
          ? `Base ${sh(a)}: ${seq}. ${sh(xs[xs.length - 2])}² ≡ 1 although ${sh(xs[xs.length - 2])} ≢ ±1, a square root of 1 that no prime allows, so ${sh(a)} is a witness: ${sh(n)} is composite.`
          : `Base ${sh(a)}: ${seq} never reaches −1 in ${s} step${s === 1 ? '' : 's'}, so ${sh(a)} is a witness: ${sh(n)} is composite.`, { a, x: xs, verdict }));
      if (verdict === 'fail') {
        trace.push(step('done', `${sh(n)} is composite.`, { probablePrime: false }));
        return { probablePrime: false, witness: a, rounds, s, d, trace };
      }
    }
    const k = rounds.filter((r) => r.verdict === 'pass').length;
    trace.push(step('done', `${sh(n)} passed ${k} round${k === 1 ? '' : 's'}: it is prime${k ? `, or composite with probability below 4^−${k}` : ''}.`, { probablePrime: true }));
    return { probablePrime: true, witness: null, rounds, s, d, trace };
  };
  const DET = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n];
  const LIMIT_DET = 3317044064679887385961981n;
  N.isProbablePrime = (n, rounds) => {
    n = B(n);
    if (n < 2n) return false;
    for (const p of SMALL_B) { if (n === p) return true; if (n % p === 0n) return false; }
    if (n < 2000n * 2000n) return true;
    if (n < LIMIT_DET) return N.millerRabin(n, DET).probablePrime;
    const bits = N.bitLength(n);
    return N.millerRabin(n, rounds || (bits >= 1024 ? 8 : bits >= 512 ? 12 : 20)).probablePrime;
  };
  N.fermatLiars = (n) => { n = B(n); const out = []; for (let a = 1n; a < n; a++) if (N.gcd(a, n) === 1n && N.pow(a, n - 1n, n) === 1n) out.push(a); return out; };
  N.strongLiars = (n) => { n = B(n); const out = []; for (let a = 1n; a < n; a++) { if (a === 1n || a === n - 1n) { out.push(a); continue; } if (N.millerRabin(n, [a]).probablePrime) out.push(a); } return out; };
  /** the Carmichael numbers up to limit: squarefree composites n with (p − 1) | (n − 1) for every prime p | n */
  N.carmichael = (limit) => {
    limit = Number(limit);
    const spf = new Uint32Array(limit + 1), out = [];
    for (let i = 2; i <= limit; i++) if (!spf[i]) for (let j = i; j <= limit; j += i) if (!spf[j]) spf[j] = i;
    for (let n = 3; n <= limit; n += 2) {
      if (spf[n] === n) continue;
      let m = n, ok = true, count = 0;
      while (m > 1 && ok) { const p = spf[m]; m /= p; count++; if (m % p === 0 || (n - 1) % (p - 1)) ok = false; }
      if (ok && count >= 2) out.push(BigInt(n));
    }
    return out;
  };
  N.nextPrime = (n) => { n = B(n) + 1n; if (n <= 2n) return 2n; if (!(n & 1n)) n++; while (!N.isProbablePrime(n)) n += 2n; return n; };

  /** a random candidate of exactly `bits` bits: the top two bits set (so two of them multiply to 2·bits bits) and odd */
  const candidate = (bits, top2) => {
    let v = N.randomBits(bits);
    v |= 1n << BigInt(bits - 1);
    if (top2 && bits > 2) v |= 1n << BigInt(bits - 2);
    return v | 1n;
  };
  const keepLog = 24;
  /** the search for a random prime, one candidate per yield */
  N.primeSteps = function* (bits, opts = {}) {
    bits = Number(bits);
    if (bits < 2) throw new Error('a prime needs at least 2 bits');
    const log = [], trace = [];
    const top2 = opts.top2 !== false;
    trace.push(step('start', `Look for a random ${bits}-bit prime: draw odd ${bits}-bit numbers${top2 ? ' with the top two bits set' : ''} and test each.`, { bits }));
    for (let tried = 1; ; tried++) {
      if (bits <= 3) { const ps = [2n, 3n, 5n, 7n].filter((p) => N.bitLength(p) === bits); const p = ps[Number(N.randBelow(BigInt(ps.length)))]; trace.push(step('found', `${p} is prime.`, { prime: p })); return { prime: p, tried, log, trace }; }
      const c = opts.filter ? opts.filter(candidate(bits, top2)) : candidate(bits, top2);
      let outcome;
      const f = N.smallFactor(c);
      if (f) outcome = { kind: 'small', by: f };
      else {
        const mr = N.millerRabin(c, c < LIMIT_DET ? DET : (opts.rounds || (bits >= 1024 ? 8 : bits >= 512 ? 12 : 20)));
        outcome = mr.probablePrime ? { kind: 'prime', rounds: mr.rounds.length } : { kind: 'witness', by: mr.witness };
        if (opts.traceRounds && (mr.probablePrime || log.length < keepLog)) trace.push(...mr.trace);
      }
      const rec = { tried, candidate: c, outcome };
      if (log.length < keepLog || outcome.kind === 'prime') log.push(rec);
      trace.push(step('candidate', outcome.kind === 'small' ? `Candidate ${tried}: ${sh(c)} is divisible by ${outcome.by}.`
        : outcome.kind === 'witness' ? `Candidate ${tried}: ${sh(c)} has the Miller–Rabin witness ${sh(outcome.by)}, so it is composite.`
          : `Candidate ${tried}: ${sh(c)} survives ${outcome.rounds} Miller–Rabin rounds: a prime.`, rec));
      if (outcome.kind === 'prime') {
        trace.push(step('found', `Found a ${bits}-bit prime after ${tried} candidate${tried === 1 ? '' : 's'} (about ln 2^${bits} / 2 ≈ ${Math.round(bits * Math.LN2 / 2)} are expected).`, { prime: c, tried }));
        return { prime: c, tried, log, trace: trace.length > 200 ? trace.slice(0, 60).concat(trace.slice(-40)) : trace };
      }
      yield rec;
    }
  };
  /** the search for a safe prime p = 2q + 1: q and p are sieved together, then q and p are tested */
  N.safePrimeSteps = function* (bits, opts = {}) {
    bits = Number(bits);
    if (bits < 3) throw new Error('a safe prime needs at least 3 bits');
    const log = [], trace = [step('start', `Look for a ${bits}-bit safe prime p = 2q + 1 with q prime.`, { bits })];
    for (let tried = 1; ; tried++) {
      let q = candidate(bits - 1, false);
      if (bits === 3) q = 3n;
      const p = 2n * q + 1n;
      let outcome;
      const fq = N.smallFactor(q), fp = N.smallFactor(p);
      if (fq || fp) outcome = { kind: 'small', by: fq || fp, which: fq ? 'q' : 'p' };
      else if (!N.isProbablePrime(q, opts.rounds)) outcome = { kind: 'q' };
      else if (!N.isProbablePrime(p, opts.rounds)) outcome = { kind: 'p' };
      else outcome = { kind: 'prime' };
      const rec = { tried, q, p, outcome };
      if (log.length < keepLog || outcome.kind === 'prime') log.push(rec);
      if (outcome.kind === 'prime') {
        trace.push(step('found', `q = ${sh(q)} and p = 2q + 1 = ${sh(p)} are both prime (after ${tried} candidates).`, { p, q, tried }));
        return { prime: p, q, tried, log, trace };
      }
      if (log.length <= keepLog) trace.push(step('candidate', outcome.kind === 'small' ? `Candidate ${tried}: ${outcome.which} is divisible by ${outcome.by}.` : `Candidate ${tried}: ${outcome.kind} = ${sh(outcome.kind === 'q' ? q : p)} is composite.`, rec));
      yield rec;
    }
  };
  const drain = (gen) => { for (;;) { const r = gen.next(); if (r.done) return r.value; } };
  N.randomPrime = (bits, opts) => drain(N.primeSteps(bits, opts));
  N.randomSafePrime = (bits, opts) => drain(N.safePrimeSteps(bits, opts));
  N.drain = drain;
  /** run a step generator a few milliseconds at a time, yielding to the page between slices */
  N.runChunked = (gen, opts = {}) => new Promise((resolve, reject) => {
    const budget = opts.budget || 12, now = () => (globalThis.performance ? performance.now() : Date.now());
    const slice = () => {
      try {
        const t0 = now();
        let r;
        do { r = gen.next(); if (r.done) { resolve(r.value); return; } } while (now() - t0 < budget);
        if (opts.onProgress) opts.onProgress(r.value);
        if (opts.signal && opts.signal.aborted) { reject(new Error('stopped')); return; }
        setTimeout(slice, 0);
      } catch (e) { reject(e); }
    };
    slice();
  });
})(globalThis.Sifer = globalThis.Sifer || {});
