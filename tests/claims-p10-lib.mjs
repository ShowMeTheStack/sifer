// The machinery of tests/claims-p10.mjs: runs every topic of part 10 with its presets and random
// inputs, and for every frame checks
//  - the wording of the narration, the predictions and the quiz (a/an, doubled words, double spaces, a space before
//    punctuation, a missing value);
//  - that every number the narration quotes is one of the frame's facts (the values the topic took from the engines),
//    decimal numbers whole and hex digits as pieces of a fact's hex, so nothing is typed in by hand;
//  - and then the topic's own check, which works the facts out again without the engines: a small elliptic-curve
//    arithmetic written here, brute force, and node:crypto where it has the algorithm.
import { load, harness, rng } from './load.mjs';
import crypto from 'node:crypto';

export const S = load(['core', 'stage', 'topics']);
export { crypto };

const VOWEL = /^(a|e|i|o|u|honest|hour|8|11|18|80|8\d\d?|RSA|SHA|AES|ECC|ECDSA|ECDH|EdDSA|Ed25519|ML|LWE|HMAC|MAC|MGF|OAEP|X\b|F\b|H\b|L\b|M\b|N\b|S\b|R\b|RFC|NIST|SP|n-bit|x-coordinate|x-only|l\b|n\b|m\b|f\b|s\b|x\b|r\b|h\b)/;
const CONS = /^(u[ns]i|use|usu|one|once|eu|uni)/i;
export function wording(say) {
  const s = (say || '').replace(/"[^"]*"/g, '"…"').replace(/“[^”]*”/g, '“…”').replace(/([\w)₀-₉]) : (?=[\w(])/g, '$1:'), out = [];
  if (/\S {2,}\S/.test(s)) out.push('a double space');
  if (/\s[,.;:](\s|$)/.test(s)) out.push('a space before punctuation');
  if (/\.\./.test(s.replace(/…/g, ''))) out.push('two full stops');
  for (const m of s.matchAll(/\b([A-Za-z]{2,}) \1\b/g)) if (!/^(that|had)$/i.test(m[1])) out.push('the word "' + m[1] + '" twice');
  for (const m of s.matchAll(/(^|[^\w'’])(a|an|A|An) ([\w'′-]+)/g)) {
    const art = m[2].toLowerCase(), w = m[3];
    if (/^(and|is|or|b|mod|to|in|has|was|with)$/.test(w)) continue;
    let vowel = (VOWEL.test(w) || /^[aeiou]/i.test(w)) && !CONS.test(w);
    if (/^\d/.test(w)) { const d = w.replace(/\D.*$/, ''); vowel = d[0] === '8' || (/^1[18]/.test(d) && (d.length - 2) % 3 === 0); }
    if (art === 'a' && vowel) out.push('"a ' + w + '"');
    if (art === 'an' && !vowel) out.push('"an ' + w + '"');
  }
  if (/\bthe the\b|\ba a\b|\bof of\b|\bto to\b|\bis is\b/i.test(s)) out.push('a doubled small word');
  if (/(undefined|NaN|\bnull\b|\[object|Infinity)/.test(say || '')) out.push('a missing value');
  return out;
}

/** the decimal strings and hex strings a fact may appear as */
export function forms(v, dec, hex) {
  if (v === null || v === undefined || typeof v === 'boolean') return;
  if (Array.isArray(v) || ArrayBuffer.isView(v)) {
    if (v instanceof Uint8Array) hex.push(Buffer.from(v).toString('hex'));
    for (const x of v) forms(x, dec, hex);
    return;
  }
  if (v instanceof Map) { for (const [a, b] of v) { forms(a, dec, hex); forms(b, dec, hex); } return; }
  if (typeof v === 'object') { for (const x of Object.values(v)) forms(x, dec, hex); return; }
  if (typeof v === 'bigint') { const a = v < 0n ? -v : v; dec.add(a.toString()); hex.push(a.toString(16)); return; }
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return;
    const a = Math.abs(v);
    dec.add(String(a));
    for (let d = 0; d <= 4; d++) dec.add(a.toFixed(d));
    dec.add(String(Math.round(a)));
    dec.add(a.toLocaleString('en-US'));
    return;
  }
  const str = String(v);
  if (/^[0-9a-f]+$/i.test(str)) hex.push(str.toLowerCase());
  dec.add(str);
  for (const m of str.matchAll(/\d+(?:\.\d+)?/g)) dec.add(m[0]);
}
const NAMES = /\b(?:P-\d+|secp\d+k1|secp\d+r1|Curve\d+|Ed\d+|X\d+|SHA-\d+|SHA\d+|RFC \d+|FIPS \d+(?:-\d+)?|SP 800-\d+|PKCS #\d+|RSA-\d+|DSA-\d+|ML-DSA-\d+|v\d+(?:\.\d+)?|MGF\d+|HMAC-SHA-\d+|SEC \d)\b/g;
/** the numbers a sentence quotes: hex tokens (0x…, or runs of 8 or more hex digits) and decimal numbers */
export function numbersIn(say) {
  let s = String(say || '').replace(NAMES, ' ');
  const hexes = [];
  s = s.replace(/\b0x([0-9a-f]+)(?:…([0-9a-f]+))?/g, (m, a, b) => { hexes.push(a); if (b) hexes.push(b); return ' '; });
  s = s.replace(/\b([0-9a-f]{3,})…([0-9a-f]{3,})\b/g, (m, a, b) => { hexes.push(a, b); return ' '; });
  s = s.replace(/\b([0-9a-f]{8,})(?:…([0-9a-f]+))?/g, (m, a, b) => { if (!/[a-f]/.test(m) && m.length < 30 && !b) return m; hexes.push(a); if (b) hexes.push(b); return ' '; });
  const decs = [...s.matchAll(/\d+(?:,\d{3})*(?:\.\d+)?/g)].map((m) => m[0]);
  return { decs, hexes };
}

/**
 * mods: [{topic: id or RegExp, allow: [numbers as strings], random(rnd) -> values, count, extra: [values],
 *   check({S, tp, input, r, fail, ok})}]   check runs once per run with r (S.run's result).
 */
export function runClaims(name, part, mods, only) {
  const t = harness(name);
  const rnd = rng(20261018);
  let runs = 0;
  for (const tp of S.topics) {
    if (!tp.family.startsWith(part)) continue;
    if (only.length && !only.some((o) => tp.id.startsWith(o))) continue;
    const mine = mods.filter((m) => (m.topic instanceof RegExp ? m.topic.test(tp.id) : tp.id === m.topic));
    if (!mine.length) { t.ok(false, tp.id + ': no claim check'); continue; }
    const inputs = [{}].concat((tp.presets || []).map((p) => p.values));
    for (const m of mine) { inputs.push(...(m.extra || [])); if (m.random) for (let k = 0; k < (m.count || 6); k++) inputs.push(m.random(rnd)); }
    const allow = new Set(['0', '1', '2'].concat(...mine.map((m) => m.allow || [])));
    for (const v of inputs) {
      const input = S.inputOf(tp, Object.assign(S.inputOf(tp), v));
      const bad = S.checkInput(tp, input);
      if (bad) { if (v && Object.keys(v).length && !mine.some((m) => m.mayRefuse)) t.ok(false, tp.id + ' refuses the input ' + JSON.stringify(v) + ': ' + bad); continue; }
      const js = JSON.stringify(v), tag = tp.id + ' ' + (js.length > 90 ? js.slice(0, 87) + '…}' : js);
      let r;
      try { r = S.run(tp, input); } catch (e) { t.ok(false, tag + ': ' + e.message); continue; }
      runs++;
      t.ok(r.ok, tag + ': ' + (r.error || '') + ' ' + (r.stack || '').split('\n').slice(1, 3).join(' '));
      if (!r.ok) continue;
      t.ok(!(r.predictErrors || []).length, tag + ': ' + (r.predictErrors || []).join('; '));
      r.frames.forEach((f, i) => {
        for (const w of wording(f.say)) t.ok(false, tag + ' frame ' + i + ': ' + w + ': ' + f.say);
        if (f.predict) {
          for (const w of wording(f.predict.ask)) t.ok(false, tag + ' frame ' + i + ' prediction: ' + w + ': ' + f.predict.ask);
          if (typeof f.predict.explain === 'string') for (const w of wording(f.predict.explain)) t.ok(false, tag + ' frame ' + i + ' prediction explanation: ' + w);
        }
        if (!f.facts) { t.ok(false, tag + ' frame ' + i + ': no facts'); return; }
        const dec = new Set(), hex = [];
        forms(f.facts, dec, hex);
        const { decs, hexes } = numbersIn(f.say);
        const stray = decs.filter((n) => !dec.has(n) && !dec.has(n.replace(/,/g, '')) && !allow.has(n));
        t.ok(!stray.length, tag + ' frame ' + i + ': the narration quotes ' + stray.join(', ') + ', which no fact holds: ' + f.say);
        const strayH = hexes.filter((h) => !hex.some((x) => x.includes(h)));
        t.ok(!strayH.length, tag + ' frame ' + i + ': the narration quotes the hex ' + strayH.join(', ') + ', which no fact holds: ' + f.say);
      });
      for (const m of mine) {
        if (!m.check) continue;
        try { m.check({ S, tp, input, values: v, r, fail: (msg) => t.ok(false, tag + ': ' + msg), ok: (c, msg) => t.ok(c, tag + ': ' + msg) }); }
        catch (e) { t.ok(false, tag + ': the claim check fails: ' + (e.stack || e.message).split('\n').slice(0, 3).join(' ')); }
      }
    }
    for (const q of tp.quiz || []) for (const w of wording(q.q + ' ' + q.why + ' ' + q.options.join('. '))) t.ok(false, tp.id + ' quiz: ' + w + ': ' + q.q);
  }
  t.done();
  return runs;
}

// ---- arithmetic of our own, apart from src/core ----------------------------------------------------------------
export const mod = (a, m) => { a = BigInt(a); m = BigInt(m); return ((a % m) + m) % m; };
export const pw = (b, e, m) => { b = mod(b, m); e = BigInt(e); m = BigInt(m); let r = 1n % m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
/** the inverse by Fermat for a prime modulus, by a recursive Euclid otherwise */
export const inv = (a, m) => {
  a = mod(a, m); m = BigInt(m);
  const eg = (x, y) => (y === 0n ? [x, 1n, 0n] : (([g, s, t]) => [g, t, s - (x / y) * t])(eg(y, x % y)));
  const [g, s] = eg(a, m);
  return g === 1n ? mod(s, m) : null;
};
export const gcd = (a, b) => { a = BigInt(a); b = BigInt(b); if (a < 0n) a = -a; if (b < 0n) b = -b; while (b) [a, b] = [b, a % b]; return a; };
export const isPrime = (n) => { n = BigInt(n); if (n < 2n) return false; for (const q of [2n, 3n, 5n, 7n, 11n, 13n]) if (n % q === 0n) return n === q; let d = n - 1n, s = 0; while (!(d & 1n)) { d >>= 1n; s++; } for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) { let x = pw(a, d, n); if (x === 1n || x === n - 1n) continue; let ok = false; for (let i = 1; i < s; i++) { x = (x * x) % n; if (x === n - 1n) { ok = true; break; } } if (!ok) return false; } return true; };
export const factor = (n) => { n = BigInt(n); const out = []; for (let p = 2n; p * p <= n; p++) { let e = 0; while (n % p === 0n) { n /= p; e++; } if (e) out.push([p, e]); } if (n > 1n) out.push([n, 1]); return out; };
/** affine elliptic-curve arithmetic on y² = x³ + ax + b over GF(p), written plainly (null is the point at infinity) */
export function ec(p, a, b) {
  p = BigInt(p); a = mod(a, p); b = mod(b, p);
  const E = { p, a, b };
  E.on = (P) => !P || mod(P.y * P.y - P.x * P.x * P.x - a * P.x - b, p) === 0n;
  E.add = (P, Q) => {
    if (!P) return Q; if (!Q) return P;
    if (P.x === Q.x && mod(P.y + Q.y, p) === 0n) return null;
    const l = P.x === Q.x ? mod((3n * P.x * P.x + a) * inv(2n * P.y, p), p) : mod((Q.y - P.y) * inv(Q.x - P.x, p), p);
    const x = mod(l * l - P.x - Q.x, p);
    return { x, y: mod(l * (P.x - x) - P.y, p) };
  };
  E.neg = (P) => (P ? { x: P.x, y: mod(-P.y, p) } : null);
  E.mul = (k, P) => { k = BigInt(k); if (k < 0n) { k = -k; P = E.neg(P); } let R = null, A = P; while (k > 0n) { if (k & 1n) R = E.add(R, A); A = E.add(A, A); k >>= 1n; } return R; };
  E.eq = (P, Q) => (!P || !Q ? !P && !Q : P.x === Q.x && P.y === Q.y);
  E.points = () => { const out = []; for (let x = 0n; x < p; x++) for (let y = 0n; y < p; y++) if (mod(y * y - x * x * x - a * x - b, p) === 0n) out.push({ x, y }); return out; };
  E.count = () => { let N = 1n; for (let x = 0n; x < p; x++) { const r = mod(x * x * x + a * x + b, p); if (r === 0n) N += 1n; else if (pw(r, (p - 1n) / 2n, p) === 1n) N += 2n; } return N; };
  E.order = (P) => { let n = 1n, R = P; while (R) { R = E.add(R, P); n++; } return n; };
  return E;
}
/** P-256 and secp256k1 parameters, typed in from SEC 2 for the checks */
export const P256 = { p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn, a: -3n, b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn, n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n, G: { x: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n, y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n } };
export const K256 = { p: (1n << 256n) - (1n << 32n) - 977n, a: 0n, b: 7n, n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n, G: { x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n } };
export const b64u = (v, len) => Buffer.from(v.toString(16).padStart(2 * len, '0'), 'hex').toString('base64url');
export const sha256 = (b) => new Uint8Array(crypto.createHash('sha256').update(b).digest());
export const bigOf = (b) => BigInt('0x' + (Buffer.from(b).toString('hex') || '0'));
/** the frames of a run with a given stage */
export const at = (r, stage) => r.frames.filter((f) => f.meta && f.meta.stage === stage);
