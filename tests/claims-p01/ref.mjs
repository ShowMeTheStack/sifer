// Independent working-out for the part 1 claims check: every classical cipher and Enigma written again here, plainly,
// without the engines, so the narration can be compared with a second computation.
export const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
export const md = (n, m = 26) => ((n % m) + m) % m;
export const L = (t) => String(t).toUpperCase().replace(/[^A-Z]/g, '');
const I = (c) => c.charCodeAt(0) - 65, C = (i) => ABC[md(i)];

export const shift = (t, k) => Array.from(L(t), (c) => C(I(c) + k)).join('');
export const inv26 = (a) => { for (let x = 1; x < 26; x++) if ((a * x) % 26 === 1) return x; return null; };
export const gcd = (a, b) => (b ? gcd(b, a % b) : Math.abs(a));
export const affine = (t, a, b) => Array.from(L(t), (c) => C(a * I(c) + b)).join('');
export function keyword(word, cont) {
  const k = [...new Set(L(word))], start = cont && k.length ? I(k[k.length - 1]) + 1 : 0, rest = [];
  for (let i = 0; i < 26; i++) { const c = C(start + i); if (!k.includes(c)) rest.push(c); }
  return k.join('') + rest.join('');
}
export const subst = (t, alpha) => Array.from(L(t), (c) => alpha[I(c)]).join('');
export const vig = (t, key, s = 1) => { const k = L(key); return Array.from(L(t), (c, i) => C(I(c) + s * I(k[i % k.length]))).join(''); };
export const autokey = (t, pr) => { const p = L(t), ks = L(pr) + p; return Array.from(p, (c, i) => C(I(c) + I(ks[i]))).join(''); };
export function columnar(t, key) {
  const k = L(key), p = L(t), w = k.length, order = [...k].map((c, i) => [c, i]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] - b[1])).map((x) => x[1]);
  let out = ''; const cols = [];
  for (const c of order) { let s = ''; for (let i = c; i < p.length; i += w) s += p[i]; cols.push(s); out += s; }
  return { out, cols, order };
}
export function rail(t, n) {
  const p = L(t), rows = Array.from({ length: n }, () => ''); let r = 0, d = 1;
  for (const c of p) { rows[r] += c; if (n > 1) { if (r === 0) d = 1; else if (r === n - 1) d = -1; r += d; } }
  return { out: rows.join(''), rows };
}
export function playfairSquare(key) { const s = []; for (const c of L(key).replace(/J/g, 'I') + 'ABCDEFGHIKLMNOPQRSTUVWXYZ') if (!s.includes(c)) s.push(c); return s.join(''); }
export function playfairPair(sq, pr, dir = 1) {
  const a = sq.indexOf(pr[0]), b = sq.indexOf(pr[1]), ra = Math.floor(a / 5), ca = a % 5, rb = Math.floor(b / 5), cb = b % 5;
  if (ra === rb) return sq[ra * 5 + md(ca + dir, 5)] + sq[rb * 5 + md(cb + dir, 5)];
  if (ca === cb) return sq[md(ra + dir, 5) * 5 + ca] + sq[md(rb + dir, 5) * 5 + cb];
  return sq[ra * 5 + cb] + sq[rb * 5 + ca];
}
export const counts = (t) => { const c = new Array(26).fill(0); for (const ch of L(t)) c[I(ch)]++; return c; };
export const ioc = (t) => { const c = counts(t), n = c.reduce((a, b) => a + b, 0); return c.reduce((s, x) => s + x * (x - 1), 0) / (n * (n - 1)); };
export const chi = (cnt, eng) => { const n = cnt.reduce((a, b) => a + b, 0); let s = 0; for (let i = 0; i < 26; i++) { const e = (n * eng[i]) / 100; s += ((cnt[i] - e) ** 2) / e; } return s; };
export const fact = (n) => { let f = 1n; for (let i = 2n; i <= BigInt(n); i++) f *= i; return f; };

// ---- Enigma I, written plainly -----------------------------------------------------------------------------------
const W = { I: ['EKMFLGDQVZNTOWYHXUSPAIBRCJ', 'Q'], II: ['AJDKSIRUXBLHWTMCQGZNPYFVOE', 'E'], III: ['BDFHJLCPRTXVZNYEIWGAKMUSQO', 'V'], IV: ['ESOVPZJAYQUIRHXLNFTGKDCMWB', 'J'], V: ['VZBRGITYUPSDNHLXAWMJQOFECK', 'Z'] };
const UKWB = 'YRUHQSLDPXNGOKMIEBFZCWVJAT';
export function enigma(cfg) {
  const order = cfg.order, rings = Array.from(cfg.rings || 'AAA', I), pos = Array.from(cfg.window || 'AAA', I), plug = Array.from(ABC, (c, i) => i);
  for (const pr of String(cfg.plugs || '').toUpperCase().split(/\s+/).filter(Boolean)) { plug[I(pr[0])] = I(pr[1]); plug[I(pr[1])] = I(pr[0]); }
  const wir = order.map((r) => Array.from(W[r][0], I)), inv = wir.map((w) => { const v = []; w.forEach((x, i) => { v[x] = i; }); return v; }), notch = order.map((r) => I(W[r][1]));
  const m = {
    pos,
    get window() { return pos.map(C).join(''); },
    step() { const mid = pos[1] === notch[1], right = pos[2] === notch[2]; const s = [mid, mid || right, true]; if (mid) { pos[0] = md(pos[0] + 1); pos[1] = md(pos[1] + 1); } else if (right) pos[1] = md(pos[1] + 1); pos[2] = md(pos[2] + 1); return s; },
    through(c) {
      let x = plug[c];
      for (const k of [2, 1, 0]) { const o = md(pos[k] - rings[k]); x = md(wir[k][md(x + o)] - o); }
      x = I(UKWB[x]);
      for (const k of [0, 1, 2]) { const o = md(pos[k] - rings[k]); x = md(inv[k][md(x + o)] - o); }
      return plug[x];
    },
    press(ch) { m.step(); return C(m.through(I(ch))); },
    run(t) { return Array.from(L(t), (c) => m.press(c)).join(''); },
    perm() { return Array.from(ABC, (c, i) => m.through(i)); },
  };
  return m;
}
export const cycleLengths = (p) => { const seen = new Array(26).fill(false), out = []; for (let s = 0; s < 26; s++) { if (seen[s]) continue; let x = s, n = 0; while (!seen[x]) { seen[x] = true; n++; x = p[x]; } out.push(n); } return out.sort((a, b) => b - a); };
