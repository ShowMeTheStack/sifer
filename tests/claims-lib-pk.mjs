// Shared by tests/claims-p07.mjs, claims-p08.mjs and claims-p09.mjs: runs every topic of a part with its presets and
// random inputs, and for every frame checks
//  - the wording of the narration and of the predictions (a/an, doubled words, double spaces, a space before
//    punctuation, a missing value);
//  - that every number the narration quotes is one of the frame's facts (the values the topic took from the engines),
//    so nothing is typed in by hand; a long number quoted by its first and last digits counts when its ends match;
//    a topic may allow a few structural numbers (the 2 in 2^16);
//  - and then the topic's own check, which works the facts out again independently (node:crypto, brute force, or a
//    second method).
import { load, harness, rng } from './load.mjs';

export const S = load(['core', 'stage', 'topics']);

const VOWEL = /^(a|e|i|o|u|honest|hour|8|11|18|80|8\d\d?|RSA|SHA|AES|ECC|ECDSA|ML|LWE|HMAC|MAC|MGF|OAEP|[XFHLMNSR]\b|RFC|NIST|SP|n-bit|x-coordinate)(?![a-z])/;
const CONS = /^(u[ns]i|use|usu|one|once|eu|uni)/i;
export function wording(say) {
  const s = (say || '').replace(/"[^"]*"/g, '"…"').replace(/“[^”]*”/g, '“…”'), out = [];
  if (/\S {2,}\S/.test(s)) out.push('a double space');
  if (/\s[,.;:](\s|$)/.test(s)) out.push('a space before punctuation');
  if (/\.\./.test(s.replace(/…/g, ''))) out.push('two full stops');
  for (const m of s.matchAll(/\b([A-Za-z]{2,}) \1\b/g)) if (!/^(that|had)$/i.test(m[1])) out.push('the word "' + m[1] + '" twice');
  for (const m of s.matchAll(/(^|[^\w'’])(a|an|A|An) ([\w'′-]+)/g)) {
    const art = m[2].toLowerCase(), w = m[3];
    // a single-letter name (a, b) followed by a joining word is a variable, not an article
    if (art === 'a' && /^(and|or|is|to|in|of|mod|with|from|by|are|was|b|x|then|but|as|for|so|at|has|stays|must|never|only)$/.test(w)) continue;
    let vowel = (VOWEL.test(w) || /^[aeiou]/i.test(w)) && !CONS.test(w);
    if (/^\d/.test(w)) vowel = w[0] === '8' || (/^1[18]/.test(w.replace(/\D.*$/, '')) && (w.replace(/\D.*$/, '').length - 2) % 3 === 0);
    if (art === 'a' && vowel) out.push('"a ' + w + '"');
    if (art === 'an' && !vowel) out.push('"an ' + w + '"');
  }
  if (/\bthe the\b|\ba a\b|\bof of\b|\bto to\b|\bis is\b/i.test(s)) out.push('a doubled small word');
  if (/(undefined|NaN|\bnull\b|\[object|Infinity)/.test(say || '')) out.push('a missing value');
  return out;
}

/** the strings a fact may appear as in the narration */
export function forms(v, out) {
  if (v === null || v === undefined) return out;
  if (Array.isArray(v) || ArrayBuffer.isView(v)) { for (const x of v) forms(x, out); return out; }
  if (v instanceof Map) { for (const [a, b] of v) { forms(a, out); forms(b, out); } return out; }
  if (typeof v === 'object') { for (const x of Object.values(v)) forms(x, out); return out; }
  if (typeof v === 'bigint') {
    const s = (v < 0n ? -v : v).toString();
    out.add(s);
    if (s.length > 12) { for (const k of [6, 8, 10]) { out.add(s.slice(0, k)); out.add(s.slice(-k)); } out.add(String(s.length)); }
    return out;
  }
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return out;
    const a = Math.abs(v);
    out.add(String(a));
    for (let d = 0; d <= 6; d++) out.add(a.toFixed(d));
    out.add(String(+a.toPrecision(3)));
    out.add(String(+a.toPrecision(2)));
    out.add(String(Math.round(a)));
    out.add(a.toLocaleString('en-US'));
    return out;
  }
  if (typeof v === 'boolean') return out;
  const str = String(v);
  out.add(str);
  for (const m of str.matchAll(/\d+(?:\.\d+)?/g)) out.add(m[0]);
  return out;
}
const NAMES = /\b(?:AES|SHA|SHA3|RSA|DSA|MGF|RFC|SP|P|FIPS|PKCS|Curve|Ed|X|TDEA|ECC|DH|MODP)[- ]?\d+(?:-\d+)?(?: Part \d+)?|\b\d+TDEA\b|\b(?:SP )?800-\d+\b|\bPKCS #\d+\b|\bv\d+(?:\.\d+)?\b|\bL\[1\/3\]/g;
/** the numbers quoted in a sentence (names like RSA-2048 and sub- or superscripts are not numbers; 1,234 is one number) */
export function numbersIn(say) {
  return [...String(say || '').replace(NAMES, ' ').replace(/\b[0-9a-f]*[a-f][0-9a-f]*\b/g, (h) => (h.length >= 6 ? ' ' : h)).replace(/[0-9a-f]{16,}/g, ' ').matchAll(/\d+(?:,\d{3})*(?:\.\d+)?/g)].map((m) => m[0]).map((x) => (/,\d{3}/.test(x) ? x : x));
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
    for (const m of mine) { inputs.push(...(m.extra || [])); if (m.random) for (let k = 0; k < (m.count || 8); k++) inputs.push(m.random(rnd)); }
    const allow = new Set(['0', '1', '2'].concat(...mine.map((m) => m.allow || [])));
    for (const v of inputs) {
      const input = S.inputOf(tp, Object.assign(S.inputOf(tp), v));
      const bad = S.checkInput(tp, input);
      if (bad) { if (v && Object.keys(v).length && !mine.some((m) => m.mayRefuse)) t.ok(false, tp.id + ' refuses the input ' + JSON.stringify(v) + ': ' + bad); continue; }
      const js = JSON.stringify(v), tag = tp.id + ' ' + (js.length > 80 ? js.slice(0, 77) + '…}' : js);
      let r;
      try { r = S.run(tp, input); } catch (e) { t.ok(false, tag + ': ' + e.message); continue; }
      runs++;
      t.ok(r.ok, tag + ': ' + (r.error || '') + ' ' + (r.stack || '').split('\n').slice(1, 3).join(' '));
      if (!r.ok) continue;
      r.frames.forEach((f, i) => {
        for (const w of wording(f.say)) t.ok(false, tag + ' frame ' + i + ': ' + w + ': ' + f.say);
        if (f.predict) {
          for (const w of wording(f.predict.ask)) t.ok(false, tag + ' frame ' + i + ' prediction: ' + w + ': ' + f.predict.ask);
          if (typeof f.predict.explain === 'string') for (const w of wording(f.predict.explain)) t.ok(false, tag + ' frame ' + i + ' prediction explanation: ' + w);
        }
        if (!f.facts) { t.ok(false, tag + ' frame ' + i + ': no facts'); return; }
        const ok = forms(f.facts, new Set());
        const stray = numbersIn(f.say).filter((n) => !ok.has(n) && !ok.has(n.replace(/,/g, '')) && !allow.has(n));
        t.ok(!stray.length, tag + ' frame ' + i + ': the narration quotes ' + stray.join(', ') + ', which no fact holds: ' + f.say);
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
/** close enough for values printed with d decimals */
export const near = (a, b, d) => Math.abs(a - b) <= 0.5 * 10 ** -(d === undefined ? 4 : d) + 1e-12;
/** independent arithmetic: modular power, gcd, inverse, integer roots, primality by node:crypto */
export const pw = (b, e, m) => { b = BigInt(b); e = BigInt(e); m = BigInt(m); let r = 1n; b = ((b % m) + m) % m; if (e < 0n) throw new Error('negative exponent'); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r % m; };
export const gcd = (a, b) => { a = BigInt(a); b = BigInt(b); if (a < 0n) a = -a; if (b < 0n) b = -b; while (b) [a, b] = [b, a % b]; return a; };
export const inv = (a, m) => { a = BigInt(a); m = BigInt(m); let [r0, r1, s0, s1] = [((a % m) + m) % m, m, 1n, 0n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } if (r0 !== 1n) return null; return ((s0 % m) + m) % m; };
export const mod = (a, m) => { a = BigInt(a); m = BigInt(m); return ((a % m) + m) % m; };
