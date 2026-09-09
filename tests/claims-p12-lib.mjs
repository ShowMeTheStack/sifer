// Shared by tests/claims-p12.mjs and tests/claims-p13.mjs: runs every topic of a part with its presets and random
// inputs, and for every frame checks
//  - the wording of the narration (a/an, doubled words, double spaces, a space before punctuation, two full stops);
//  - that every number the narration quotes (decimals, numbers with thousands separators, super- and subscripts)
//    is one of the frame's facts, so nothing is typed in by hand; a topic may allow a few structural numbers;
//  - that every hex string the narration quotes is part of a fact;
//  - and then the topic's own check, which works the values out again independently (node:crypto or a second
//    implementation written here).
import { load, harness, rng } from './load.mjs';

export const S = load(['core', 'stage', 'topics']);

const VOWEL = /^(a|e|i|o|u|honest|hour|8|11|18|80|8\d\d?|RSA|SHA|AES|ECC|ECDSA|ML|HMAC|MD5|X25519|S-box|SPN|IV|[LMNSRFHX](?![a-z])(?!AC)|FIPS|HKDF|OCSP|RFC|NIST|n-bit|n\b)/;
const CONS = /^(u[ns]i|use|usu|one|once|eu|uni)/i;
export function wording(say) {
  const s = (say || '').replace(/"[^"]*"/g, '"…"').replace(/“[^”]*”/g, '“…”'), out = [];
  if (/\S {2,}\S/.test(s)) out.push('a double space');
  if (/\s[,.;:](\s|$)/.test(s)) out.push('a space before punctuation');
  if (/\.\./.test(s.replace(/…/g, ''))) out.push('two full stops');
  for (const m of s.matchAll(/\b([A-Za-z]{2,}) \1\b/g)) if (!/^(that|had)$/i.test(m[1])) out.push('the word "' + m[1] + '" twice');
  for (const m of s.matchAll(/(^|[^\w'′])(a|an|A|An) ([\w'′-]+)/g)) {
    const art = m[2].toLowerCase(), w = m[3];
    if (/^(and|or|is|are|to|in|on|at|of|with|by|as|was|were|the|from|through)$/i.test(w)) continue; // a variable named a, not the article
    const vowel = (VOWEL.test(w) || /^[aeiou]/i.test(w)) && !CONS.test(w);
    if (art === 'a' && vowel) out.push('"a ' + w + '"');
    if (art === 'an' && !vowel) out.push('"an ' + w + '"');
  }
  if (/(undefined|NaN|\bnull\b|\[object)/.test(say || '')) out.push('a missing value');
  return out;
}

const SUP = '⁰¹²³⁴⁵⁶⁷⁸⁹', SUB = '₀₁₂₃₄₅₆₇₈₉';
const hexOf = (a) => Array.from(a, (v) => (v & 255).toString(16).padStart(2, '0')).join('');
/** every string a fact may appear as: numbers in several roundings, strings and their digit runs, bytes as hex */
function forms(v, out, hexes) {
  if (v === null || v === undefined) return;
  if (ArrayBuffer.isView(v)) { hexes.push(hexOf(v)); return; }
  if (Array.isArray(v)) { for (const x of v) forms(x, out, hexes); return; }
  if (typeof v === 'object') { for (const x of Object.values(v)) forms(x, out, hexes); return; }
  if (typeof v === 'bigint') { out.add(v.toString()); hexes.push(v.toString(16)); return; }
  if (typeof v === 'boolean') return;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return;
    const a = Math.abs(v);
    out.add(String(a));
    for (let d = 0; d <= 6; d++) out.add(a.toFixed(d));
    out.add(String(Math.round(a)));
    hexes.push(Math.round(a).toString(16));
    return;
  }
  const str = String(v);
  hexes.push(str.toLowerCase().replace(/\s+/g, ''));
  for (const m of str.replace(/,(\d{3})/g, '$1').matchAll(/\d+(?:\.\d+)?/g)) out.add(m[0]);
  for (const ch of str) { const k = SUP.indexOf(ch) >= 0 ? SUP.indexOf(ch) : SUB.indexOf(ch); if (k >= 0) out.add(String(k)); }
  for (const m of str.replace(/[⁰¹²³⁴⁵⁶⁷⁸⁹]+/g, (x) => ' ' + [...x].map((c) => SUP.indexOf(c)).join('') + ' ').replace(/[₀-₉]+/g, (x) => ' ' + [...x].map((c) => SUB.indexOf(c)).join('') + ' ').matchAll(/\d+/g)) out.add(m[0]);
}
// names that contain digits but are not values
const NAMES = /\b(?:SHA3?-\d+|SHA-\d+\/\d+|SHAKE\d+|MD[45]|AES-\d+(?:-GCM)?|RFC \d+|FIPS \d+|SP 800-\d+[A-Z]?|X25519|ChaCha20|Salsa20|Poly1305|Keccak-f\[\d+\]|HMAC-SHA\d+|HMAC-SHA-\d+|HMAC-MD5|HMAC-SHA-1|SHA3-\d+|RSA-\d+|TLS 1\.3|TLS_\w+|SHA-0|MD4|GF\(2[¹²³⁴⁵⁶⁷⁸⁹⁰]+\)|GF\(2\^\d+\)|K[₀-₉]+|W[₀-₉]+|M[₀-₉]+|CV[₀-₉]+|P[₀-₉]+|Z[₀-₉]+|H[₀-₉]+|T[12]|U[₀-₉]+|U\d|T\(\d+\)|x=\d)/g;
/** the hex strings and the numbers a sentence quotes */
export function quoted(say) {
  let s = String(say || '').replace(/“[^”]*”/g, ' ').replace(NAMES, ' ').replace(/\b([0-9a-f]{8})((?: [0-9a-f]{1,8})+)\b/g, (m) => m.replace(/ /g, ''));
  const hex = [];
  s = s.replace(/\b[0-9a-f]{6,}\b…?/g, (m) => { const h = m.replace('…', ''); if (/[a-f]/.test(h) || h.length >= 8) { hex.push(h); return ' '; } return m; });
  s = s.replace(/[⁰¹²³⁴⁵⁶⁷⁸⁹]+/g, (x) => ' ' + [...x].map((c) => SUP.indexOf(c)).join('') + ' ').replace(/[₀-₉]+/g, (x) => ' ' + [...x].map((c) => SUB.indexOf(c)).join('') + ' ');
  const nums = [...s.matchAll(/\d{1,3}(?:,\d{3})+|\d+(?:\.\d+)?/g)].map((m) => m[0].replace(/,/g, ''));
  return { hex, nums };
}

/**
 * mods: [{topic: id or RegExp, allow: [numbers as strings], random(rnd) -> values, count, extra: [values],
 *   check({S, tp, input, r, fail, ok})}]
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
      if (bad) { if (mine.some((m) => (m.extra || []).includes(v))) t.ok(false, tp.id + ' refuses its own extra input: ' + bad); continue; }
      const js = JSON.stringify(v), tag = tp.id + ' ' + (js.length > 80 ? js.slice(0, 77) + '…}' : js);
      let r;
      try { r = S.run(tp, input); } catch (e) { t.ok(false, tag + ': ' + e.message); continue; }
      runs++;
      t.ok(r.ok, tag + ': ' + (r.error || ''));
      if (!r.ok) continue;
      r.frames.forEach((f, i) => {
        for (const w of wording(f.say)) t.ok(false, tag + ' frame ' + i + ': ' + w + ': ' + f.say);
        if (f.predict && typeof f.predict.ask === 'string') for (const w of wording(f.predict.ask)) t.ok(false, tag + ' frame ' + i + ' prediction: ' + w);
        if (!f.facts) { t.ok(false, tag + ' frame ' + i + ': no facts'); return; }
        const ok = new Set(), hexes = [];
        forms(f.facts, ok, hexes);
        const q = quoted(f.say);
        const stray = q.nums.filter((n) => !ok.has(n) && !allow.has(n));
        t.ok(!stray.length, tag + ' frame ' + i + ': the narration quotes ' + stray.join(', ') + ', which no fact holds: ' + f.say);
        const strayHex = q.hex.filter((h) => !hexes.some((x) => x.includes(h)));
        t.ok(!strayHex.length, tag + ' frame ' + i + ': the narration quotes the hex ' + strayHex.join(', ') + ', which no fact holds: ' + f.say);
      });
      for (const m of mine) {
        if (!m.check) continue;
        try { m.check({ S, tp, input, values: v, r, fail: (msg) => t.ok(false, tag + ': ' + msg), ok: (c, msg) => t.ok(c, tag + ': ' + msg) }); }
        catch (e) { t.ok(false, tag + ': the claim check fails: ' + (e.stack || e.message).split('\n').slice(0, 3).join(' ')); }
      }
    }
  }
  t.done();
  return runs;
}
export const hex = hexOf;
export const fromHex = (s) => Uint8Array.from((String(s).replace(/\s+/g, '').match(/../g) || []).map((x) => parseInt(x, 16)));
export const utf8 = (s) => new TextEncoder().encode(String(s));
