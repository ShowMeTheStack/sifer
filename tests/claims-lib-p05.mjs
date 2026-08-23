// Shared by tests/claims-p05.mjs and tests/claims-p06.mjs: runs every topic of a part with its presets and random
// inputs, and for every frame checks
//  - the wording of the narration and of its predictions (a/an, doubled words, double spaces, stray spaces);
//  - that every hex value the narration quotes (bytes, blocks, words) is one of the frame's facts,
//    and that every other number it states is a fact too (a topic may allow a few structural numbers, such as the
//    16 of "16 bytes"), so nothing is typed in by hand;
//  - and then the topic's own check, which works the facts out again independently (tests/claims-ref-aes.mjs, an
//    AES written apart from the engines, and node:crypto).
import { load, harness, rng } from './load.mjs';

export const S = load(['core', 'stage', 'topics']);
export const hex = (a, sep) => Array.from(a, (v) => (v & 255).toString(16).padStart(2, '0')).join(sep || '');
export const h2 = (v) => (v & 255).toString(16).padStart(2, '0');
export const same = (a, b) => a.length === b.length && Array.from(a).every((v, i) => v === b[i]);

/** text in single quotes (not apostrophes): 'like this' */
const SQ = /(^|[\s(])'[^']*'(?=[\s,.;:)!?]|$)/g;
const CONS = /^(u[ns]i|use|usu|one|once|eu|uni|user)/i;
/** does a word (or a hex byte) start with a vowel sound */
export const vowelSound = (w) => {
  // a hex value is read digit by digit: an 8e, an a3, an e5, an f0; a 63, a 1b
  if (/^[0-9a-f]+$/.test(w) && /[a-f]/.test(w) && /\d/.test(w)) return /^[8aef]/.test(w);
  if (/^(8|11|18)/.test(w) && !/^(1[0-79]|1\d\d)/.test(w)) return true;
  if (/^(AES|ECB|IV|S-box|SP|XTS|XOR|OFB|MAC|HMAC|RSA|NIST|FIPS|L|M|N|R|S|X|F|H|SBOX|LSB|MSB|AEAD|ISO|IEEE|SHA)\b/.test(w)) return true;
  if (/^(honest|hour)/i.test(w)) return true;
  return /^[aeiou]/i.test(w) && !CONS.test(w);
};
export function wording(say) {
  const s = (say || '').replace(/"[^"]*"/g, '"…"').replace(/“[^”]*”/g, '“…”').replace(SQ, "$1'…'"), out = [];
  if (/\S {2,}\S/.test(s)) out.push('a double space');
  if (/\s[,.;:](\s|$)/.test(s)) out.push('a space before punctuation');
  if (/\.\./.test(s.replace(/…/g, ''))) out.push('two full stops');
  for (const m of s.replace(/`/g, '').matchAll(/\b([A-Za-z]{2,}) \1\b/g)) if (!/^(that|had)$/i.test(m[1]) && !/^[0-9a-f]{2}$/.test(m[1])) out.push('the word "' + m[1] + '" twice');
  for (const m of s.replace(/`/g, '').matchAll(/(^|[^\w'])(a|an|A|An) ([\w'′-]+)/g)) {
    // a lone 'a' before a function word is a hex digit ("a and 0"), not an article
    if (m[2] === 'a' && /^(and|or|of|to|in|is|at|on)$/.test(m[3])) continue;
    const art = m[2].toLowerCase(), v = vowelSound(m[3]);
    if (art === 'a' && v) out.push('"a ' + m[3] + '"');
    if (art === 'an' && !v) out.push('"an ' + m[3] + '"');
  }
  if (/\bthe the\b|\ba a\b|\bof of\b|\bto to\b|\bis is\b/i.test(s)) out.push('a doubled small word');
  if (/(undefined|NaN|\bnull\b|\[object)/.test(say || '')) out.push('a missing value');
  return out;
}

/** the strings a fact may appear as in the narration */
export function forms(v, out) {
  out = out || new Set();
  if (v === null || v === undefined || typeof v === 'boolean') return out;
  if (ArrayBuffer.isView(v) || (Array.isArray(v) && v.length && v.every((x) => Number.isInteger(x) && x >= 0 && x < 256))) {
    out.add(hex(v)); out.add(hex(v, ' '));
    for (const x of v) forms(x, out);
    return out;
  }
  if (Array.isArray(v)) { for (const x of v) forms(x, out); return out; }
  if (typeof v === 'object') { for (const x of Object.values(v)) forms(x, out); return out; }
  if (typeof v === 'bigint') { out.add(v.toString()); out.add(v.toString(16)); out.add(v.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')); return out; }
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return out;
    const a = Math.abs(v);
    out.add(String(a));
    for (let d = 0; d <= 6; d++) out.add(a.toFixed(d));
    out.add(String(+a.toPrecision(3))); out.add(String(+a.toPrecision(2)));
    out.add(String(Math.round(a)));
    out.add(String(Math.round(a)).replace(/\B(?=(\d{3})+(?!\d))/g, ','));
    if (Number.isInteger(a)) { out.add(a.toString(16)); if (a < 256) out.add(h2(a)); if (a < 16) out.add(a.toString(2).padStart(4, '0')); if (a < 256) out.add(a.toString(2).padStart(8, '0')); }
    return out;
  }
  const str = String(v);
  out.add(str);
  for (const m of str.matchAll(/\d+(?:\.\d+)?/g)) out.add(m[0]);
  for (const m of str.matchAll(/[0-9a-f]+/g)) out.add(m[0]);
  if (/^[0-9a-f]+$/.test(str) && str.length % 2 === 0) out.add(str.replace(/(..)(?!$)/g, '$1 '));
  return out;
}
/** the hex values of a sentence: runs of hex digits with a letter and a digit in them, or six or more letters a-f
 * (pure digits are numbers, checked as such; their hex forms are facts too) */
const HEXRE = /(?<![\w.'’-])[0-9a-f]{2,}(?![\w'’-])/g;
const isHex = (t) => (/[a-f]/.test(t) && /\d/.test(t)) || (/^[a-f]{6,}$/.test(t) && !/^(accede|deface|facade|efface|decade|backed)/.test(t));
export const quoted = (say) => [...String(say || '').replace(/“[^”]*”/g, ' ').replace(SQ, '$1 ').replace(/"[^"]*"/g, ' ').matchAll(HEXRE)].map((m) => m[0]).filter(isHex);
const NAMES = /\b(?:AES|SHA|RSA|FIPS|SP|RFC|PKCS|ISO|IEEE|CFB|DES|3DES|PRESENT|GF|AES-NI|Sweet|Te|Td|w|K|C|P|T|E|D|H|I|J|X|Y|S)\s?-?#?\d+(?:-\d+)?[A-E]?/g;
/** the numbers stated outside backticks and quotes (names like AES-128, SP 800-38A and w12 are not numbers) */
export function numbersIn(say) {
  const s = String(say || '').replace(HEXRE, (t) => (isHex(t) ? ' ' : t)).replace(/“[^”]*”/g, ' ').replace(SQ, '$1 ').replace(/"[^"]*"/g, ' ').replace(/GF\(2[^)]*\)/g, ' ').replace(NAMES, ' ');
  return [...s.matchAll(/\d+(?:,\d{3})*(?:\.\d+)?/g)].map((m) => m[0]);
}

/**
 * mods: [{topic: id or RegExp, allow: [numbers as strings], text: [quoted words allowed], random(rnd) -> values,
 *   extra: [values], count, check({S, tp, input, values, r, fail, ok})}]   check runs once per run with r = S.run(...).
 */
export function runClaims(name, families, mods, only) {
  const t = harness(name);
  const rnd = rng(20261018);
  let runs = 0;
  for (const tp of S.topics) {
    if (!families.some((f) => tp.family.startsWith(f))) continue;
    if (only.length && !only.some((o) => tp.id.startsWith(o))) continue;
    const mine = mods.filter((m) => (m.topic instanceof RegExp ? m.topic.test(tp.id) : tp.id === m.topic));
    if (!mine.length) { t.ok(false, tp.id + ': no claim check'); continue; }
    const inputs = [{}].concat((tp.presets || []).map((p) => p.values));
    for (const m of mine) { inputs.push(...(m.extra || [])); if (m.random) for (let k = 0; k < (m.count || 8); k++) inputs.push(m.random(rnd)); }
    const allow = new Set(['0', '1', '2'].concat(...mine.map((m) => m.allow || [])));
    const words = new Set([].concat(...mine.map((m) => m.text || [])));
    for (const v of inputs) {
      const input = S.inputOf(tp, Object.assign(S.inputOf(tp), v));
      const bad = S.checkInput(tp, input);
      if (bad) { t.ok(false, tp.id + ' refuses an input it should take (' + JSON.stringify(v).slice(0, 80) + '): ' + bad); continue; }
      const js = JSON.stringify(v), tag = tp.id + ' ' + (js.length > 80 ? js.slice(0, 77) + '…}' : js);
      let r;
      try { r = S.run(tp, input); } catch (e) { t.ok(false, tag + ': ' + e.message); continue; }
      runs++;
      t.ok(r.ok, tag + ': ' + (r.error || '') + ' ' + (r.stack || '').split('\n').slice(1, 3).join(' '));
      if (!r.ok) continue;
      r.frames.forEach((f, i) => {
        for (const w of wording(f.say)) t.ok(false, tag + ' frame ' + i + ': ' + w + ': ' + f.say);
        if (f.predict && typeof f.predict.ask === 'string') for (const w of wording(f.predict.ask)) t.ok(false, tag + ' frame ' + i + ' prediction: ' + w + ': ' + f.predict.ask);
        if (f.predict && typeof f.predict.explain === 'string') for (const w of wording(f.predict.explain)) t.ok(false, tag + ' frame ' + i + ' prediction: ' + w + ': ' + f.predict.explain);
        if (!f.facts) { t.ok(false, tag + ' frame ' + i + ': no facts'); return; }
        const ok = forms(f.facts);
        const strayQ = quoted(f.say).filter((q) => !ok.has(q) && !ok.has(q.replace(/\s+/g, '')) && !words.has(q));
        t.ok(!strayQ.length, tag + ' frame ' + i + ': the narration quotes ' + strayQ.join(', ') + ', which no fact holds: ' + f.say);
        const stray = numbersIn(f.say).filter((n) => !ok.has(n) && !ok.has(n.replace(/,/g, '')) && !allow.has(n));
        t.ok(!stray.length, tag + ' frame ' + i + ': the narration states ' + stray.join(', ') + ', which no fact holds: ' + f.say);
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
/** close enough for values printed with d decimals */
export const near = (a, b, d) => Math.abs(a - b) <= 0.5 * 10 ** -(d === undefined ? 4 : d) + 1e-12;
/** the frames of a run whose meta.stage is one of the names given */
export const at = (r, ...stages) => r.frames.filter((f) => f.meta && stages.includes(f.meta.stage));
