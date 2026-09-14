// Shared by tests/claims-p14.mjs and tests/claims-p15.mjs: runs every topic of a part with its presets and random
// inputs, and for every frame checks
//  - the wording of the narration (a/an, doubled words, double spaces, a space before punctuation);
//  - that every number the narration quotes is one of the frame's facts (the values the topic took from the
//    engine), so nothing is typed in by hand; a topic may allow a few structural numbers (the 2 in 2 × mean);
//  - and then the topic's own check, which works the facts out again independently.
import { load, harness, rng } from './load.mjs';

export const S = load(['core', 'stage', 'topics']);

// words said with a vowel sound first: acronyms spelt out letter by letter, and numbers like 8 and 11
const VOWEL = /^((RSA|ECC|ECDSA|ML|SLH|LWE|NTT|FO|LLL|HMAC|S-box|SPA|SVP|X|F|H|L|M|N|S|R)(-[\w-]+)?|8|11|18|80|8\d|8\d\d|honest|hour)$/;
const CONS = /^(u[ns]i|use|usu|one|once|eu|uni)/i;
export function wording(say) {
  const s = (say || '').replace(/"[^"]*"/g, '"…"').replace(/“[^”]*”/g, '“…”'), out = [];
  if (/\S {2,}\S/.test(s)) out.push('a double space');
  if (/\s[,.;:](\s|$)/.test(s)) out.push('a space before punctuation');
  if (/\.\./.test(s.replace(/…/g, ''))) out.push('two full stops');
  for (const m of s.matchAll(/\b([A-Za-z]{2,}) \1\b/g)) if (!/^(that|had)$/i.test(m[1]) && !/^[SM]+$/.test(m[1])) out.push('the word "' + m[1] + '" twice');
  for (const m of s.matchAll(/(^|[^\w'])(a|an|A|An) ([\w'′-]+)/g)) {
    const art = m[2].toLowerCase(), w = m[3];
    // a capital A mid-sentence, or before a verb, is a matrix or a variable, not an article
    if (/^A/.test(m[2]) && (!/(^|[.:;!?]\s*)$/.test(s.slice(0, m.index + m[1].length)) || /^(is|has|was|holds|gives|times)$/.test(w))) continue;
    const vowel = VOWEL.test(w.replace(/[,.;:]$/, '')) || (/^[aeiou]/.test(w) && !CONS.test(w)) || (/^[AEIOU][a-z]/.test(w) && !CONS.test(w));
    if (art === 'a' && vowel && !/^(one|uni|use|usu|eu)/i.test(w)) out.push('"a ' + w + '"');
    if (art === 'an' && !vowel) out.push('"an ' + w + '"');
  }
  if (/\bthe the\b|\ba a\b|\bof of\b|\bto to\b/i.test(s)) out.push('a doubled small word');
  if (/(undefined|NaN|null|\[object)/.test(say || '')) out.push('a missing value');
  return out;
}

/** the strings a fact may appear as in the narration */
function forms(v, out) {
  if (v === null || v === undefined) return out;
  if (Array.isArray(v) || ArrayBuffer.isView(v)) { for (const x of v) forms(x, out); return out; }
  if (typeof v === 'object') { for (const x of Object.values(v)) forms(x, out); return out; }
  if (typeof v === 'bigint') { out.add(v.toString()); return out; }
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return out;
    const a = Math.abs(v);
    out.add(String(a));
    if (Number.isInteger(v)) out.add(String(a));
    for (let d = 0; d <= 6; d++) out.add(a.toFixed(d));
    out.add(String(+a.toPrecision(3)));
    out.add(String(Math.round(a)));
    return out;
  }
  const str = String(v);
  out.add(str);
  for (const m of str.matchAll(/\d+(?:\.\d+)?/g)) out.add(m[0]);
  return out;
}
const NAMES = /\b(?:AES|SHA3?|SHAKE|RSA|ML-KEM|ML-DSA|SLH-DSA|ECC P|P|FIPS|CBD|Curve|Ed|X|Hamming|T)-?\d+/g;
/** the numbers quoted in a sentence (names like AES-128 and sub- or superscripts are not numbers) */
export function numbersIn(say) {
  return [...String(say || '').replace(NAMES, ' ').replace(/[0-9a-f]{12,}…?/g, ' ').matchAll(/\d+(?:\.\d+)?/g)].map((m) => m[0]);
}

/**
 * mods: [{topic: id prefix or RegExp, allow: [numbers as strings], random(rnd) -> values, extra: [values],
 *   check({S, tp, input, r, f, i, facts, fail})}]   check runs once per run with r (S.run's result).
 */
export async function runClaims(name, part, mods, only) {
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
      if (bad) { if (v && Object.keys(v).length && mine.some((m) => (m.extra || []).includes(v))) t.ok(false, tp.id + ' refuses its own extra input: ' + bad); continue; }
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
        const ok = forms(f.facts, new Set());
        const stray = numbersIn(f.say).filter((n) => !ok.has(n) && !allow.has(n));
        t.ok(!stray.length, tag + ' frame ' + i + ': the narration quotes ' + stray.join(', ') + ', which no fact holds: ' + f.say);
      });
      for (const m of mine) {
        if (!m.check) continue;
        let pre = null;
        if (m.prepare) try { pre = await m.prepare(S, input); } catch (e) { t.ok(false, tag + ': prepare fails: ' + e.message); continue; }
        try { m.check({ S, tp, input, pre, values: v, r, fail: (msg) => t.ok(false, tag + ': ' + msg), ok: (c, msg) => t.ok(c, tag + ': ' + msg) }); }
        catch (e) { t.ok(false, tag + ': the claim check fails: ' + (e.stack || e.message).split('\n').slice(0, 3).join(' ')); }
      }
    }
  }
  t.done();
  return runs;
}
/** close enough for values printed with d decimals */
export const near = (a, b, d) => Math.abs(a - b) <= 0.5 * 10 ** -(d === undefined ? 4 : d) + 1e-12;
