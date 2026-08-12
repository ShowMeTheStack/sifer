// Part 1 narration claims: every topic of the classical and Enigma families is run with its default, every preset and
// a spread of random valid inputs. Each value a frame's narration quotes is read back and compared with an independent
// working-out (tests/claims-p01/ref.mjs: the ciphers and Enigma written again without the engines). The wording is
// checked too: a and an, doubled words, double spaces, stray spaces before punctuation, leftover hyphen minus signs.
// Prints "claims-p01 N passed, M failed". Usage: node tests/claims-p01.mjs [topic id prefix ...]
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { files, harness, rng } from './load.mjs';
import { classicChecks } from './claims-p01/classic.mjs';
import { enigmaChecks } from './claims-p01/enigma.mjs';

// the engines, the stage and only this part's topics, so another part's work in progress cannot stop the check
const src = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
const ctx = vm.createContext({ console, performance, setTimeout, clearTimeout, TextEncoder, TextDecoder });
for (const f of files(['core', 'stage']).concat(files(['topics']).filter((f) => /topics\/p01-/.test(f)))) vm.runInContext(readFileSync(join(src, f), 'utf8'), ctx, { filename: f });
const S = ctx.Sifer, t = harness('claims-p01'), only = process.argv.slice(2);
const CHECKS = Object.assign({}, classicChecks(S), enigmaChecks(S));

// ---- wording ----
const VOWEL = /^([AEFHILMNORSX]|[AEFHILMNORSX][^a-z]|8|11|18|[aeio]|un[^i]|hour|honest)/;
const CONS = /^(one|use|uni|eu|[bcdgjkpqtvwyz]|[BCDGJKPQTUVWYZ](?![a-z])|[BCDGJKPQTVWYZ][a-z]|U[a-z])/;
export function wording(say) {
  const s = String(say || '').replace(/"[^"]*"/g, '"…"'), out = [];
  if (/\S {2,}\S/.test(s.replace(/AD: [\d ]+ BE: [\d ]+ CF: [\d ]+/g, ''))) out.push('a double space');
  if (/\s[,.;:](\s|$)/.test(s)) out.push('a space before punctuation');
  for (const m of s.matchAll(/\b([A-Za-z]{2,}) \1\b/g)) if (!/^(that|had)$/i.test(m[1]) && !/^[A-Z]+$/.test(m[1])) out.push('the word "' + m[1] + '" twice');
  for (const m of s.matchAll(/(^|[^\w'])(a|an) ([\w'-]+)/g)) { const w = m[3]; if (m[2] === 'a' && VOWEL.test(w) && !CONS.test(w)) out.push('"a ' + w + '"'); if (m[2] === 'an' && CONS.test(w) && !VOWEL.test(w)) out.push('"an ' + w + '"'); }
  if (/(^|[\s(=·])-\d/.test(s)) out.push('a hyphen used as a minus sign');
  if (/\.\.|\.…|…\./.test(s)) out.push('doubled full stops');
  if (/undefined|NaN|\[object/.test(s)) out.push('a broken value');
  return out;
}

// ---- random valid inputs ----
const WORDS = S.Classic.letters(S.Classic.corpus.text()).length ? S.Classic.corpus.text().toUpperCase().replace(/[^A-Z ]/g, ' ').split(/\s+/).filter((w) => w.length > 1) : [];
const phrase = (r, maxLetters) => { let s = ''; for (;;) { const w = WORDS[Math.floor(r() * WORDS.length)]; if ((s + w).replace(/ /g, '').length > maxLetters) return s.trim() || w.slice(0, maxLetters); s += w + ' '; } };
const pick = (r, xs) => xs[Math.floor(r() * xs.length)];
const word = (r, n) => Array.from({ length: n }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(r() * 26)]).join('');
const orders = ['I II III', 'IV I III', 'II V I', 'III I II', 'V IV II', 'I III V'];
const plugs = (r, n) => { const ls = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split(''); for (let i = 25; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [ls[i], ls[j]] = [ls[j], ls[i]]; } return Array.from({ length: n }, (_, i) => ls[2 * i] + ls[2 * i + 1]).join(' '); };
const RANDOM = {
  'p01-shift': (r) => ({ text: phrase(r, 40), k: Math.floor(r() * 26), dir: pick(r, ['enc', 'dec']) }),
  'p01-brute-shift': (r) => { const k = Math.floor(r() * 26), p = phrase(r, 60 + Math.floor(r() * 40)); return { text: S.Classic.shift.encrypt(p, k).out, truth: k }; },
  'p01-affine': (r) => ({ a: 1 + Math.floor(r() * 25), b: Math.floor(r() * 26), text: phrase(r, 30) }),
  'p01-substitution': (r) => ({ word: phrase(r, 14), cont: pick(r, ['a', 'after']), text: phrase(r, 30) }),
  'p01-kerckhoffs': (r) => ({ rate: pick(r, ['6', '9', '12']), vlen: 1 + Math.floor(r() * 20) }),
  'p01-frequency': (r) => ({ src: pick(r, ['keeper', 'fair']), word: phrase(r, 12) }),
  'p01-vigenere': (r) => ({ text: phrase(r, 36), key: word(r, 1 + Math.floor(r() * 8)) }),
  'p01-autokey': (r) => ({ text: phrase(r, 36), primer: word(r, 1 + Math.floor(r() * 8)), dir: pick(r, ['enc', 'dec']) }),
  'p01-kasiski': (r) => ({ src: pick(r, ['keeper', 'fair']), key: word(r, 3 + Math.floor(r() * 9)) }),
  'p01-ioc': (r) => ({ src: pick(r, ['keeper', 'fair']), key: word(r, 2 + Math.floor(r() * 10)) }),
  'p01-column-shifts': (r) => { const k = word(r, 3 + Math.floor(r() * 8)); return { src: pick(r, ['keeper', 'fair']), key: k, len: r() < 0.8 ? k.length : 2 + Math.floor(r() * 12) }; },
  'p01-columnar': (r) => ({ text: phrase(r, 30), key: word(r, 4 + Math.floor(r() * 5)), pad: pick(r, ['no', 'X']), dir: 'enc' }),
  'p01-railfence': (r) => ({ text: phrase(r, 30), rails: 2 + Math.floor(r() * 5), dir: pick(r, ['enc', 'dec']) }),
  'p01-playfair': (r) => ({ key: phrase(r, 12), text: phrase(r, 26), dir: 'enc' }),
  'p01-otp': (r) => { const p = phrase(r, 16), n = p.replace(/ /g, '').length; return { text: p, decoy: word(r, n), seed: 1 + Math.floor(r() * 9999) }; },
  'p01-two-time-pad': (r) => ({ m1: phrase(r, 18).toLowerCase() + ' the end', m2: phrase(r, 22).toLowerCase(), crib: ' the ', seed: 1 + Math.floor(r() * 999) }),
  'p01-enigma-path': (r) => ({ order: pick(r, orders), rings: word(r, 3), window: word(r, 3), plugs: plugs(r, Math.floor(r() * 11)), key: word(r, 1) }),
  'p01-enigma-stepping': (r) => ({ order: pick(r, orders), window: word(r, 3), presses: 2 + Math.floor(r() * 11) }),
  'p01-enigma-plugboard': (r) => ({ plugs: plugs(r, 1 + Math.floor(r() * 13)), keys: word(r, 1 + Math.floor(r() * 5)) }),
  'p01-enigma-noself': (r) => ({ order: pick(r, orders), rings: word(r, 3), window: word(r, 3), plugs: plugs(r, Math.floor(r() * 11)), key: word(r, 1) }),
  'p01-rejewski': (r) => ({ order: pick(r, orders), rings: 'AAA', window: word(r, 3), plugs: plugs(r, 6 + Math.floor(r() * 5)), n: 40 + Math.floor(r() * 120) }),
  'p01-crib-align': (r) => { const p = S.Classic.letters(S.P1.EN.plain), a = Math.floor(r() * 30), n = 6 + Math.floor(r() * 12); return { crib: p.slice(a, a + n) }; },
  'p01-bombe-menu': (r) => { const p = S.Classic.letters(S.P1.EN.plain), n = 8 + Math.floor(r() * 12), a = Math.floor(r() * (p.length - n)); return { crib: p.slice(a, a + n), offset: a }; },
};
const SLOW = new Set(['p01-substitution-solver', 'p01-bombe-deduce', 'p01-bombe-stop']);

const rnd = rng(19181939);
let runs = 0;
for (const tp of S.topics) {
  if (!tp.id.startsWith('p01-')) continue;
  if (only.length && !only.some((o) => tp.id.startsWith(o))) continue;
  const check = CHECKS[tp.id];
  t.ok(!!check, 'no claim check for ' + tp.id);
  const inputs = [{}].concat((tp.presets || []).map((p) => p.values));
  const gen = RANDOM[tp.id];
  if (gen && !SLOW.has(tp.id)) for (let k = 0; k < 12; k++) inputs.push(gen(rnd));
  for (const v of inputs) {
    const input = S.inputOf(tp, Object.assign(S.inputOf(tp), v));
    if (v.truth !== undefined) input.truth = v.truth;
    if (S.checkInput(tp, input)) continue;
    const js = JSON.stringify(v), tag = tp.id + ' ' + (js.length > 80 ? js.slice(0, 77) + '…}' : js);
    const r = S.run(tp, input); runs++;
    t.ok(r.ok, tag + ': ' + (r.error || ''));
    if (!r.ok) continue;
    r.frames.forEach((f, i) => {
      for (const w of wording(f.say)) t.ok(false, tag + ' frame ' + i + ': ' + w + ': ' + f.say);
      if (f.predict) for (const w of wording(f.predict.ask)) t.ok(false, tag + ' frame ' + i + ' prediction: ' + w);
      t.ok(true);
    });
    let claims = 0;
    const x = {
      input, F: r.frames,
      pass: () => t.ok(true),
      ok: (c, what) => t.ok(!!c, tag + ': ' + what),
      eq: (got, want, what) => (claims++, t.ok(String(got) === String(want), tag + ': ' + what + ': the narration says ' + got + ', it should be ' + want)),
      near: (got, want, tol, what) => (claims++, t.ok(Math.abs(got - want) <= tol, tag + ': ' + what + ': the narration says ' + got + ', it should be ' + want)),
      match: (say, re, fn, optional) => { const m = re.exec(String(say)); if (m) fn(m); else if (!optional) t.ok(false, tag + ': cannot read ' + re + ' in "' + String(say).slice(0, 160) + '"'); },
    };
    try { if (check) check(x); } catch (e) { t.ok(false, tag + ': the claim check fails: ' + (e.stack || e.message).split('\n').slice(0, 3).join(' ')); }
    if (!claims && !/stop/.test(tp.id)) t.ok(false, tag + ': no value in the narration was checked');
  }
}
console.log('  ' + runs + ' runs');
t.done();
