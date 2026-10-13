// The screenshots in the README: node tools/readme-shots.mjs [name ...] [--built] [--base=url] [--list]
// Drives the page in headless Chrome and writes docs/images/<name>.png: 1600×950 in the light theme, one shot in
// the dark theme and one on a phone at 390×844. Each shot stops on a frame part of the way through, where the
// picture has something to say. With names, only those shots are taken again; --list prints the names.
// By default it uses dev.html (every source file on its own, no build needed); --built builds index.html first and
// shoots that, as the site serves it; --base= points it at a page served elsewhere. Prints console errors per shot.
import { launch } from './cdp.mjs';
import { execSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const built = process.argv.includes('--built');
if (built) execSync('node build.mjs', { cwd: root, stdio: 'ignore' });
mkdirSync(join(root, 'docs/images'), { recursive: true });
const out = (n) => join(root, 'docs/images', n + '.png');
const only = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const base = (process.argv.find((a) => a.startsWith('--base=')) || '').slice(7);
const W = [1600, 950], PHONE = [390, 844];

const wait = (ms) => `await new Promise((r) => setTimeout(r, ${ms}));`;
// wait for an expression to come true inside the page
const until = (expr, ms = 20000) => `await new Promise((r, j) => { const t0 = Date.now(); const w = () => { let ok = false; try { ok = (${expr}); } catch (e) { /* not yet */ } if (ok) r(); else if (Date.now() - t0 > ${ms}) j(new Error('timed out: ' + ${JSON.stringify(expr)})); else setTimeout(w, 40); }; w(); });`;
// the box that scrolls the page, whichever it is
const SC = `[document.getElementById('main'), document.scrollingElement].find((x) => x && x.scrollHeight > x.clientHeight + 2)`;
// scroll the page so an element sits just under the top bar
const scrollTo = (sel, pad = 12) => `{ const e = document.querySelector(${JSON.stringify(sel)}); if (e) { const bar = document.getElementById('top'); const off = (bar ? bar.getBoundingClientRect().bottom : 56) + ${pad}; const sc = ${SC}; if (sc) sc.scrollTop += e.getBoundingClientRect().top - off; } }`;
// scroll the page so an element's bottom sits just above the bottom of the screen
const bottomAt = (sel, pad = 16) => `{ const e = document.querySelector(${JSON.stringify(sel)}); const sc = ${SC}; if (e && sc) sc.scrollTop += e.getBoundingClientRect().bottom - (innerHeight - ${pad}); }`;
const click = (sel) => `{ const e = document.querySelector(${JSON.stringify(sel)}); if (!e) throw new Error('no ' + ${JSON.stringify(sel)}); e.click(); }`;
const P = 'Sifer.app.page';
// open a topic (with an optional input) and stop on a frame part of the way through (frac, or a function of the
// frames that picks the index)
const topic = (id, frac, query, extra) => ({
  hash: 'topic=' + id + (query ? '?' + Object.entries(query).map(([k, v]) => k + '=' + encodeURIComponent(JSON.stringify(v))).join('&') : ''),
  js: until(`${P} && ${P}.player && ${P}.player.frames.length > 1`, 60000) + ` const p = ${P}.player; p.pause(); const fr = p.frames; p.go(${typeof frac === 'function' ? `(${frac})(fr)` : `Math.round(${frac} * (fr.length - 1))`}, true); ${wait(250)} ${scrollTo('#inputs')} ${extra || ''}`,
});
// the frame whose narration first matches a pattern (the last frame if none does), plus an offset
const at = (re, d = 0) => `(fr) => { const i = fr.findIndex((f) => ${re}.test(String(f.say || ''))); return i < 0 ? fr.length - 1 : Math.min(fr.length - 1, i + ${d}); }`;
const bench = (tab, state, js) => ({ pre: `Sifer.Bench.preset(${JSON.stringify(tab)}, ${JSON.stringify(state)});`, hash: 'bench/' + tab, js: until(`document.querySelector('#benchBody') && document.querySelector('#benchBody').children.length`) + (js || '') });

// name: { hash, pre (before the route), js (after), size, wait ms, theme }
const SHOTS = {
  // the home page: the avalanche of AES-128 running live beside the title
  home: { hash: '', js: until(`document.querySelector('#heroArt') && /After round 2 of 10/.test(document.querySelector('#heroArt').textContent)`, 30000) + wait(250), wait: 100 },

  subbytes: topic('aes-subbytes', 0.5),
  avalanche: topic('aes-avalanche', 1),
  desf: topic('des-f', 0.5),
  chacha: topic('st-chacha-qr', 0.35),
  cbc: topic('modes-cbc', 0.6),
  gcm: topic('modes-gcm', 1, null, scrollTo('.stage-card', 4)),
  sha256: topic('p12-compress', 0.4),
  keccak: topic('p12-theta', 0.5),
  ecreal: topic('ec-real-add', 0.6),
  ecgfp: topic('ec-gfp-law', 0.6),
  sqm: topic('p08-sqm', 0.85, { size: 'rsa2048' }),
  mlkem: topic('pq-mlkem-flow', 0.5),
  cpa: topic('sc-cpa', 0.7),
  ns: topic('p13-ns', 0.92, { scenario: 'replay' }),

  // Enigma I with a message part typed and the next key held down: its lamp lit, the rotors moved on
  enigma: {
    hash: 'enigma',
    js: until(`document.querySelector('#enigDeck svg') && ${P}.ctx`) + `const c = ${P}.ctx; c.setAll({ order: ['II', 'IV', 'I'], reflector: 'B', rings: 'FKQ', start: 'RWD', window: 'RWD', plugs: 'AM BT CX EJ GU HP KS LO NZ RW' }); c.typeAll('MEETATTHEMILLATDUS'); c.press('K'); ${wait(300)}`,
    wait: 900,
  },
  // the Bombe after its run: the menu with its loops lit, the stop that survived and the key it gave
  bombe: {
    hash: 'enigma/bombe',
    js: until(`document.querySelector('#bombeMenu svg') && ${P}.view && ${P}.view.runNow`) + `await ${P}.view.runNow(); ${P}.view.solve(0); ${wait(300)} ${scrollTo('#bombeMenu', -110)}`,
    wait: 200,
  },
  // the cipher bench: AES-128 in CBC, the ladder of round states with round 3 opened
  bench: {
    hash: 'bench/cipher',
    js: until(`document.querySelector('#cbView') && ${P}.bench && ${P}.bench.set`) + `${P}.bench.set({ algo: 'aes128', mode: 'cbc', dir: 'enc', view: 'rounds', toy: false, round: 4 }); ${wait(400)} ${scrollTo('#cbDetailBox', -260)}`,
    wait: 900,
  },
  lesson: {
    hash: 'lesson=ae-sub',
    js: wait(1200) + `for (const p of (${P} && ${P}.players) || []) { p.pause(); p.go(Math.round(0.55 * (p.frames.length - 1)), true); } ${wait(300)}`,
    wait: 900,
  },
  // a code exercise: MixColumns written without the reduction by 1b, and the first test it fails
  exercise: {
    hash: 'exercise=ae-x-code-mixcol',
    pre: `const x = Sifer.Content.exercises.get('ae-x-code-mixcol'); const s = Sifer.UI.storage; const p = s.get('learn', {}); p.drafts = p.drafts || {}; p.drafts[x.id] = x.wrong[0]; s.set('learn', p);`,
    js: wait(800) + `${click('#btnCheck')} ${until(`document.querySelector('#exResult') && document.querySelector('#exResult').textContent.length > 20`)} ${wait(400)} ${bottomAt('#exResult')}`,
    wait: 900,
  },
  // the ladder most of the way up: the top rungs still ahead, the scoreboard beside them
  ctf: {
    hash: 'ctf',
    pre: `Sifer.CTF.reset(); for (const x of Sifer.Content.ladder().slice(0, -3)) Sifer.CTF.submit(x.id, x.solution);`,
    js: until(`document.querySelector('#ctfLadder')`) + wait(300),
    wait: 900,
  },
  sandbox: {
    hash: 'sandbox/quarter-round',
    js: until(`document.querySelector('#sandboxView') && ${P}.editor`) + `${P}.editor.value = 'function quarterRound(a, b, c, d) {\\n  a = (a + b) >>> 0; d ^= a; d = (d << 16) | (d >>> 16);\\n  c = (c + d) >>> 0; b ^= c; b = (b << 12) | (b >>> 20);\\n  a = (a + b) >>> 0; d ^= a; d = (d << 8) | (d >>> 24);\\n  c = (c + d) >>> 0; b ^= c; b = (b << 7) | (b >>> 25);\\n  return [a, b, c, d];\\n}\\n'; ${P}.run(); ${until(`document.querySelector('#sbResult .cases-table, #sbResult .ok, #sbResult')  && document.querySelector('#sbResult').textContent.length > 10`)} ${wait(500)}`,
    wait: 900,
  },

  dark: Object.assign(topic('aes-encrypt', 0.5), { theme: 'dark' }),
  // on a phone the case is cropped to the keys, so they stay large enough to press
  phone: {
    hash: 'enigma', size: PHONE,
    js: until(`document.querySelector('#enigDeck svg') && ${P}.ctx`) + `const c = ${P}.ctx; c.setAll({ order: ['II', 'IV', 'I'], reflector: 'B', rings: 'FKQ', start: 'RWD', window: 'RWD', plugs: 'AM BT CX EJ GU HP KS LO NZ RW' }); c.typeAll('MEETATTHEMILL'); c.press('A'); ${wait(300)} ${scrollTo('#enigDeck', 4)}`,
    wait: 900,
  },
};

if (process.argv.includes('--list')) { console.log(Object.keys(SHOTS).join(' ')); process.exit(0); }
for (const [name, s] of Object.entries(SHOTS)) {
  if (only.length && !only.includes(name)) continue;
  const size = s.size || W;
  const b = await launch({ width: size[0], height: size[1], mobile: size[0] < 600 });
  try {
    const page = base || (b.url + (built ? '' : 'dev.html'));
    await b.send('Page.navigate', { url: page + '#' });
    await b.waitFor('window.__siferReady === true', 30000);
    await b.eval(`if (Sifer.Learner) Sifer.Learner.settings.predict = false; Sifer.app.settings.projector = false; Sifer.app.settings.sound = false; Sifer.app.setTheme(${JSON.stringify(s.theme || 'light')}); ${s.pre || ''} 1`);
    await b.eval(`location.hash = ${JSON.stringify(s.hash)}; 1`);
    await b.sleep(400);
    await b.waitFor('window.__siferReady === true', 30000);
    if (s.js) await b.eval('(async () => { ' + s.js + ' })().then(() => 1)');
    await b.sleep(s.wait || 900);
    await b.eval(`for (const t of document.querySelectorAll('.toast')) t.remove(); 1`);
    await b.screenshot(out(name));
    const errs = b.logs.filter((l) => l.type === 'error' || l.type === 'exception');
    console.log(name + (errs.length ? '  (' + errs.length + ' console errors: ' + errs.map((e) => e.text.slice(0, 160)).join(' | ') + ')' : ''));
  } catch (e) {
    console.log(name + '  FAILED: ' + e.message);
  } finally { await b.close(); }
}
