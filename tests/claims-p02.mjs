// Part 2's topics (modular arithmetic, number theory, finite fields), run with every preset and random inputs. In
// every frame, each equation or congruence the narration states is worked out again with arithmetic written here,
// apart from the engines; each topic's own claims (positions, lists, tables, orders, field products) are checked
// against an independent computation and against what the frame draws; and the wording is checked.
// Prints "claims-p02 N passed, M failed". Usage: node tests/claims-p02.mjs [topic id ...]
import { load, harness, rng } from './load.mjs';
import { checkArithmetic, wording } from './claims-lib-p02.mjs';
import checks1 from './claims-p02-a.mjs';
import checks2 from './claims-p02-b.mjs';
import checks3 from './claims-p02-c.mjs';
import checks4 from './claims-p02-d.mjs';

const S = load(['core', 'stage', 'topics']);
const t = harness('claims-p02');
const only = process.argv.slice(2);
const CHECKS = Object.assign({}, checks1, checks2, checks3, checks4);
const rnd = rng(20261018);
let arith = 0;
for (const tp of S.topics) {
  if (!/^p02-/.test(tp.family)) continue;
  if (only.length && !only.some((o) => tp.id.startsWith(o))) continue;
  const c = CHECKS[tp.id];
  t.ok(!!c, tp.id + ': has no claim checks');
  const inputs = [{}].concat((tp.presets || []).map((p) => p.values));
  if (c && c.extra) inputs.push(...c.extra);
  if (c && c.random) for (let k = 0; k < (c.runs || 14); k++) inputs.push(c.random(rnd));
  for (const v of inputs) {
    const input = S.inputOf(tp, Object.assign(S.inputOf(tp), v));
    if (S.checkInput(tp, input)) { if (!c || !c.mayRefuse) t.ok(false, tp.id + ' ' + JSON.stringify(v) + ': input refused: ' + S.checkInput(tp, input)); continue; }
    const tag = tp.id + ' ' + JSON.stringify(v);
    const r = S.run(tp, input);
    t.ok(r.ok, tag + ': ' + (r.error || '') + (r.stack || '').split('\n').slice(0, 3).join(' '));
    if (!r.ok) continue;
    r.frames.forEach((f, i) => {
      for (const w of wording(f.say)) t.ok(false, tag + ' frame ' + i + ': ' + w + ': ' + f.say);
      if (f.predict) for (const w of wording(f.predict.ask)) t.ok(false, tag + ' frame ' + i + ' prediction: ' + w + ': ' + f.predict.ask);
      arith += checkArithmetic(f.say || '', (msg) => t.ok(false, tag + ' frame ' + i + ': ' + msg + ': ' + f.say), c && c.arith ? c.arith(input, f) : {});
      t.ok(true);
    });
    if (c && c.check) {
      try { c.check({ S, tp, input, frames: r.frames, r, fail: (msg) => t.ok(false, tag + ': ' + msg), ok: (cond, msg) => t.ok(cond, tag + ': ' + msg) }); }
      catch (e) { t.ok(false, tag + ': the claim check fails: ' + (e.stack || e.message).split('\n').slice(0, 3).join(' ')); }
    }
  }
}
console.log('(' + arith + ' equations and congruences worked out again)');
t.done();
