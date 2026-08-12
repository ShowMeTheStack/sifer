// Part 1 claims, the Enigma wing: windows, lamps, swaps, cycles and Bombe verdicts checked against the plain Enigma of
// ref.mjs and against the planted key the Bombe is meant to recover.
import * as R from './ref.mjs';
const { ABC, L } = R;
const all = (re, s) => [...String(s).matchAll(re)];
const cfgOf = (inp) => ({ order: String(inp.order).trim().toUpperCase().split(/[\s,]+/), rings: String(inp.rings || 'AAA').trim().toUpperCase(), window: String(inp.window).trim().toUpperCase(), plugs: inp.plugs || '' });

export function enigmaChecks(S) {
  const P = S.P1;
  const scenario = () => { const k = P.EN.key; return { key: k, plain: L(P.EN.plain), ct: R.enigma(k).run(P.EN.plain) }; };
  return {
    'p01-enigma-path'(x) {
      const cfg = cfgOf(x.input), m = R.enigma(cfg), before = m.window, k = L(x.input.key), out = m.press(k);
      const all3 = x.F.map((f) => f.say).join(' ');
      x.match(all3, /The window moves from ([A-Z]{3}) to ([A-Z]{3})/, (q) => { x.eq(q[1], before, 'window before'); x.eq(q[2], m.window, 'window after'); });
      x.match(all3, /Key ([A-Z]) lights lamp ([A-Z])/, (q) => { x.eq(q[1], k, 'key'); x.eq(q[2], out, 'lamp'); });
      x.match(all3, /The whole journey: ([A-Z → ]+)\./, (q) => { const steps = q[1].split(' → '); x.eq(steps[steps.length - 1], out, 'journey ends at the lamp'); });
      const back = R.enigma(cfg); back.step(); x.eq(ABC[back.through(ABC.indexOf(out))], k, 'the path runs backwards');
    },
    'p01-enigma-stepping'(x) {
      const cfg = { order: String(x.input.order).trim().toUpperCase().split(/[\s,]+/), window: String(x.input.window).trim().toUpperCase() }, m = R.enigma(cfg);
      for (const f of x.F) x.match(f.say, /^Press (\d+)\..*The window moves from ([A-Z]{3}) to ([A-Z]{3})/, (q) => { const b = m.window, s = m.step(); x.eq(q[2], b, 'press ' + q[1] + ' before'); x.eq(q[3], m.window, 'press ' + q[1] + ' after'); x.eq(/double step/.test(f.say), s[0], 'double step named exactly when the left rotor moves'); }, true);
      x.match(x.F[x.F.length - 1].say, /a full cycle takes ([\d,]+) presses/, (q) => { const c = R.enigma(cfg), start = c.window; let n = 0; const seen = new Set(); do { c.step(); n++; if (seen.has(c.window)) break; seen.add(c.window); } while (c.window !== start && n < 20000); x.eq(+q[1].replace(/,/g, ''), c.window === start ? n : seen.size, 'period'); });
    },
    'p01-enigma-plugboard'(x) {
      const base = { order: ['IV', 'I', 'III'], rings: 'AAA', window: 'BXC' }, a = R.enigma(Object.assign({ plugs: x.input.plugs }, base)), b = R.enigma(Object.assign({ plugs: '' }, base));
      const pairs = String(x.input.plugs).toUpperCase().trim().split(/\s+/).filter(Boolean);
      for (const f of x.F) x.match(f.say, /^Key ([A-Z]) at window ([A-Z]{3}): .* turns [A-Z] into ([A-Z])\. Without cables the rotors alone would give \1 → ([A-Z])\./, (q) => { const o1 = a.press(q[1]), o2 = b.press(q[1]); x.eq(q[2], a.window, 'window'); x.eq(q[3], o1, 'lamp with cables'); x.eq(q[4], o2, 'lamp without'); }, true);
      x.match(x.F[x.F.length - 1].say, /= ([\d,]+) ways to plug them/, (q) => { const n = pairs.length; x.eq(q[1].replace(/,/g, ''), String(R.fact(26) / (R.fact(26 - 2 * n) * R.fact(n) * 2n ** BigInt(n))), 'plugboard count'); });
    },
    'p01-enigma-noself'(x) {
      const cfg = cfgOf(x.input), m = R.enigma(cfg); m.step(); const p = m.perm(), all3 = x.F.map((f) => f.say).join(' ');
      x.ok(p.every((v, i) => v !== i && p[v] === i), 'the reference machine is a fixed-point-free involution');
      x.match(all3, /a set of 13 swaps: ([A-Z ]+)\./, (q) => { for (const pr of q[1].trim().split(' ')) x.eq(ABC[p[ABC.indexOf(pr[0])]], pr[1], 'swap ' + pr); });
      x.match(all3, /Over ([\d,]+) letters of text, Enigma never once .*: (\d+) matches/, (q) => { const t = L(S.Classic.corpus.text()).slice(0, +q[1].replace(/,/g, '')), c = R.enigma(cfg).run(t); x.eq(+q[2], Array.from(t).filter((ch, i) => ch === c[i]).length, 'self matches'); });
    },
    'p01-rejewski'(x) {
      const cfg = cfgOf(x.input), m = R.enigma(cfg), A = []; for (let k = 0; k < 6; k++) { m.step(); A.push(m.perm()); }
      const prod = (a, d) => Array.from(ABC, (c, i) => d[a[i]]), AD = prod(A[0], A[3]), BE = prod(A[1], A[4]), CF = prod(A[2], A[5]);
      const all3 = x.F.map((f) => f.say).join(' ');
      x.match(all3, /AD: ([\d ]+?)  BE: ([\d ]+?)  CF: ([\d ]+?)\./, (q) => { x.eq(q[1], R.cycleLengths(AD).join(' '), 'AD lengths'); x.eq(q[2], R.cycleLengths(BE).join(' '), 'BE lengths'); x.eq(q[3], R.cycleLengths(CF).join(' '), 'CF lengths'); });
      for (const q of all(/the product AD takes ([A-Z]) to ([A-Z])/g, all3)) x.eq(ABC[AD[ABC.indexOf(q[1])]], q[2], 'AD(' + q[1] + ')');
      const n = R.enigma(Object.assign({}, cfg, { plugs: '' })), B = []; for (let k = 0; k < 6; k++) { n.step(); B.push(n.perm()); }
      x.match(all3, /Without cables AD has cycles of lengths ([\d ]+);/, (q) => x.eq(q[1], R.cycleLengths(prod(B[0], B[3])).join(' '), 'AD without cables'));
    },
    'p01-crib-align'(x) {
      const { ct } = scenario(), c = ct.slice(0, 44), crib = L(x.input.crib);
      for (const f of x.F) x.match(f.say, /^At offset (\d+) (no crib letter faces itself|the crib's)/, (q) => { const off = +q[1]; const clash = Array.from(crib).some((ch, i) => c[off + i] === ch); x.eq(q[2] !== 'no crib letter faces itself', clash, 'clash at ' + off); }, true);
    },
    'p01-bombe-menu'(x) {
      const { ct } = scenario(), crib = L(x.input.crib), off = x.input.offset, all3 = x.F.map((f) => f.say).join(' ');
      for (const q of all(/([A-Z])–([A-Z]) \((\d+)\)/g, all3)) { const i = q[3] - 1; x.eq(q[1] + q[2], crib[i] + ct[off + i], 'pair ' + q[3]); }
      // the largest group, worked out again: letters, edges and loops
      const adj = {}; for (let i = 0; i < crib.length; i++) { const a = crib[i], b = ct[off + i]; (adj[a] = adj[a] || []).push(b); (adj[b] = adj[b] || []).push(a); }
      const seen = new Set(), groups = [];
      for (const s of Object.keys(adj)) { if (seen.has(s)) continue; const g = [], st = [s]; seen.add(s); while (st.length) { const v = st.pop(); g.push(v); for (const w of adj[v]) if (!seen.has(w)) { seen.add(w); st.push(w); } } const e = g.reduce((t, v) => t + adj[v].length, 0) / 2; groups.push({ n: g.length, e, loops: e - g.length + 1 }); }
      groups.sort((a, b) => b.loops - a.loops || b.e - a.e);
      x.match(all3, /the largest has (\d+) letters, (\d+) edges and (\d+) loops?/, (q) => { x.eq(+q[1], groups[0].n, 'letters'); x.eq(+q[2], groups[0].e, 'edges'); x.eq(+q[3], groups[0].loops, 'loops'); });
    },
    'p01-bombe-stop'(x) {
      const all3 = x.F.map((f) => f.say).join(' '), sc = scenario();
      if (x.input.case === 'right') x.ok(/A stop\./.test(all3) && /Only wire [A-Z] is live/.test(all3), 'the right guess at the right position is a consistent stop');
      if (x.input.case === 'wrong') x.match(all3, /the true stecker of ([A-Z]) is among the dark ones \(([A-Z, ]+)\)/, (q) => { const sig = {}; for (const pr of sc.key.plugs.split(' ')) { sig[pr[0]] = pr[1]; sig[pr[1]] = pr[0]; } x.ok(q[2].split(', ').includes(sig[q[1]] || q[1]), 'the true partner of ' + q[1] + ' is dark'); });
      if (x.input.case === 'away') x.ok(/All 26 wires of register [A-Z] are live/.test(all3), 'a wrong position floods the register');
      for (const q of all(/Scrambler (\d+) carries ([A-Z]) on ([A-Z]) to ([A-Z]) on ([A-Z])\./g, all3)) {
        // the scrambler at crib position i: rotors without plugboard, fast drum stepped i + 1 from the Bombe position
        const pos = (all3.match(/at ([A-Z]{3})[,;]/) || [])[1], i = q[1] - 1;
        const m = R.enigma({ order: sc.key.order, rings: 'AAA', window: pos.slice(0, 2) + ABC[(ABC.indexOf(pos[2]) + i + 1) % 26], plugs: '' });
        x.eq(ABC[m.through(ABC.indexOf(q[2]))], q[4], 'scrambler ' + q[1]);
      }
    },
    'p01-bombe-deduce'(x) {
      const sc = scenario(), sig = {}, all3 = x.F.map((f) => f.say).join(' ');
      for (const pr of sc.key.plugs.split(' ')) { sig[pr[0]] = pr[1]; sig[pr[1]] = pr[0]; }
      for (const q of all(/cable ([A-Z])–([A-Z])\./g, all3)) x.eq(sig[q[1]], q[2], 'cable ' + q[1] + q[2]);
      for (const q of all(/: ([A-Z]) has no cable\./g, all3)) x.eq(sig[q[1]], undefined, q[1] + ' unplugged');
      x.match(all3, /Key: rotors ([IV ]+), UKW-B, rings ([A-Z]{3}), start ([A-Z]{3}), cables ([A-Z ]+)\. .*? (\d+) of (\d+) letters match/, (q) => {
        const plain = R.enigma({ order: q[1].trim().split(' '), rings: q[2], window: q[3], plugs: q[4] }).run(sc.ct);
        x.eq(+q[5], Array.from(plain).filter((c, i) => c === sc.plain[i]).length, 'letters right with the recovered key'); x.eq(+q[6], sc.plain.length, 'message length');
      });
    },
  };
}
