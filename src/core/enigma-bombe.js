// The Bombe for Enigma I: for every rotor order and every drum position, the scramblers of the menu are wired
// together through the diagonal board, one hypothesis is put on the test register, and the current spreads. A
// position where the current does not reach all 26 wires of the register is a stop; a stop survives when some
// stecker for the register letter gives a self-consistent plugboard.
//   S.Enigma.bombe.job({crib, cipher, offset, rotors | orders, reflector, stepping, rings}) -> job
//     job.run(budgetMs) -> {done, progress, order, tested, newStops}; job.stops; job.cancel()
//     stepping 'fast' (the real Bombe: only the fast drum moves over the crib; positions are cores, rings at A)
//              'full' (the full lever stepping with the given rings, which also finds a turnover inside the crib)
//   S.Enigma.bombe.runAll(params)          -> {stops, tested, ms}
//   S.Enigma.bombe.test(params, order, pos, hypothesis) -> the diagonal-board spread at one position, step by step
//   S.Enigma.bombe.drums(params, order, pos) -> the drum positions of each scrambler of the menu
//   S.Enigma.bombe.serve(scope)            -> answers {cmd:'start', params} / {cmd:'cancel'} messages in a Web Worker
// Checking a stop (plugboard deduction, decryption, ring settings) is in enigma-check.js.
(function (S) {
  'use strict';
  const E = (S.Enigma = S.Enigma || {});
  const B = (E.bombe = E.bombe || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', N = 26;
  const md = (n) => ((n % 26) + 26) % 26;
  const I = (c) => c.charCodeAt(0) - 65;
  const { now } = Date;

  B.orders = (rotors = ['I', 'II', 'III', 'IV', 'V']) => { const out = []; for (const a of rotors) for (const b of rotors) for (const c of rotors) if (a !== b && b !== c && a !== c) out.push([a, b, c]); return out; };

  /** table[((l·26 + m)·26 + r)·26 + c]: the scrambler (three rotors with cores at l, m, r, and the reflector) on input c */
  B.scramblerTable = (order, reflector) => {
    const W = order.map(E.wheel), U = E.wheel(E.reflectorId(reflector)).fwd, sf = [], sb = [];
    for (const w of W) {
      const f = new Uint8Array(676), b = new Uint8Array(676);
      for (let p = 0; p < N; p++) for (let c = 0; c < N; c++) { f[p * N + c] = md(w.fwd[(c + p) % N] - p); b[p * N + c] = md(w.bwd[(c + p) % N] - p); }
      sf.push(f); sb.push(b);
    }
    const [fL, fM, fR] = sf, [bL, bM, bR] = sb, table = new Uint8Array(N * N * N * N);
    for (let l = 0; l < N; l++) { const lo = l * N; for (let m = 0; m < N; m++) { const mo = m * N; for (let r = 0; r < N; r++) {
      const ro = r * N, base = ((l * N + m) * N + r) * N;
      for (let c = 0; c < N; c++) table[base + c] = bR[ro + bM[mo + bL[lo + U[fL[lo + fM[mo + fR[ro + c]]]]]]];
    } } }
    return table;
  };

  /** the menu's scramblers as flat arrays: for letter L the edges eOther/eIdx[eStart[L] .. eStart[L+1]) */
  function flatten(menu) {
    const per = Array.from({ length: N }, () => []);
    menu.edges.forEach((e, k) => { per[I(e.a)].push([I(e.b), k]); per[I(e.b)].push([I(e.a), k]); });
    const eStart = new Int32Array(N + 1); let k = 0;
    for (let l = 0; l < N; l++) { eStart[l] = k; k += per[l].length; } eStart[N] = k;
    const eOther = new Int32Array(k), eIdx = new Int32Array(k); k = 0;
    for (let l = 0; l < N; l++) for (const [o, j] of per[l]) { eOther[k] = o; eIdx[k] = j; k++; }
    return { eStart, eOther, eIdx };
  }

  /** the propagation engine for one menu: stamps instead of clearing, a stack of wires, per-letter counts */
  function engine(menu, reg) {
    const { eStart, eOther, eIdx } = flatten(menu);
    const stamp = new Uint32Array(N * N), stack = new Int32Array(N * N), lstamp = new Uint32Array(N), lcount = new Uint8Array(N);
    let gen = 0;
    const eng = {
      table: null, offs: new Int32Array(menu.edges.length), live: stamp,
      get gen() { return gen; },
      /** spread from (reg, v). mode 0: stop early when the register is full (returns 26); mode 1: stop early on a
       *  letter with two live wires (returns −1); otherwise returns the number of live register wires */
      spread(v, mode) {
        gen++; if (gen === 0xffffffff) { stamp.fill(0); lstamp.fill(0); gen = 1; }
        const table = eng.table, offs = eng.offs;
        let sp = 0, regCount = 0;
        const start = reg * N + v; stamp[start] = gen; stack[sp++] = start; regCount = 1; lstamp[reg] = gen; lcount[reg] = 1;
        while (sp) {
          const w = stack[--sp], L = (w / N) | 0, val = w - L * N;
          const d = val * N + L;
          if (stamp[d] !== gen) {
            stamp[d] = gen; stack[sp++] = d;
            if (lstamp[val] !== gen) { lstamp[val] = gen; lcount[val] = 1; } else if (++lcount[val] > 1 && mode === 1) return -1;
            if (val === reg && ++regCount === N && mode === 0) return N;
          }
          for (let k = eStart[L], end = eStart[L + 1]; k < end; k++) {
            const o = eOther[k], w2 = o * N + table[offs[eIdx[k]] + val];
            if (stamp[w2] !== gen) {
              stamp[w2] = gen; stack[sp++] = w2;
              if (lstamp[o] !== gen) { lstamp[o] = gen; lcount[o] = 1; } else if (++lcount[o] > 1 && mode === 1) return -1;
              if (o === reg && ++regCount === N && mode === 0) return N;
            }
          }
        }
        return regCount;
      },
      /** the live wires of the last spread as a 26×26 boolean grid */
      grid() { const g = []; for (let l = 0; l < N; l++) { const row = []; for (let v = 0; v < N; v++) row.push(stamp[l * N + v] === gen); g.push(row); } return g; },
      /** the steckers of the last (consistent) spread: letter → partner */
      partners() { const p = {}; for (let l = 0; l < N; l++) for (let v = 0; v < N; v++) if (stamp[l * N + v] === gen) p[ABC[l]] = ABC[v]; return p; },
    };
    return eng;
  }

  /** the loops of the menu as conditions: a spanning tree from the register, and for each edge outside it the tree
   *  paths (as edge numbers) from the register to its two ends; shortest loops first */
  function loopPlan(sub, reg) {
    const adj = Array.from({ length: N }, () => []);
    sub.edges.forEach((e, k) => { adj[I(e.a)].push([I(e.b), k]); adj[I(e.b)].push([I(e.a), k]); });
    const path = { [reg]: [] }, tree = new Set(), q = [reg];
    while (q.length) { const x = q.shift(); for (const [y, k] of adj[x]) if (!(y in path)) { path[y] = path[x].concat([k]); tree.add(k); q.push(y); } }
    const out = [];
    sub.edges.forEach((e, k) => { if (!tree.has(k) && I(e.a) in path) out.push({ k, pu: path[I(e.a)], pv: path[I(e.b)] }); });
    return out.sort((x, y) => x.pu.length + x.pv.length - y.pu.length - y.pv.length);
  }

  /** the drum positions for crib letter i (0-based), as table offsets, from a start position */
  function cribOffsets(mode, start, rings, notchM, notchR, n, out) {
    if (mode === 'fast') { const [l, m, r] = start; for (let i = 0; i < n; i++) out[i] = ((l * N + m) * N + ((r + i + 1) % N)) * N; return out; }
    let w = start.slice();
    for (let i = 0; i < n; i++) { w = E.advance(w, notchM, notchR); out[i] = ((md(w[0] - rings[0]) * N + md(w[1] - rings[1])) * N + md(w[2] - rings[2])) * N; }
    return out;
  }
  const posText = (p) => p.map((x) => ABC[x]).join('');
  function setup(params) {
    const menu = params.menu || B.menu(params.crib, params.cipher, params.offset || 0);
    if (menu.clashes.length) throw new Error('the crib faces itself at this offset, so it cannot be here');
    if (!menu.register) throw new Error('the crib gives no menu');
    const mode = params.stepping === 'full' ? 'full' : 'fast';
    const rings = mode === 'full' ? E.machine({ rings: params.rings || 'AAA' }).rings : [0, 0, 0];
    const reflector = E.reflectorId(params.reflector || 'B');
    const reg = I(params.register || menu.register);
    // only edges of the register's component can carry current from it
    const comp = menu.components.find((c) => c.letters.includes(ABC[reg]));
    const edges = menu.edges.filter((e) => comp.letters.includes(e.a));
    const sub = Object.assign({}, menu, { edges });
    return { menu, sub, mode, rings, reflector, reg };
  }

  B.job = (params) => {
    const st = setup(params), { sub, mode, rings, reflector, reg } = st;
    const orders = params.orders || B.orders(params.rotors), simulate = !!params.simulate;
    const eng = engine(sub, reg), n = sub.edges.length, cribIdx = sub.edges.map((e) => e.i), maxI = Math.max(...cribIdx) + 1;
    const offsAll = new Int32Array(maxI), stops = [], total = orders.length * 17576, lp = loopPlan(sub, reg);
    let oi = 0, p = 0, tested = 0, raw = 0, cancelled = false, notchM = -1, notchR = -1;
    const load = () => { const o = orders[oi]; eng.table = B.scramblerTable(o, reflector); notchM = E.wheel(o[1]).notch; notchR = E.wheel(o[2]).notch; };
    // the loop test: a stecker s for the register survives only if, carried along the spanning tree, it closes every
    // loop. Any hypothesis the diagonal board finds consistent passes it, so it only saves the hopeless ones.
    const passes = (s) => {
      const table = eng.table, offs = eng.offs;
      for (let j = 0; j < lp.length; j++) {
        const q = lp[j]; let a = s, b = s;
        for (let t = 0; t < q.pu.length; t++) a = table[offs[q.pu[t]] + a];
        for (let t = 0; t < q.pv.length; t++) b = table[offs[q.pv[t]] + b];
        if (table[offs[q.k] + a] !== b) return false;
      }
      return true;
    };
    const record = (order, start, v, cnt) => {
      const partners = eng.partners(), pairs = [], seen = new Set();
      for (const a of Object.keys(partners).sort()) { const b = partners[a]; if (seen.has(a)) continue; seen.add(a); seen.add(b); pairs.push([a, b]); }
      return { order: order.slice(), pos: posText(start), mode, rings: posText(rings), reflector, register: ABC[reg], hypothesis: ABC[v], steckers: pairs, lit: cnt };
    };
    const job = {
      menu: st.menu, register: ABC[reg], mode, total, stops, orders,
      get tested() { return tested; },
      get rawStops() { return raw; },
      cancel() { cancelled = true; },
      run(budget = 50) {
        const t0 = now(), newStops = [];
        while (!cancelled && oi < orders.length) {
          if (p === 0) load();
          const order = orders[oi];
          for (; p < 17576; p++) {
            const start = [(p / 676) | 0, ((p / 26) | 0) % 26, p % 26];
            cribOffsets(mode, start, rings, notchM, notchR, maxI, offsAll);
            for (let k = 0; k < n; k++) eng.offs[k] = offsAll[cribIdx[k]];
            tested++;
            if (!simulate) {
              for (let v = 0; v < N; v++) if (passes(v) && eng.spread(v, 1) >= 0) { const s = record(order, start, v, 0); stops.push(s); newStops.push(s); }
            } else {
              // the machine itself: one hypothesis on the register, current everywhere it can reach
              const cnt = eng.spread(0, 0);
              if (cnt === N) continue;
              raw++;
              const lit = eng.grid()[reg];
              for (let v = 0; v < N; v++) if ((!lit[v] || cnt === 1) && eng.spread(v, 1) >= 0) { const s = record(order, start, v, cnt); stops.push(s); newStops.push(s); }
            }
            if ((p & 255) === 255 && now() - t0 > budget) { p++; return job.status(newStops); }
          }
          p = 0; oi++;
          if (now() - t0 > budget) break;
        }
        return job.status(newStops);
      },
      status(newStops) { return { done: cancelled || oi >= orders.length, progress: tested / total, order: orders[Math.min(oi, orders.length - 1)], tested, rawStops: raw, stops: stops.length, newStops }; },
    };
    return job;
  };
  B.runAll = (params) => { const t0 = now(), j = B.job(params); let r; do r = j.run(1e9); while (!r.done); return { stops: j.stops, tested: j.tested, rawStops: j.rawStops, ms: now() - t0, register: j.register, menu: j.menu }; };

  /** the drums of every scrambler of the menu at one Bombe position, as window letters */
  B.drums = (params, order, pos) => {
    const st = setup(params), w = E.wheel(order[1]), r = E.wheel(order[2]), maxI = Math.max(...st.menu.edges.map((e) => e.i)) + 1;
    const offs = cribOffsets(st.mode, Array.from(pos, I), st.rings, w.notch, r.notch, maxI, new Int32Array(maxI));
    return st.menu.edges.map((e) => { const o = offs[e.i] / N; return { edge: e, drums: posText([(o / 676) | 0, ((o / 26) | 0) % 26, o % 26]) }; });
  };

  /** one position in slow motion: every wire that lights, and why (an edge's scrambler or the diagonal board) */
  B.test = (params, order, pos, hypothesis) => {
    const st = setup(params), { sub, reg } = st, table = B.scramblerTable(order, st.reflector);
    const maxI = Math.max(...sub.edges.map((e) => e.i)) + 1;
    const offs = cribOffsets(st.mode, Array.from(pos, I), st.rings, E.wheel(order[1]).notch, E.wheel(order[2]).notch, maxI, new Int32Array(maxI));
    const v0 = hypothesis == null ? 0 : I(hypothesis), live = new Uint8Array(676), events = [], queue = [];
    const light = (w, why) => { if (live[w]) return; live[w] = 1; queue.push(w); events.push({ letter: ABC[(w / N) | 0], value: ABC[w % N], why }); };
    light(reg * N + v0, { by: 'hypothesis' });
    for (let q = 0; q < queue.length; q++) {
      const w = queue[q], L = (w / N) | 0, v = w % N;
      light(v * N + L, { by: 'diagonal', from: ABC[L] + ABC[v] });
      for (const e of sub.edges) {
        if (I(e.a) !== L && I(e.b) !== L) continue;
        const other = I(e.a) === L ? I(e.b) : I(e.a);
        light(other * N + table[offs[e.i] + v], { by: 'scrambler', edge: e.i, from: ABC[L] + ABC[v] });
      }
    }
    const regLive = []; for (let v = 0; v < N; v++) if (live[reg * N + v]) regLive.push(ABC[v]);
    const grid = []; for (let l = 0; l < N; l++) grid.push(Array.from(live.slice(l * N, l * N + N), Boolean));
    const per = grid.map((r) => r.filter(Boolean).length), consistent = per.every((c) => c <= 1);
    const trace = [step('bombe-hypothesis', `Assume ${ABC[reg]} is steckered to ${ABC[v0]}: put current on wire ${ABC[v0]} of register ${ABC[reg]}.`, { register: ABC[reg], value: ABC[v0] })];
    for (const ev of events.slice(1, 80)) trace.push(step('bombe-wire', ev.why.by === 'diagonal' ? `Diagonal board: ${ev.why.from[0]}↔${ev.why.from[1]} means ${ev.letter}↔${ev.value}, so wire ${ev.value} of ${ev.letter} lights.` : `Scrambler ${ev.why.edge + 1} carries ${ev.why.from[1]} on ${ev.why.from[0]} to ${ev.value} on ${ev.letter}.`, ev));
    trace.push(step('bombe-verdict', regLive.length === N ? `All 26 wires of register ${ABC[reg]} are live: every stecker for ${ABC[reg]} leads to a contradiction, so the drums move on.` : regLive.length === 1 ? `Only wire ${regLive[0]} is live at the register: the assumption holds together. A stop.` : `${regLive.length} wires are live and ${N - regLive.length} dark at the register: a stop; the true stecker of ${ABC[reg]} is among the dark ones (${ABC.split('').filter((c) => !regLive.includes(c)).join(', ')}).`, { regLive, consistent }));
    return { grid, events, regLive, consistent, stop: regLive.length < N, trace };
  };

  /** Web Worker glue: post {cmd:'start', params, slice} to run, {cmd:'cancel'} to stop; replies progress and done */
  B.serve = (scope) => {
    let job = null;
    scope.onmessage = (ev) => {
      const d = ev.data || {};
      if (d.cmd === 'cancel') { if (job) job.cancel(); job = null; return; }
      if (d.cmd !== 'start') return;
      try { job = B.job(d.params); } catch (err) { scope.postMessage({ type: 'error', message: err.message }); return; }
      const mine = job;
      const tick = () => {
        if (job !== mine) return;
        const r = mine.run(d.slice || 100);
        scope.postMessage({ type: 'progress', progress: r.progress, order: r.order, tested: r.tested, rawStops: r.rawStops, newStops: r.newStops });
        if (r.done) { scope.postMessage({ type: 'done', stops: mine.stops, tested: mine.tested }); job = null; } else setTimeout(tick, 0);
      };
      tick();
    };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
