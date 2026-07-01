// The Bombe's menu: a crib is laid against the ciphertext (where no letter may face itself, since Enigma never
// encrypts a letter to itself), and every crib letter joined to its cipher letter becomes an edge of a graph whose
// loops give the Bombe its power.
//   S.Enigma.bombe.align(cipher, crib)          -> {offsets: [{offset, ok, clashes}], possible, trace}
//   S.Enigma.bombe.menu(crib, cipher, offset)   -> {edges, letters, degree, components, main, loops, register, trace}
//     edges[k] = {a: crib letter, b: cipher letter, i: crib index, pos: message position}
//     loops    = a cycle basis of the main component: [{letters: ['E','T','R','E'], edges: [crib indices]}]
(function (S) {
  'use strict';
  const E = (S.Enigma = S.Enigma || {});
  const B = (E.bombe = E.bombe || {});
  const step = (kind, say, data) => Object.assign({ kind, say }, data || {});
  const clean = (t) => String(t).toUpperCase().replace(/[^A-Z]/g, '');

  /** every place the crib could sit under the ciphertext, and the clashes that rule places out */
  B.align = (cipher, crib) => {
    const c = clean(cipher), k = clean(crib), offsets = [], trace = [];
    for (let off = 0; off + k.length <= c.length; off++) {
      const clashes = [];
      for (let i = 0; i < k.length; i++) if (k[i] === c[off + i]) clashes.push({ i, pos: off + i, letter: k[i] });
      offsets.push({ offset: off, ok: !clashes.length, clashes });
      trace.push(step(clashes.length ? 'align-clash' : 'align-ok', clashes.length ? `At offset ${off} the crib's ${clashes.map((x) => `${x.letter} (letter ${x.i + 1})`).join(', ')} would face ${clashes.length > 1 ? 'themselves' : 'itself'}, which Enigma cannot do, so the crib is not here.` : `At offset ${off} no crib letter faces itself, so the crib may be here.`, { offset: off, clashes }));
    }
    const possible = offsets.filter((o) => o.ok).map((o) => o.offset);
    trace.push(step('align-done', `${possible.length} of ${offsets.length} positions survive the no-self-encipherment rule${possible.length ? ': ' + possible.slice(0, 12).join(', ') + (possible.length > 12 ? ` and ${possible.length - 12} more` : '') : ''}.`, { possible }));
    return { offsets, possible, trace };
  };

  B.menu = (crib, cipher, offset = 0) => {
    const k = clean(crib), c = clean(cipher), edges = [], trace = [], clashes = [];
    for (let i = 0; i < k.length && offset + i < c.length; i++) {
      if (k[i] === c[offset + i]) { clashes.push(i); continue; }
      edges.push({ a: k[i], b: c[offset + i], i, pos: offset + i });
    }
    if (clashes.length) trace.push(step('menu-clash', `Crib letters ${clashes.map((i) => i + 1).join(', ')} face themselves: this alignment is impossible.`, { clashes }));
    const adj = {}, letters = [];
    for (const e of edges) for (const [x, y] of [[e.a, e.b], [e.b, e.a]]) { if (!adj[x]) { adj[x] = []; letters.push(x); } adj[x].push({ to: y, i: e.i }); }
    letters.sort();
    const degree = {}; for (const l of letters) degree[l] = adj[l].length;
    trace.push(step('menu-edges', `${edges.length} pairs from the crib: ${edges.map((e) => `${e.a}–${e.b} (${e.i + 1})`).join(', ')}. Each pair is one scrambler in the Bombe, set to its own place in the message.`, { edges }));
    // connected components
    const comp = {}, components = [];
    for (const l of letters) {
      if (comp[l] != null) continue;
      const id = components.length, members = [], stack = [l]; comp[l] = id;
      while (stack.length) { const x = stack.pop(); members.push(x); for (const { to } of adj[x]) if (comp[to] == null) { comp[to] = id; stack.push(to); } }
      const ne = edges.filter((e) => comp[e.a] === id).length;
      components.push({ id, letters: members.sort(), edges: ne, loops: ne - members.length + 1 });
    }
    components.sort((x, y) => y.loops - x.loops || y.edges - x.edges || x.id - y.id);
    const main = components[0] || { letters: [], edges: 0, loops: 0 };
    // the test register: the busiest letter of the main component (most edges, then most loops through it)
    let register = null;
    for (const l of main.letters) if (register == null || degree[l] > degree[register]) register = l;
    // a cycle basis by a breadth-first tree from the register: each edge outside the tree closes one loop
    const parent = {}, depth = {}, viaEdge = {}, treeEdges = new Set(), loops = [];
    if (register) {
      const q = [register]; parent[register] = null; depth[register] = 0;
      while (q.length) { const x = q.shift(); for (const { to, i } of adj[x]) if (!(to in depth)) { depth[to] = depth[x] + 1; parent[to] = x; viaEdge[to] = i; treeEdges.add(i); q.push(to); } }
      for (const e of edges) {
        if (treeEdges.has(e.i) || !(e.a in depth)) continue;
        let u = e.a, v = e.b; const left = [u], right = [v], le = [], re = [];
        while (u !== v) { if (depth[u] >= depth[v]) { le.push(viaEdge[u]); u = parent[u]; left.push(u); } else { re.push(viaEdge[v]); v = parent[v]; right.push(v); } }
        right.pop();
        const ls = left.concat(right.reverse()), es = le.concat(re.reverse()).concat([e.i]);
        loops.push({ letters: ls.concat([ls[0]]), edges: es, closing: e.i });
      }
    }
    trace.push(step('menu-components', `The letters fall into ${components.length} connected group${components.length === 1 ? '' : 's'}; the largest has ${main.letters.length} letters, ${main.edges} edges and ${main.loops} loop${main.loops === 1 ? '' : 's'}.`, { components }));
    loops.forEach((lp, n) => trace.push(step('menu-loop', `Loop ${n + 1}: ${lp.letters.join(' → ')} through scramblers ${lp.edges.map((i) => i + 1).join(', ')}. Going round it, a wrong guess at a stecker contradicts itself.`, lp)));
    if (register) trace.push(step('menu-register', `The test register sits on ${register}, the letter with the most connections (${degree[register]}).`, { register }));
    return { crib: k, cipher: c, offset, length: k.length, edges, letters, adj, degree, components, main, loops, register, clashes, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
