// Enigma I, Rejewski's cycles, key sheets and the Bombe. Vectors: the existing app's Enigma I tests (~/enigma/test)
// and two well-known published Enigma I messages (the 1930 operating instructions and a 1941 army message).
import { load, harness, rng } from './load.mjs';
const S = load(['core']), t = harness('enigma'), E = S.Enigma, B = E.bombe, C = S.Classic, ABC = E.ABC;

// ---- the machine ----
t.eq(E.encrypt({}, 'AAAAA'), 'BDZGO', 'I II III, UKW-B, rings AAA, window AAA: AAAAA');
t.eq(E.encrypt({ rings: 'BBB' }, 'AAAAA'), 'EWTYX', 'rings BBB: AAAAA');
t.eq(E.encrypt({ rings: [2, 2, 2] }, 'AAAAA'), 'EWTYX', 'rings given as sheet numbers');
{
  const m = E.machine({ window: 'ADU' }), seq = [];
  for (let i = 0; i < 4; i++) { m.press('A'); seq.push(m.window); }
  t.eq(seq, ['ADV', 'AEW', 'BFX', 'BFY'], 'the double step ADU → ADV → AEW → BFX → BFY');
  const d = E.machine({ window: 'AEW' }).press('A').stepping;
  t.eq([d.pawls, d.steps], [[true, false, true], [true, true, true]], 'pawls at AEW: the left pawl and the right pawl engage, all three rotors move');
  const r = E.machine({ window: 'ADV' }).press('A').stepping;
  t.eq([r.pawls, r.steps], [[false, true, true], [false, true, true]], 'pawls at ADV: the right rotor at its notch carries the middle');
  const k = E.machine({ rings: 'AAK', window: 'AAV' }); k.press('A');
  t.eq(k.window, 'ABW', 'the turnover letter is on the ring, so it does not move with the ring setting');
}
{
  const cfg = { order: ['III', 'V', 'I'], reflector: 'C', rings: 'QHD', window: 'QEV', plugs: 'AB CD EF GH IJ KL MN OP QR ST' };
  const pt = 'THEFERRYWILLNOTRUNONSATURDAY', ct = E.encrypt(cfg, pt);
  t.eq(E.encrypt(cfg, ct), pt, 'plugboard of ten cables: decryption is encryption');
}
{
  const m = E.machine({ order: ['IV', 'V', 'II'], reflector: 'A', plugs: 'QW ER TZ' }); let selfs = 0;
  for (let i = 0; i < 4000; i++) { const ch = ABC[i % 26]; if (m.press(ch).out === ch) selfs++; }
  t.eq(selfs, 0, 'no letter ever encrypts to itself (4000 presses)');
}
for (const bad of [{ order: ['VI', 'II', 'III'] }, { order: ['I', 'I', 'II'] }, { order: ['I', 'II'] }, { reflector: 'D' }, { plugs: 'AB AC' }, { plugs: 'AA' }, { plugs: 'ABC' }, { window: 'AA' }]) {
  let threw = false; try { E.machine(bad); } catch (e) { threw = true; }
  t.ok(threw, 'rejects ' + JSON.stringify(bad));
}
t.eq(E.machine({ plugs: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' }).plugs.length, 13, 'thirteen cables are allowed');
{ let threw = false; try { E.parsePlugs('AB CD EF GH IJ KL MN OP QR ST UV WX YZ', 12); } catch (e) { threw = true; } t.ok(threw, 'more cables than the limit are refused'); }

// published Enigma I messages
t.eq(E.encrypt({ order: ['II', 'I', 'III'], reflector: 'A', rings: '24 13 22', window: 'ABL', plugs: 'AM FI NV PS TU WZ' },
  'GCDSE AHUGW TQGRK VLFGX UCALX VYMIG MMNMF DXTGN VHVRM MEVOU YFZSL RHDRR XFJWC FHUHM UNZEF RDISI KBGPM YVXUZ'),
'FEINDLIQEINFANTERIEKOLONNEBEOBAQTETXANFANGSUEDAUSGANGBAERWALDEXENDEDREIKMOSTWAERTSNEUSTADT', '1930 operating instructions example (UKW-A, II I III, rings 24 13 22)');
t.eq(E.encrypt({ order: ['II', 'IV', 'V'], reflector: 'B', rings: '02 21 12', window: 'BLA', plugs: 'AV BS CG DL FU HZ IN KM OW RX' },
  'EDPUD NRGYS ZRCXN UYTPO MRMBO FKTBZ REZKM LXLVE FGUEY SIOZV EQMIK UBPMM YLKLT TDEIS MDICA GYKUA CTCDO MOHWX MUUIA UBSTS LRNBZ SZWNR FXWFY SSXJZ VIJHI DISHP RKLKA YUPAD TXQSP INQMA TLPIF SVKDA SCTAC DPBOP VHJK'),
'AUFKLXABTEILUNGXVONXKURTINOWAXKURTINOWAXNORDWESTLXSEBEZXSEBEZXUAFFLIEGERSTRASZERIQTUNGXDUBROWKIXDUBROWKIXOPOTSCHKAXOPOTSCHKAXUMXEINSAQTDREINULLXUHRANGETRETENXANGRIFFXINFXRGTX', '1941 army message, part 1 (UKW-B, II IV V, rings 02 21 12)');

// random configurations: encryption equals decryption, stepping rule, step back
const r = rng(1930);
for (let n = 0; n < 150; n++) {
  const cfg = E.randomKey(r, { pairs: Math.floor(r() * 14), reflector: 'ABC'[n % 3] }), len = 20 + Math.floor(r() * 300);
  let pt = ''; for (let i = 0; i < len; i++) pt += ABC[Math.floor(r() * 26)];
  const ct = E.encrypt(cfg, pt);
  t.ok(E.encrypt(cfg, ct) === pt, 'reciprocal ' + JSON.stringify(cfg));
  t.ok([...ct].every((c, i) => c !== pt[i]), 'no self-encryption ' + n);
  t.ok(E.machine(cfg).encrypt(pt).out === ct, 'traced and fast paths agree ' + n);
}
{
  // the middle rotor moves exactly when the right rotor shows its notch or when it shows its own notch (the double step)
  let ok = true, doubles = 0;
  for (let n = 0; n < 20; n++) {
    const cfg = E.randomKey(r), m = E.machine(cfg), W = cfg.order.map(E.wheel);
    for (let i = 0; i < 1500; i++) {
      const p = m.positions, s = m.step(), q = m.positions;
      const mid = p[1] === W[1].notch, right = p[2] === W[2].notch;
      if ((q[1] !== p[1]) !== (mid || right) || (q[0] !== p[0]) !== mid || q[2] === p[2]) ok = false;
      if (mid) { doubles++; if (!s.steps.every(Boolean)) ok = false; }
      const back = E.machine({ order: cfg.order }).setWindow(s.after); const prev = back.stepBack();
      if (!prev.includes(s.before)) ok = false;
    }
  }
  t.ok(ok, 'pawl stepping, double steps and stepping back agree with the rule over 30 000 presses');
  t.ok(doubles > 20, 'double steps happened (' + doubles + ')');
  const m = E.machine({ window: 'AAA' }); let period = 0;
  do { m.step(); period++; } while (m.window !== 'AAA' && period < 20000);
  t.eq(period, 16900, 'the double step shortens the period to 26·25·26 = 16 900');
}
{
  const p = E.machine({ order: ['I', 'II', 'III'], rings: 'BCD', window: 'XYZ', plugs: 'AQ' }).press('A');
  t.eq(p.path.map((x) => x.part).join(' '), 'plugboard ETW R M L UKW L M R ETW plugboard', 'the signal path visits every part in order');
  t.ok(p.path.every((x, i) => i === 0 || x.from === p.path[i - 1].to), 'each stage starts where the last ended');
  t.ok(p.path.filter((x) => 'pinIn' in x).every((x) => x.pinIn === (x.from + x.offset) % 26), 'contact positions follow the core offset');
  t.eq(p.path[0].to, 16, 'the A–Q cable');
  t.ok(p.trace.length >= 10 && p.trace.every((s) => s.say.length > 10), 'every key press is narrated');
}

// ---- Rejewski ----
{
  const day = { order: ['III', 'I', 'II'], reflector: 'B', rings: 'KUJ', window: 'PDH', plugs: 'AZ BY CX DW EV FU' };
  const ch = S.Enigma.rejewski.characteristic(day);
  for (const nm of ['AD', 'BE', 'CF']) {
    const L = ch[nm].lengths, sum = L.reduce((a, b) => a + b, 0), pairs = {}; L.forEach((x) => { pairs[x] = (pairs[x] || 0) + 1; });
    t.eq(sum, 26, nm + ' cycles cover the alphabet');
    t.ok(Object.values(pairs).every((c) => c % 2 === 0), nm + ' cycles come in pairs of equal length: ' + L.join(' '));
  }
  const cj = S.Enigma.rejewski.conjugacy(day);
  t.ok(cj.same, 'the cables conjugate AD, BE and CF: same lengths, letters renamed by σ');
  t.eq(cj.withPlugs.key, cj.withoutPlugs.key, 'the characteristic does not depend on the plugboard');
  const ind = S.Enigma.rejewski.indicators(day, 220, rng(7)), fi = S.Enigma.rejewski.fromIndicators(ind);
  t.ok(fi.complete.AD && fi.complete.BE && fi.complete.CF, '220 indicators fix all three products');
  t.eq(fi.text, ch.text, 'cycles read from the traffic equal the machine’s characteristic');
  t.eq(fi.conflicts.length, 0, 'the indicators agree with each other');
  // the catalogue finds the core position (rings A) for the right rotor order, with no cables needed
  const core = { order: day.order, reflector: 'B', window: 'FJY' }, target = S.Enigma.rejewski.characteristic(Object.assign({ plugs: day.plugs }, core)).key;
  const job = S.Enigma.rejewski.catalogue({ target, orders: [day.order] }); let res; do res = job.run(100); while (!res.done);
  t.ok(res.matches.some((x) => x.window === 'FJY'), 'the catalogue finds FJY among ' + res.matches.length + ' entries with that characteristic');
}

// ---- key sheets ----
{
  const sh = E.keySheet({ seed: 'harbour', year: 2026, month: 2 }), sh2 = E.keySheet({ seed: 'harbour', year: 2026, month: 2 });
  t.eq(sh.days.length, 28, 'February 2026 has 28 days');
  t.eq(sh.days[0].day, 28, 'the last day is at the top');
  t.eq(JSON.stringify(sh.days), JSON.stringify(sh2.days), 'a sheet is reproducible from its seed');
  const asc = sh.days.slice().reverse();
  t.eq(new Set(asc.map((d) => d.order.join())).size, 28, 'no rotor order repeats');
  t.ok(asc.every((d, i) => !i || d.order.every((x, k) => x !== asc[i - 1].order[k])), 'no rotor in the same slot two days running');
  t.ok(asc.every((d, i) => !i || d.plugs.split(' ').every((p) => !asc[i - 1].plugs.split(' ').includes(p))), 'no cable repeated from the day before');
  t.ok(asc.every((d) => d.plugs.split(' ').length === 10 && d.plugs.split(' ').every((p) => Math.abs(p.charCodeAt(0) - p.charCodeAt(1)) !== 1)), 'ten cables, none joining neighbouring letters');
  t.eq(new Set(asc.flatMap((d) => d.groups)).size, 28 * 4, 'indicator groups are unique');
  const key = E.keySheet.dayKey(sh, 14);
  t.ok(E.encrypt(key, E.encrypt(key, 'ROUNDTRIP')) === 'ROUNDTRIP', 'a day of the sheet loads into the machine');
  t.ok(sh.text().split('\n').length === 31, 'the sheet prints as text');
}

// ---- the Bombe ----
{
  const al = B.align('QWERTYKEEPER', 'KEEP');
  t.eq(al.possible, [2, 3, 4], 'crib alignment: offsets where a crib letter would face itself are ruled out');
  t.ok(al.offsets[6].clashes.length === 4 && al.offsets[8].clashes[0].letter === 'E' && al.offsets[8].clashes[0].i === 2, 'each clash is reported with its letter and place');
  const mn = B.menu('ABCA', 'BCAD', 0);
  t.eq(mn.loops.length, 1, 'a triangle A–B–C is one loop');
  t.eq(mn.main.loops, mn.main.edges - mn.main.letters.length + 1, 'loops = edges − letters + 1');
}
const corpus = C.letters(C.corpus.text()) + C.letters(Object.values(C.corpus.longExamples).join(''));
/** a planted key, a message and a crib of 14–18 letters with no middle-rotor turnover inside it and at least minLoops loops */
function plant(rand, minLoops) {
  for (;;) {
    const key = E.randomKey(rand), start = Math.floor(rand() * (corpus.length - 400)), len = 160 + Math.floor(rand() * 120);
    const plain = corpus.slice(start, start + len), cipher = E.encrypt(key, plain);
    for (let tries = 0; tries < 30; tries++) {
      const cl = 14 + Math.floor(rand() * 5), off = Math.floor(rand() * (len - cl)), crib = plain.slice(off, off + cl);
      const m = E.machine(key); m.run(plain.slice(0, off)); const w0 = m.positions, core = w0.map((p, i) => ABC[(p - m.rings[i] + 26) % 26]).join('');
      m.run(crib); if (m.positions[1] !== w0[1]) continue;
      const menu = B.menu(crib, cipher, off);
      if (menu.main.loops >= minLoops) return { key, plain, cipher, crib, off, core, menu };
    }
  }
}
{
  const rand = rng(1940); let found = 0, solved = 0, cases = 0, falseStops = 0, worst = 0;
  for (let n = 0; n < 22; n++) {
    const c = plant(rand, n < 3 ? 3 : 2);
    let orders;
    if (n < 3) orders = undefined;   // the full run over all 60 rotor orders
    else { const all = B.orders().filter((o) => o.join() !== c.key.order.join()); orders = [c.key.order]; for (let k = 0; k < 5; k++) orders.push(all.splice(Math.floor(rand() * all.length), 1)[0]); }
    const run = B.runAll({ menu: c.menu, reflector: 'B', orders });
    if (n < 3) worst = Math.max(worst, run.ms);
    const good = B.check(run.stops, c.menu), hit = good.find((s) => s.order.join() === c.key.order.join() && s.pos === c.core);
    cases++; falseStops += good.length - (hit ? 1 : 0);
    if (hit) found++; else { t.ok(false, `case ${n}: the true stop ${c.key.order.join(' ')} ${c.core} was not found (${good.length} checked stops)`); continue; }
    const sol = B.solve(hit, c.menu);
    let same = 0; for (let i = 0; i < c.plain.length; i++) if (sol.plain[i] === c.plain[i]) same++;
    if (same === c.plain.length) solved++; else t.ok(false, `case ${n}: the solved key ${JSON.stringify(sol.key)} reads ${same}/${c.plain.length} letters right`);
    t.eq(E.encrypt(sol.key, c.cipher), sol.plain, `case ${n}: the recovered key is a working machine setting`);
  }
  t.eq(found, cases, `the Bombe found the planted rotor order and core in ${found}/${cases} cases`);
  t.eq(solved, cases, `the whole message came back letter for letter in ${solved}/${cases} cases`);
  console.log(`  bombe: ${cases} planted keys, ${found} found, ${solved} fully solved, ${falseStops} false stops surviving the check, full 60-order run ≤ ${worst} ms`);
}
{
  // the worked keys of the pages: each crib's stop must give back a key that decrypts the whole message exactly
  const practice = [
    { key: { order: ['IV', 'I', 'III'], reflector: 'B', rings: 'AAA', window: 'BXC', plugs: 'IE NZ MU KF OC XS DV PL JT YG' },
      plain: 'WEATHERREPORTFORTHENORTHVALLEYRAINBYEVENINGANDASTRONGWINDFROMTHEWESTAFTERMIDNIGHT', cribs: [['WEATHERREPORTFOR', 0], ['REPORTFORTHE', 7]] },
    { key: { order: ['V', 'II', 'IV'], reflector: 'B', rings: 'ARC', window: 'ZBN', plugs: 'NP WZ JK SR QC TY GL BM DA EH' },
      plain: 'WEATHERREPORTFORTHEHARBOURDISTRICTCALMSEASLIGHTMISTCLEARINGBYNOONWINDFROMTHEWESTATTHREEKNOTSTHEFERRYRUNSONTIMEANDTHELIGHTHOUSEKEEPERREPORTSNOTHINGFURTHER', cribs: [['WEATHERREPORTFORTHE', 0]] },
  ];
  for (const pr of practice) for (const [crib, off] of pr.cribs) {
    const cipher = E.encrypt(pr.key, pr.plain), menu = B.menu(crib, cipher, off);
    const good = B.check(B.runAll({ menu, reflector: 'B', orders: [pr.key.order] }).stops, menu);
    const sols = good.map((s) => B.solve(s, menu)), exact = sols.filter((x) => x.plain === pr.plain);
    t.ok(exact.length >= 1, `practice key ${pr.key.window}, crib ${crib} at ${off}: a stop decrypts all ${pr.plain.length} letters (${sols.map((x) => x.key.rings + '/' + x.key.window).join(', ')})`);
    t.ok(exact.every((x) => E.encrypt(x.key, cipher) === pr.plain), `practice key ${pr.key.window}, crib ${crib}: the recovered setting is a working key`);
  }
  // more planted keys, the true rotor order only: every one must come back letter for letter
  const rand = rng(1943); let exact = 0, n = 0;
  for (; n < 24; n++) {
    const c = plant(rand, 2), run = B.runAll({ menu: c.menu, reflector: 'B', orders: [c.key.order] });
    const hit = B.check(run.stops, c.menu).find((s) => s.pos === c.core);
    if (!hit) { t.ok(false, `planted key ${n}: the true stop ${c.core} was not found`); continue; }
    const sol = B.solve(hit, c.menu);
    if (sol.plain === c.plain) exact++; else t.ok(false, `planted key ${n} ${JSON.stringify(c.key)}: recovered ${JSON.stringify(sol.key)} decrypts ${[...c.plain].filter((x, i) => sol.plain[i] === x).length}/${c.plain.length}`);
  }
  t.eq(exact, n, `every planted key decrypts the whole message exactly (${exact}/${n})`);
}
{
  // the full stepping model (rings known, here A) finds a key whose crib spans a middle-rotor turnover
  const key = { order: ['V', 'III', 'I'], reflector: 'B', rings: 'AAA', window: 'GMK', plugs: 'AT BL DF GJ HM NS OP QU RW XZ' };
  const plain = C.letters(C.corpus.longExamples.keeper), cipher = E.encrypt(key, plain), off = 3, crib = plain.slice(off, off + 20);
  const m = E.machine(key); m.run(plain.slice(0, off)); const w0 = m.window; m.run(crib);
  t.ok(w0[1] !== m.window[1], 'this crib spans a turnover (' + w0 + ' → ' + m.window + ')');
  const menu = B.menu(crib, cipher, off);
  const fast = B.check(B.runAll({ menu, reflector: 'B', orders: [key.order] }).stops, menu).filter((s) => s.pos === w0);
  const full = B.check(B.runAll({ menu, reflector: 'B', orders: [key.order], stepping: 'full', rings: 'AAA' }).stops, menu).filter((s) => s.pos === w0);
  t.eq(fast.length, 0, 'the fast-drum model misses a crib with a turnover');
  t.eq(full.length, 1, 'the full stepping model finds it');
  t.eq(B.solve(full[0], menu).plain, plain, 'and decrypts the message');
}
{
  // the machine itself (one hypothesis, current through the diagonal board) and the test of one position
  const c = plant(rng(5), 3), run = B.runAll({ menu: c.menu, reflector: 'B', orders: [c.key.order], simulate: true });
  t.ok(run.stops.some((s) => s.pos === c.core), 'the simulated machine stops at the true position (' + run.rawStops + ' raw stops in one order)');
  const truth = E.plugMap(E.parsePlugs(c.key.plugs)), reg = run.register, st = ABC[truth[ABC.indexOf(reg)]];
  const right = B.test({ menu: c.menu }, c.key.order, c.core, st);
  t.ok(right.consistent && right.regLive.length === 1, 'with the true stecker only one register wire lights');
  const wrong = B.test({ menu: c.menu }, c.key.order, c.core, ABC[(truth[ABC.indexOf(reg)] + 1) % 26]);
  t.ok(!wrong.regLive.includes(st), 'with a wrong stecker the true one stays dark');
  t.ok(B.drums({ menu: c.menu }, c.key.order, c.core).every((d) => d.drums.slice(0, 2) === c.core.slice(0, 2)), 'only the fast drum differs between scramblers');
  // the Web Worker glue, driven with a stand-in scope
  const msgs = []; const scope = { postMessage: (m) => msgs.push(m) }; B.serve(scope);
  scope.onmessage({ data: { cmd: 'start', params: { menu: c.menu, reflector: 'B', orders: [c.key.order] }, slice: 2 } });
  await new Promise((res) => { const iv = setInterval(() => { if (msgs.some((m) => m.type === 'done')) { clearInterval(iv); res(); } }, 5); });
  const done = msgs.find((m) => m.type === 'done');
  t.ok(msgs.filter((m) => m.type === 'progress').length > 1, 'the worker reports progress in chunks (' + msgs.length + ' messages)');
  t.ok(done.stops.some((s) => s.pos === c.core), 'the worker finds the stop');
}
t.done();
