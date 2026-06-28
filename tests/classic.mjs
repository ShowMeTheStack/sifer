// Classical ciphers and their attacks. Hand-worked examples check each rule; random round trips check every cipher;
// the attacks must recover planted keys from original texts that are not part of the reference corpus.
import { load, harness, rng } from './load.mjs';
const S = load(['core']), t = harness('classic'), C = S.Classic;

// test-only plaintexts, written for these tests and absent from the model's corpus
const FRESH = [
  'ON THE FIRST COLD MORNING OF THE YEAR THE CANAL FROZE FROM ONE LOCK TO THE NEXT AND THE CHILDREN OF THE TOWPATH COTTAGES WALKED OUT ONTO THE ICE WITH THEIR PARENTS SHOUTING FROM THE BANK THE LOCK KEEPER TESTED THE ICE WITH A LONG POLE AND DECLARED IT SAFE FOR ONE AFTERNOON ONLY SO EVERYONE SKATED UNTIL THE LIGHT FAILED AND THEN WENT HOME TO WARM THEIR HANDS BY THE STOVE WHILE THE KETTLE SANG',
  'THE NEW POSTMISTRESS SORTED THE LETTERS BY STREET AND THEN BY HOUSE NUMBER BEFORE SHE OPENED THE DOOR EACH MORNING SHE NOTICED THAT THE SAME PALE BLUE ENVELOPE ARRIVED EVERY THURSDAY FOR THE MAN AT NUMBER NINE AND THAT HE NEVER SENT A REPLY AFTER A YEAR SHE ASKED HIM ABOUT IT AND HE LAUGHED AND SAID THE LETTERS WERE FROM HIS BROTHER WHO WROTE ONLY TO TELL HIM THE SCORES OF THE FOOTBALL MATCHES THEY HAD WATCHED TOGETHER AS BOYS',
  'BEFORE THE STORM ARRIVED THE FARMERS MOVED THE SHEEP DOWN FROM THE HIGH FIELDS AND STACKED THE HAY UNDER THE BARN ROOF THE WIND CAME IN THE NIGHT AND TORE A BRANCH FROM THE OLD OAK BY THE GATE BUT NOTHING ELSE WAS HARMED IN THE MORNING THE WHOLE VALLEY WAS BRIGHT AND WET AND A RAINBOW STOOD OVER THE RIVER FOR NEARLY AN HOUR WHILE THE DOGS RAN BARKING THROUGH THE PUDDLES IN THE LANE',
  'MY GRANDFATHER KEPT A SMALL NOTEBOOK IN HIS COAT POCKET AND WROTE DOWN THE NAME OF EVERY BIRD HE SAW ON HIS WALK TO THE VILLAGE SHOP OVER FORTY YEARS THE LIST GREW TO MORE THAN TWO HUNDRED KINDS AND HE COULD TELL YOU FROM MEMORY THE DAY HE FIRST SAW EACH ONE WHEN HIS EYES GREW WEAK HE ASKED ME TO READ THE LIST ALOUD AND HE WOULD CLOSE HIS EYES AND SMILE AS IF EACH NAME WERE AN OLD FRIEND KNOCKING AT THE DOOR',
];

// ---- extended Euclid and inverses ----
{
  const e = C.egcd(240, 46);
  t.eq([e.g, e.x, e.y], [2, -9, 47], 'egcd(240, 46): 2 = −9·240 + 47·46');
  t.eq(e.rows.length, 7, 'the table has two starting rows and a row per division');
  t.eq(C.inverse(7).inv, 15, '7·15 = 105 ≡ 1 (mod 26)');
  t.eq(C.inverse(13).inv, null, '13 has no inverse mod 26');
  for (let a = 1; a < 26; a++) { const v = C.inverse(a).inv; t.ok(v === null ? C.gcd(a, 26) > 1 : (a * v) % 26 === 1, 'inverse of ' + a); }
  t.ok(C.inverse(19).trace.every((s) => s.say.length > 10), 'every Euclid step is narrated');
}
// ---- hand-worked examples ----
t.eq(C.shift.encrypt('Meet at noon!', 3).out, 'PHHW DW QRRQ!', 'shift by 3 keeps spaces and punctuation');
t.eq(C.affine.encrypt('AFFINE', 5, 8).out, 'IHHWVC', 'affine 5p + 8');
t.eq(C.affine.decrypt('IHHWVC', 5, 8).out, 'AFFINE', 'affine inverse uses 21 = 5⁻¹');
t.eq(C.affine.decrypt('IHHWVC', 5, 8).inv, 21, '5⁻¹ = 21 mod 26');
t.eq(C.affine.encrypt('ABC', 4, 1).out, null, 'a = 4 is refused');
t.eq(C.substitution.keywordAlphabet('LIGHTHOUSE').alphabet, 'LIGHTOUSEABCDFJKMNPQRVWXYZ', 'keyword alphabet from A');
t.eq(C.substitution.keywordAlphabet('LIGHTHOUSE', { continueFrom: true }).alphabet, 'LIGHTOUSEFJKMNPQRVWXYZABCD', 'keyword alphabet continuing after the last keyword letter');
t.eq(C.vigenere.encrypt('HARBOUR', 'KEY').out, 'REPLSSB', 'Vigenère HARBOUR under KEY');
t.eq(C.autokey.encrypt('HARBOUR', 'KEY').out, 'REPIOLS', 'autokey HARBOUR with primer KEY');
t.eq(C.columnar.encrypt('WEATHERSTATION', 'CAB').out, 'EHSTNAETIWTRAO', 'columnar transposition under CAB');
t.eq(C.railfence.encrypt('WEATHERSTATION', 3).out, 'WHTOETESAINART', 'rail fence on three rails');
{
  const sq = C.playfair.square('LANTERN');
  t.eq(sq.rows, ['LANTE', 'RBCDF', 'GHIKM', 'OPQSU', 'VWXYZ'], 'Playfair square from LANTERN');
  const pf = (p) => C.playfair.encrypt(p, 'LANTERN').out;
  t.eq([pf('LA'), pf('LR'), pf('AC'), pf('EL'), pf('VL')], ['AN', 'RG', 'NB', 'LA', 'LR'], 'Playfair row, column, rectangle and wrap-around rules');
  t.eq(C.playfair.digraphs('BALLOON').pairs, ['BA', 'LX', 'LO', 'ON'], 'doubled letters are split and an odd end padded');
  t.eq(C.playfair.digraphs('JAXXE').pairs, ['IA', 'XQ', 'XE'], 'J becomes I, and a doubled X is split by Q');
}
// ---- round trips with random keys ----
const r = rng(26);
const rl = (n) => { let s = ''; for (let i = 0; i < n; i++) s += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(r() * 26)]; return s; };
for (let n = 0; n < 60; n++) {
  const p = FRESH[n % 4].slice(0, 30 + Math.floor(r() * 300)), L = C.letters(p);
  const k = Math.floor(r() * 26); t.eq(C.shift.decrypt(C.shift.encrypt(p, k).out, k).out, p, 'shift ' + n);
  const [a, b] = C.affine.keys()[Math.floor(r() * 312)]; t.eq(C.affine.decrypt(C.affine.encrypt(p, a, b).out, a, b).out, p, 'affine ' + n);
  const al = C.substitution.keywordAlphabet(rl(8), { continueFrom: n % 2 }).alphabet; t.eq(C.substitution.decrypt(C.substitution.encrypt(p, al).out, al).out, p, 'substitution ' + n);
  const vk = rl(1 + Math.floor(r() * 12)); t.eq(C.vigenere.decrypt(C.vigenere.encrypt(p, vk).out, vk).out, p, 'Vigenère ' + n);
  t.eq(C.autokey.decrypt(C.autokey.encrypt(p, vk).out, vk).out, p, 'autokey ' + n);
  const ck = rl(2 + Math.floor(r() * 9)); t.eq(C.columnar.decrypt(C.columnar.encrypt(p, ck).out, ck).out, L, 'columnar ' + n);
  t.eq(C.columnar.decrypt(C.columnar.encrypt(p, ck, { pad: true }).out, ck).out.slice(0, L.length), L, 'padded columnar ' + n);
  const rails = 2 + Math.floor(r() * 8); t.eq(C.railfence.decrypt(C.railfence.encrypt(p, rails).out, rails).out, L, 'rail fence ' + n);
  const pk = rl(6), pd = C.playfair.decrypt(C.playfair.encrypt(p, pk).out, pk).out, pl = C.playfair.digraphs(p).pairs.join('');
  t.eq(pd, pl, 'Playfair ' + n);
  const pad = C.otp.pad(L.length, r); t.eq(C.otp.letters(C.otp.letters(p, pad).out, pad, -1).out, L, 'one-time pad on letters ' + n);
}
{
  const m = new TextEncoder().encode('Meet me by the north gate at six'), pad = C.otp.bytePad(m.length, r);
  const c = C.otp.bytes(m, pad).out;
  t.eq(Array.from(C.otp.bytes(c, pad).out), Array.from(m), 'one-time pad on bytes');
  const m2 = new TextEncoder().encode('Bring the spare key and a torch!'), c2 = C.otp.bytes(m2, pad).out;
  const drag = C.otp.cribDrag(c, c2, 'north gate');
  t.ok(drag.rows.find((x) => x.pos === 15).text === new TextDecoder().decode(m2.slice(15, 25)), 'a reused pad: dragging "north gate" across c1 ⊕ c2 shows the other message');
  let threw = false; try { C.otp.letters('LONGMESSAGE', 'SHORT'); } catch (e) { threw = true; } t.ok(threw, 'a pad shorter than the message is refused');
}
// ---- statistics ----
{
  const p = FRESH.join(' '), f = C.freq(p);
  t.eq(f.ranked[0].letter, 'E', 'E is the commonest letter of the test texts');
  t.ok(C.ioc(p).ioc > 0.06 && C.ioc(p).ioc < 0.075, 'English has an IC near 0.066: ' + C.ioc(p).ioc.toFixed(4));
  t.ok(C.ioc(rl(2000)).ioc < 0.042, 'random letters have an IC near 1/26');
  t.ok(C.chiSquared(p).chi < 100 && C.chiSquared(C.shift.encrypt(p, 7).out).chi > 1000, 'χ² is small for English, large for a shifted text');
  const m = C.model();
  t.eq(m.bigrams[0].gram, 'TH', 'TH leads the corpus bigrams'); t.eq(m.trigrams[0].gram, 'THE', 'THE leads the trigrams');
  t.ok(Math.abs(C.ENGLISH.reduce((a, b) => a + b, 0) - 100) < 0.05, 'the reference frequencies sum to 100%');
  t.ok(C.score(p, true) > -4.6 && C.score(rl(500), true) < -6, 'quadgram score separates English from noise');
}
// ---- attacks ----
{
  let ok = 0, n = 0;
  for (const [i, key] of [[0, 'TIDE'], [1, 'POSTBOX'], [2, 'HAYSTACK'], [3, 'WREN'], [0, 'CANALBOAT'], [1, 'SKY'], [2, 'ORCHARDS'], [3, 'FEATHERED']].entries()) {
    const ct = C.vigenere.encrypt(FRESH[key[0]], key[1]).out, b = C.breakVigenere(ct);
    n++; if (b.key === key[1]) ok++; else t.ok(false, `Vigenère ${i}: wanted ${key[1]}, got ${b.key} (length ${b.len})`);
    if (i === 1) {
      t.ok(b.kasiski.best === 7 || b.kasiski.ranked.slice(0, 3).some((x) => x.factor === 7), 'Kasiski points at 7');
      t.ok(Math.abs(b.friedman.estimate - 7) < 3.5, 'Friedman estimates about 7: ' + b.friedman.estimate.toFixed(2));
      t.ok(b.period[6].avg > 0.058 && b.period[5].avg < 0.05, 'columns of 7 look English, columns of 6 do not');
      t.ok(['vig-start', 'kasiski-votes', 'friedman', 'period-ioc', 'vig-length', 'column-shift', 'vig-done'].every((k) => b.trace.some((s) => s.kind === k)), 'the break is traced in its three moves');
    }
  }
  t.eq(ok, n, `Vigenère keys recovered: ${ok}/${n}`);
  const k = C.kasiski(C.vigenere.encrypt(FRESH[0] + FRESH[2], 'LOCK').out);
  t.ok(k.repeats.length > 3 && k.repeats.every((x) => x.distances.every((d) => d > 0)), 'Kasiski lists repeats and distances');
  t.eq(k.best, 4, 'Kasiski votes for 4');
  const cs = C.columnShifts(C.vigenere.encrypt(FRESH[3], 'MOTH').out, 4);
  t.eq(cs.key, 'MOTH', 'per-column χ² recovers MOTH');
}
for (const [i, k] of [[0, 3], [1, 11], [2, 19], [3, 25]]) {
  const b = C.bruteShift(C.shift.encrypt(FRESH[i].slice(0, 60), k).out);
  t.eq(b.best.k, k, 'brute-force shift ' + k);
  t.eq(b.ranked.length, 26, 'all 26 shifts ranked');
}
for (const [i, a, b] of [[0, 5, 8], [1, 17, 3], [2, 25, 20], [3, 9, 0]]) {
  const br = C.bruteAffine(C.affine.encrypt(FRESH[i].slice(0, 80), a, b).out);
  t.eq([br.best.a, br.best.b], [a, b], `brute-force affine ${a}p + ${b}`);
  t.eq(br.rows.length, 312, '312 affine keys');
}
{
  const ct = C.railfence.encrypt(FRESH[1], 5).out;
  t.eq(C.bruteRailfence(ct).best.rails, 5, 'rail fence: five rails found by score');
}
{
  let exact = 0;
  const words = ['NIGHTJAR', 'QUARRY', 'BLACKSMITH', 'WINDOW', 'PUZZLED', 'FROSTBITE'];
  for (let i = 0; i < words.length; i++) {
    const p = FRESH[i % 4], al = C.substitution.keywordAlphabet(words[i], { continueFrom: i % 2 }).alphabet;
    const ct = C.substitution.encrypt(p, al).out, s = C.solveSubstitution(ct, { seed: i + 1 });
    if (s.plain === p) exact++; else {
      const L = C.letters(p), Q = C.letters(s.plain); let same = 0; for (let j = 0; j < L.length; j++) if (L[j] === Q[j]) same++;
      t.ok(same > 0.9 * L.length, `substitution ${words[i]}: ${same}/${L.length} letters right`);
    }
  }
  t.ok(exact >= words.length - 1, `substitution solved exactly in ${exact}/${words.length} cases (about 330 letters each)`);
  const ct = C.substitution.encrypt(FRESH[2], C.substitution.keywordAlphabet('MEADOW').alphabet).out;
  const a = C.solveSubstitution(ct, { seed: 9 }), b = C.solveSubstitution(ct, { seed: 9 });
  t.eq([a.alphabet, a.swaps], [b.alphabet, b.swaps], 'the solver is deterministic for a seed');
  t.ok(a.trace[0].kind === 'sub-start' && a.trace.length > 3, 'the climb is traced from the frequency-order start');
  const job = C.substitutionSolver(ct, { seed: 9 }); let st, chunks = 0; do { st = job.run(5); chunks++; } while (!st.done);
  t.eq(st.best.alphabet, a.alphabet, 'run in chunks (' + chunks + ') it reaches the same key');
}
{
  const long = C.corpus.longExamples.keeper, al = C.substitution.keywordAlphabet('HARBOURWALL').alphabet;
  t.eq(C.solveSubstitution(C.substitution.encrypt(long, al).out, { seed: 3 }).plain, long, 'the long worked example solves exactly');
  t.ok(Object.values(C.corpus.examples).every((x) => /^[A-Z ]+$/.test(x)), 'example plaintexts are clean');
}
t.done();
