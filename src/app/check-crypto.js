// The cryptographic answer kinds: a value in hex (or bytes), a function written in the sandbox, a CTF flag, and
// "break it", where the student submits what an attack recovered (a key, a plaintext, a factor) and it is checked
// against the hidden truth, or by trying it. Fields of each kind are listed in src/app/check-index.js.
(function (S) {
  'use strict';
  const K = (S.Check = S.Check || {});
  K.kinds = K.kinds || {};
  const right = (x, extra) => ({ ok: true, message: 'Right.' + (extra ? ' ' + extra : '') + (x.why ? ' ' + x.why : '') });

  // ---- hex and bytes ------------------------------------------------------------------------------------------------
  /** hex as typed: spaces, colons, 0x prefixes and case are ignored. Returns {hex} or {error} */
  K.readHex = function (text) {
    let t = String(text === undefined || text === null ? '' : text).trim().toLowerCase();
    t = t.replace(/0x/g, '').replace(/[\s:_,-]+/g, '');
    if (!t) return { error: 'Type a value in hex first, like 3a 7f 00.' };
    const bad = /[^0-9a-f]/.exec(t);
    if (bad) return { error: '"' + bad[0] + '" is not a hex digit: use 0–9 and a–f.' };
    return { hex: t };
  };
  K.kinds.hex = {
    check(x, a) {
      const r = K.readHex(a);
      if (r.error) return { ok: false, message: r.error };
      let g = r.hex;
      if (x.accept) return K.accepted(x, x.accept(g));
      const wants = [].concat(x.answer).map((w) => K.readHex(w).hex);
      const w0 = wants[0];
      // a value (not bytes) may drop its leading zeros
      if (x.value) { const strip = (h) => h.replace(/^0+(?=.)/, ''); if (wants.some((w) => strip(w) === strip(g))) return right(x); }
      if (wants.includes(g)) return right(x);
      if (g.length % 2 && !x.value) return { ok: false, message: 'That is ' + g.length + ' hex digits: a whole number of bytes takes an even number.' };
      if (g.length !== w0.length) return { ok: false, message: 'Not quite: the answer is ' + K.plural(w0.length / 2, 'byte') + ' long, and yours is ' + K.plural(Math.ceil(g.length / 2), 'byte') + '.' + (x.whyNot ? ' ' + x.whyNot : '') };
      let bytes = 0;
      for (let i = 0; i < w0.length; i += 2) if (w0.slice(i, i + 2) !== g.slice(i, i + 2)) bytes++;
      return { ok: false, message: 'Not quite: ' + K.plural(bytes, 'byte differs', 'bytes differ') + ' from the answer.' + (x.whyNot ? ' ' + x.whyNot : '') };
    },
  };
  K.kinds.bytes = K.kinds.hex;

  // ---- code, run in the sandbox ---------------------------------------------------------------------------------------
  /** the tests of a code exercise: given, or made from a reference function on its cases */
  K.codeTests = function (x) {
    if (x.tests) return typeof x.tests === 'function' ? x.tests() : x.tests;
    if (x.ref && x.cases) return x.cases.map((args) => ({ args, want: x.ref(...args) }));
    throw new Error('a code exercise needs tests, or ref and cases');
  };
  /** what a sandbox report says to the student: the first failing case, with its inputs */
  K.codeResult = function (x, rep, tests) {
    const SB = S.Sandbox, show = (v) => SB.showAs(x, v), call = (args) => x.fn + '(' + args.map((v, i) => ((x.decimalArgs || []).includes(i) ? SB.show(v) : show(v))).join(', ') + ')';
    if (rep.compileError) return { ok: false, message: rep.missing ? 'Your code has no function called ' + x.fn + ': write function ' + x.fn + '(' + (x.params || []).join(', ') + ') { … }.' : 'Your code does not run: ' + rep.compileError + '.', logs: rep.logs };
    if (rep.ok) return Object.assign(right(x, 'It passes all ' + K.plural(tests.length, 'test') + '.'), { cases: rep.cases, logs: rep.logs });
    const c = rep.cases[rep.firstFail];
    const n = rep.firstFail + 1;
    let msg = 'Test ' + n + ' of ' + tests.length + ' fails: ' + call(c.args) + ' ';
    if (rep.timedOut && !('got' in c) && !c.error) msg += 'ran longer than ' + ((x.timeLimit || 2000) / 1000) + ' s and was stopped (a loop that never ends?).';
    else if (c.error) msg += 'threw ' + c.error + '.';
    else if (c.want === undefined && typeof c.diff === 'string') msg += 'returned ' + show(c.got) + ', and ' + c.diff.replace(/\.$/, '') + '.';
    else { const d = SB.same(c.want, c.got); msg += 'returned ' + show(c.got) + ', but it should return ' + show(c.want) + (d !== true && d !== 'a different value' ? ' (' + d + ')' : '') + '.'; }
    return { ok: false, message: msg, cases: rep.cases, firstFail: rep.firstFail, logs: rep.logs };
  };
  /** the code a run sees: the task's given helpers (x.prelude), then the student's own */
  K.codeSource = (x, a) => (x.prelude ? String(x.prelude).replace(/\n*$/, '\n') : '') + String(a);
  K.kinds.code = {
    check(x, a) {
      if (K.blank(a)) return { ok: false, message: 'Write the function first.' };
      if (!S.Sandbox || !S.Sandbox.syncRunner) return { ok: false, message: 'Code is checked in a worker: use answerAsync.' };
      const tests = K.codeTests(x);
      return K.codeResult(x, S.Sandbox.runSync({ src: K.codeSource(x, a), fn: x.fn, tests, timeLimit: x.timeLimit }), tests);
    },
    async checkAsync(x, a) {
      if (K.blank(a)) return { ok: false, message: 'Write the function first.' };
      const tests = K.codeTests(x);
      return K.codeResult(x, await S.Sandbox.run({ src: K.codeSource(x, a), fn: x.fn, tests, timeLimit: x.timeLimit }), tests);
    },
  };

  // ---- a CTF flag ----------------------------------------------------------------------------------------------------
  /** the SHA-256 of a flag as hex (flags may be stored as hashes, so the page does not hold the answer in plain text) */
  K.flagHash = (flag) => S.bytes.hex(S.SHA256.hash(new TextEncoder().encode(String(flag))));
  /** a flag format like 'sifer{...}' as a pattern, and a sentence describing it */
  K.flagShape = function (format) {
    const f = String(format || 'sifer{...}');
    const i = f.indexOf('{');
    const prefix = i < 0 ? '' : f.slice(0, i);
    return { prefix, re: new RegExp('^' + prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\{[^{}\\s]+\\}$'), text: f };
  };
  K.kinds.flag = {
    check(x, a) {
      const t = String(a === undefined || a === null ? '' : a).trim();
      if (!t) return { ok: false, message: 'Paste the flag first. It looks like ' + K.flagShape(x.format).text + '.' };
      const shape = K.flagShape(x.format);
      if (!shape.re.test(x.caseless ? t.toLowerCase() : t)) return { ok: false, message: 'That is not a flag: a flag looks like ' + shape.text + ', with nothing before or after it.' };
      const t2 = x.caseless ? t.toLowerCase() : t;
      const good = x.flagHash ? K.flagHash(t2) === String(x.flagHash).toLowerCase() : x.flag ? [].concat(x.flag).includes(t2) : x.accept ? !!x.accept(t2) : false;
      return good ? right(x, 'The flag is accepted.') : { ok: false, message: 'The format is right, but this is not the flag.' + (x.whyNot ? ' ' + x.whyNot : '') };
    },
  };

  // ---- break it -------------------------------------------------------------------------------------------------------
  /**
   * The student submits what an attack recovered. target names what (a key, the plaintext, a factor, a shift); the
   * answer is compared after normalising (normalize: 'letters' | 'text' | 'hex' | 'int' | 'caseless'), or verify(value)
   * decides (it may try the key: decrypt and compare), returning true, false or a sentence saying why not.
   */
  const NORM = {
    letters: (t) => String(t).toUpperCase().replace(/[^A-Z]/g, ''),
    text: (t) => String(t).trim().replace(/\s+/g, ' '),
    caseless: (t) => String(t).trim().replace(/\s+/g, ' ').toLowerCase(),
    hex: (t) => { const r = K.readHex(t); return r.error ? '\u0000' + t : r.hex; },
    int: (t) => { const s = String(t).trim().replace(/[,_\s]/g, ''); return /^-?\d+$/.test(s) ? BigInt(s).toString() : '\u0000' + s; },
  };
  K.kinds.break = {
    check(x, a) {
      const what = x.target || 'answer';
      if (K.blank(a)) return { ok: false, message: 'Type the ' + what + ' you recovered first.' };
      const norm = NORM[x.normalize || 'text'] || NORM.text;
      const v = norm(a);
      if (v.startsWith('\u0000')) return { ok: false, message: x.normalize === 'hex' ? 'The ' + what + ' is written in hex: use 0–9 and a–f.' : 'The ' + what + ' is a whole number.' };
      if (x.verify) return K.accepted(x, x.verify(v, String(a)));
      const ok = [].concat(x.answer).some((w) => norm(typeof w === 'bigint' ? w.toString() : w) === v);
      if (ok) return right(x, 'You recovered the ' + what + '.');
      if (x.normalize === 'letters' || x.normalize === 'text' || x.normalize === 'caseless') {
        const w = norm([].concat(x.answer)[0]);
        if (w.length > 6 && v.length === w.length) { let same = 0; for (let i = 0; i < w.length; i++) if (w[i] === v[i]) same++; if (same / w.length > 0.8) return { ok: false, message: 'Close: ' + same + ' of ' + w.length + ' letters are right. Check the rest.' }; }
      }
      return { ok: false, message: 'That is not the ' + what + '.' + (x.whyNot ? ' ' + x.whyNot : '') };
    },
  };
})(globalThis.Sifer = globalThis.Sifer || {});
