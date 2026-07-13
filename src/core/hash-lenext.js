// The length-extension attack on a secret-prefix MAC, tag = H(secret ‖ message), for any Merkle–Damgård hash whose
// digest is its whole final state (MD5, SHA-1, SHA-256, SHA-512). The digest is a chaining value, so an attacker
// who knows the tag and the length of secret ‖ message can keep hashing from it: they append the padding the
// victim's hash added (the "glue") and any text they like, and compute a valid tag without ever seeing the secret.
//   S.Hash.secretPrefixMac(hash, secret, msg) -> tag
//   S.Hash.lengthExtend({hash, tag, msg, secretLen, ext}) -> {forged, tag, glue, state, trace}   the attacker's side
//   S.Hash.lengthExtension({hash, secret, msg, ext, secretLen?}) -> {ok, forged, tag, real, trace}  the whole story,
//       with the server checking the forgery; if secretLen is not given, every length 1…64 is tried against it
(function (S) {
  'use strict';
  const H = (S.Hash = S.Hash || {});
  const { step, hex, utf8, concat } = H;
  H.secretPrefixMac = (hash, secret, msg) => H.get(hash).hash(concat(utf8(secret), utf8(msg)));
  const show = (b) => {
    let s = '';
    for (const v of b) s += v >= 32 && v < 127 ? String.fromCharCode(v) : '\\x' + v.toString(16).padStart(2, '0');
    return s;
  };
  H.showBytes = show;
  H.EXTENDABLE = ['md5', 'sha1', 'sha256', 'sha512'];
  H.lengthExtend = (opt) => {
    const A = H.get(opt.hash);
    if (!A.pad || !H.EXTENDABLE.includes(A.name)) throw new Error(`${opt.hash} does not leak its whole state: length extension does not apply`);
    const msg = utf8(opt.msg), ext = utf8(opt.ext), tag = utf8(opt.tag), L = opt.secretLen + msg.length;
    const glue = A.glue(L);
    const prefixLen = L + glue.length;
    const state = H.stateFromDigest(A.name, tag);
    const r = A.run(ext, { iv: state, prefixLen, trace: true });
    const forged = concat(msg, glue, ext);
    const trace = [
      step('known', `The attacker knows the message “${show(msg)}”, its tag ${hex(tag)}, and that the secret is ${opt.secretLen} byte${opt.secretLen === 1 ? '' : 's'}: ${L} bytes went into the hash.`, { tag, L }),
      step('glue', `The hash padded those ${L} bytes with ${glue.length} bytes of glue: 80, zeros and the length ${L * 8} bits. Message ‖ glue fills exactly ${prefixLen / A.blockLen} block${prefixLen === A.blockLen ? '' : 's'}.`, { glue, prefixLen }),
      step('resume', `The tag is the chaining value after those blocks, so the attacker loads it as the state and hashes “${show(ext)}” as if ${prefixLen} bytes had come before.`, { state }),
      ...r.trace.filter((s) => s.kind === 'compress' || s.kind === 'pad'),
      step('forged', `Forged message: message ‖ glue ‖ “${show(ext)}” (${forged.length} bytes), forged tag ${hex(r.digest)}. The secret was never used.`, { forged, tag: r.digest }),
    ];
    return { forged, tag: r.digest, glue, state, prefixLen, trace };
  };
  H.lengthExtension = (opt) => {
    const hash = opt.hash || 'sha256', secret = utf8(opt.secret), msg = utf8(opt.msg), ext = utf8(opt.ext);
    const tag = H.secretPrefixMac(hash, secret, msg);
    const verify = (m, t) => H.eq(H.secretPrefixMac(hash, secret, m), t);
    const trace = [step('server', `The server tags “${show(msg)}” as ${hash}(secret ‖ message) = ${hex(tag)} and will accept any message whose tag matches.`, { tag })];
    const lens = opt.secretLen ? [opt.secretLen] : Array.from({ length: 64 }, (_, i) => i + 1);
    for (const n of lens) {
      const f = H.lengthExtend({ hash, tag, msg, ext, secretLen: n });
      if (verify(f.forged, f.tag)) {
        if (!opt.secretLen) trace.push(step('guess', `The secret's length was unknown; guessing ${n} byte${n === 1 ? '' : 's'} made the server accept (${lens.indexOf(n)} wrong guesses first, each rejected).`, { tries: lens.indexOf(n) + 1 }));
        trace.push(...f.trace, step('accept', `The server recomputes ${hash}(secret ‖ forged message) = ${hex(f.tag)}: it matches, and the forgery is accepted.`, { ok: true }));
        return { ok: true, hash, secretLen: n, forged: f.forged, tag: f.tag, original: tag, glue: f.glue, trace };
      }
    }
    trace.push(step('reject', 'No guessed secret length gave an accepted tag.', { ok: false }));
    return { ok: false, hash, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
