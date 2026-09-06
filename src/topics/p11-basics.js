// Part 11, what a signature gives: one message protected two ways, by a MAC under a key Alice and Bob share and by an
// Ed25519 signature under Alice's own key pair. Both catch a change in transit; only the signature convinces a third
// person, because only Alice could have made it.
(function (S) {
  'use strict';
  const W = S.P11;
  const ED = () => S.ECC.Ed25519;

  S.topic({
    id: 'p11-what', family: 'p11-basics', order: 10, title: 'What a signature gives, and what a MAC does not',
    blurb: 'A MAC and a signature both catch a changed message. A MAC tag can be made by anyone who holds the shared key, so it convinces the partner but nobody else. A signature can be made only with the private key and checked by anyone with the public key: integrity, authenticity and non-repudiation.',
    inputs: [
      W.textIn('msg', 'Message', 'deliver 40 crates to dock 7'),
      W.textIn('fake', 'Bob\'s altered message', 'deliver 400 crates to dock 7'),
      W.hexIn('mk', 'Shared MAC key K (hex)', W.hex(W.sha256('the key Alice and Bob share')), 32),
      W.hexIn('seed', 'Alice\'s Ed25519 secret (hex)', W.hex(W.sha256('Alice keeps this seed private')), 32),
    ],
    presets: [
      { label: 'Crates', values: { msg: 'deliver 40 crates to dock 7', fake: 'deliver 400 crates to dock 7' } },
      { label: 'A grade', values: { msg: 'final mark for student 1182: B', fake: 'final mark for student 1182: A' } },
      { label: 'Other keys', values: { msg: 'release build 3.1 is approved', fake: 'release build 3.2 is approved', mk: W.hex(W.sha256('a second shared key')), seed: W.hex(W.sha256('a second private seed')) } },
    ],
    check(inp) { return inp.msg === inp.fake ? 'The altered message must differ from the message' : null; },
    run(inp) { return W.memo('p11-what', inp, () => what(inp)); },
    predict: [
      { at: (f) => f.meta.phase === 'sig-tamper', pick: 'option', ask: 'Bob now claims Alice sent the altered message, and shows a judge an HMAC tag he computed for it with K. Can the judge tell whether Alice or Bob made that tag?', options: ['yes', 'no'], answer: 'no', explain: (fr, i) => fr[i + 1].say },
      { at: (f) => f.meta.phase === 'mac-dispute', pick: 'option', ask: 'Can Bob make a signature on the altered message that verifies under Alice\'s public key?', options: ['yes, he has the public key', 'no, he would need Alice\'s private key'], answer: 'no, he would need Alice\'s private key', explain: (fr, i) => fr[i + 1].say },
    ],
    quiz: [
      { q: 'Which property do MAC tags lack that a signature has?', options: ['integrity', 'authenticity towards the partner', 'non-repudiation', 'a fixed length'], answer: 2, why: 'Both parties hold the MAC key, so either could have made any tag; a third person cannot tell them apart.' },
      { q: 'Who can verify an Ed25519 signature?', options: ['only Alice', 'only Bob', 'anyone who has Alice\'s public key', 'anyone who has the shared key'], answer: 2, why: 'Verification uses the public key alone.' },
      { q: 'A changed message arrives with the old tag or signature. What happens?', options: ['both checks fail', 'only the MAC check fails', 'only the signature check fails', 'both pass'], answer: 0, why: 'Both protect integrity: the tag and the signature each depend on every byte of the message.' },
      { q: 'Why are MACs still used everywhere, inside TLS for example?', options: ['they are much faster and shorter, and the two ends already share a key', 'they give non-repudiation', 'signatures cannot protect integrity', 'they need no key'], answer: 0, why: 'Between two parties who share a key, MACs are the cheaper tool; signatures are for proof to others and for keys that are public.' },
      { q: 'Non-repudiation means…', options: ['the message is secret', 'the signer cannot later deny having signed', 'the message cannot be replayed', 'the key cannot be lost'], answer: 1, why: 'Only the holder of the private key could have produced a valid signature.' },
    ],
  });

  function what(inp) {
    const msg = String(inp.msg), fake = String(inp.fake), mk = W.unhex(inp.mk), seed = W.unhex(inp.seed);
    const mac = (m) => S.MAC.hmac('sha256', mk, W.utf8(m));
    const tag = mac(msg), tagF = mac(fake), tagHex = W.hex(tag), tagFHex = W.hex(tagF);
    const sg = ED().sign(seed, W.utf8(msg)), pub = sg.pub, sigHex = W.hex(sg.sig), pubHex = W.hex(pub);
    const vOk = ED().verify(pub, W.utf8(msg), sg.sig).ok, vBad = ED().verify(pub, W.utf8(fake), sg.sig).ok;
    const tagOk = W.hex(mac(msg)) === tagHex, tagBad = tagFHex === tagHex;
    const F = new S.Frames();
    const XA = 118, XB = 450, XC = 782, BW = 204;
    const people = [...W.party('pa', XA, 46, 'Alice', 'alice'), ...W.party('pb', XB, 46, 'Bob', 'bob'), ...W.party('pc', XC, 46, 'Carol, a judge', '')];
    const mBand = W.panel('bm', 6, 110, 888, 150, 'MAC: one key K, held by Alice and by Bob');
    const sBand = W.panel('bs', 6, 276, 888, 150, 'signature: Alice\'s private key, her public key A for everyone');
    const YM = 188, YS = 354;
    const sh = (h) => W.hs(h, 6);
    const blk = (key, x, y, label, text, cls, title) => W.hb(key, x, y, label, text, cls, BW, title);
    const mKeys = [blk('ma', XA, YM, 'shared key K', sh(inp.mk), 'key', 'K = ' + inp.mk), blk('mb', XB, YM, 'shared key K', sh(inp.mk), 'key', 'K = ' + inp.mk), blk('mc', XC, YM, 'Carol', 'has no key', 'soft')];
    const sKeys = [blk('sa', XA, YS, 'private seed (secret)', sh(inp.seed), 'key', 'seed = ' + inp.seed), blk('sb', XB, YS, 'public key A', sh(pubHex), 'good', 'A = ' + pubHex), blk('sc', XC, YS, 'public key A', sh(pubHex), 'good', 'A = ' + pubHex)];
    const quote = (m) => '"' + (m.length > 30 ? m.slice(0, 29) + '…' : m) + '"';
    const note = (text, cls) => W.t('note', 450, 470, text, 'strong ' + (cls || ''), 'middle', 15);
    const add = (items, say, facts, meta) => F.add({ items: people.concat(meta.phase === 'table' ? [] : mBand.concat(sBand), items), say, facts: Object.assign({ msg, fake }, facts), meta });

    add([...mKeys, ...sKeys], `Alice will send Bob the message "${msg}" twice over: once with an HMAC tag under the key K they share, once with an Ed25519 signature under her own private seed. Her public key A = ${sh(pubHex)} is published; Carol, a judge, holds nothing secret.`, { pub: pubHex, sp: sh(pubHex) }, { phase: 'setup' });

    const mSent = [blk('ma', XA, YM, 'tag = HMAC(K, m)', sh(tagHex), 'act', 'tag = ' + tagHex), ...W.arrow('mw1', XA + BW / 2, XB - BW / 2, YM, 'm, tag', 'act'), blk('mb', XB, YM, 'Bob: HMAC(K, m) again', sh(W.hex(mac(msg))), tagOk ? 'good' : 'bad'), W.verdict('mv', XB, YM + 50, tagOk, 'equal: accept'), mKeys[2]];
    add([...mSent, ...sKeys], `The MAC: Alice computes tag = HMAC-SHA-256(K, m) = ${sh(tagHex)}, ${tag.length} bytes, and sends it with m. Bob, who also holds K, computes the same function and gets the same ${tag.length} bytes, so the message is unchanged and came from someone holding K.`, { tag: tagHex, st: sh(tagHex), len: tag.length }, { phase: 'mac' });

    const mTamper = [mSent[0], ...W.arrow('mw1', XA + BW / 2, XB - BW / 2, YM, 'm′, tag', 'bad'), blk('mb', XB, YM, 'Bob: HMAC(K, m′)', sh(tagFHex), tagBad ? 'good' : 'bad', 'HMAC(K, m′) = ' + tagFHex), W.verdict('mv', XB, YM + 50, tagBad, tagBad ? 'equal' : 'differs: reject'), mKeys[2]];
    add([...mTamper, ...sKeys], `Suppose the message is changed on the way to ${quote(fake)}. Bob's HMAC of what arrived is ${sh(tagFHex)}, not the tag ${sh(tagHex)}: he rejects it. That is integrity.`, { tag: tagHex, tagF: tagFHex, sh: [sh(tagHex), sh(tagFHex)] }, { phase: 'mac-tamper' });

    const sSent = [blk('sa', XA, YS, 'σ = Sign(seed, m)', sh(sigHex), 'act', 'σ = ' + sigHex), ...W.arrow('sw1', XA + BW / 2, XB - BW / 2, YS, 'm, σ', 'act'), blk('sb', XB, YS, 'Verify(A, m, σ)', vOk ? 'valid' : 'invalid', vOk ? 'good' : 'bad'), W.verdict('sv', XB, YS + 50, vOk, 'valid under A'), sKeys[2]];
    add([...mSent, ...sSent], `The signature: Alice signs m with her private seed. The Ed25519 signature σ = ${sh(sigHex)} is ${sg.sig.length} bytes. Bob checks it with the public key A and nothing else: ${vOk ? 'valid' : 'invalid'}.`, { sig: sigHex, ss: sh(sigHex), len: sg.sig.length }, { phase: 'sig' });

    const sTamper = [sSent[0], ...W.arrow('sw1', XA + BW / 2, XB - BW / 2, YS, 'm′, σ', 'bad'), blk('sb', XB, YS, 'Verify(A, m′, σ)', vBad ? 'valid' : 'invalid', vBad ? 'good' : 'bad'), W.verdict('sv', XB, YS + 50, vBad, vBad ? 'valid' : 'fails: reject'), sKeys[2]];
    add([...mTamper, ...sTamper], `The same change to ${quote(fake)} breaks the signature too: σ was made for m, and Verify(A, m′, σ) ${vBad ? 'passes' : 'fails'}. For integrity, the MAC and the signature are equally good.`, { ok: vBad }, { phase: 'sig-tamper' });

    const mDispute = [blk('ma', XA, YM, 'Alice\'s tag on m', sh(tagHex), 'act', 'tag = ' + tagHex), blk('mb', XB, YM, 'Bob: HMAC(K, m′)', sh(tagFHex), 'hot', 'tag′ = ' + tagFHex), ...W.arrow('mw2', XB + BW / 2, XC - BW / 2, YM, 'm′, tag′', 'hot'), blk('mc', XC, YM, 'Carol, given K', 'tag′ checks out', 'hot'), W.t('mq', XC, YM + 50, 'made by Alice or by Bob?', 'bad', 'middle', 15)];
    add([...mDispute, ...sKeys], `Now a dispute. Bob says Alice sent ${quote(fake)} and shows Carol a tag for it, ${sh(tagFHex)}. He made it himself: he holds K. Even if Carol is given K, the tag checks out, and she cannot tell whether Alice or Bob made it. So the MAC gives no non-repudiation.`, { tagF: tagFHex, sh: sh(tagFHex) }, { phase: 'mac-dispute' });

    const sDispute = [blk('sa', XA, YS, 'σ = Sign(seed, m)', sh(sigHex), 'act', 'σ = ' + sigHex), blk('sb', XB, YS, 'Bob: no private seed', 'cannot sign m′', 'bad'), ...W.arrow('sw2', XB + BW / 2, XC - BW / 2, YS, 'm′, σ', 'hot'), blk('sc', XC, YS, 'Carol: Verify(A, m′, σ)', vBad ? 'valid' : 'invalid', vBad ? 'good' : 'bad'), W.t('sq', XC, YS + 50, 'but (m, σ) is valid: only Alice', 'good', 'middle', 14)];
    add([...mDispute, ...sDispute], `With signatures the dispute is settled. To sign ${quote(fake)} Bob would need Alice's private seed, which never left her; the old σ ${vBad ? 'passes' : 'fails'} on it. Carol checks the pair Bob shows with the public key A and it ${vBad ? 'passes' : 'fails'}, while Alice's real pair (m, σ) is ${vOk ? 'valid' : 'invalid'}. Only Alice could have made it, so she cannot deny it: non-repudiation.`, { ok: vBad }, { phase: 'sig-dispute' });

    const tb = W.table({
      prefix: 'tb', x: 35, y: 126, rh: 44, size: 14,
      cols: [{ w: 250, head: 'property' }, { w: 290, head: 'MAC (HMAC-SHA-256)' }, { w: 290, head: 'signature (Ed25519)' }],
      rows: [
        ['integrity', { text: '✓ any change is caught', cls: 'good' }, { text: '✓ any change is caught', cls: 'good' }],
        ['authenticity', { text: 'to Bob: someone with K', cls: 'hot' }, { text: '✓ to anyone with A', cls: 'good' }],
        ['non-repudiation', { text: '✗ Bob could have made it', cls: 'bad' }, { text: '✓ only the seed signs', cls: 'good' }],
        ['keys', 'one shared secret K', 'private seed, public A'],
        ['size here', tag.length + ' bytes', sg.sig.length + ' bytes'],
        ['cost', 'two hash calls', 'scalar multiplications'],
      ],
    });
    add([...tb.items, note('A MAC: fast, for two parties who share a key. A signature: proof for everyone.', '')], `In short: both give integrity. An HMAC tag (${tag.length} bytes here) authenticates only towards someone who shares the key, and either holder could have made it. A signature (${sg.sig.length} bytes) can be made only with the private key and checked by anyone, which gives authenticity to all and non-repudiation.`, { len: tag.length, slen: sg.sig.length }, { phase: 'table' });

    const fr = W.fix(F.list, { x: 0, y: 0, w: 900, h: 490 });
    for (const f of fr) f.narrowView = /^sig/.test(f.meta.phase) ? { x: 0, y: 270, w: 900, h: 220 } : f.meta.phase === 'table' ? { x: 20, y: 100, w: 860, h: 320 } : { x: 0, y: 0, w: 900, h: 270 };
    return { frames: fr, def: W.def('MAC and signature', ['MAC: tag = HMAC(K, m); verify: recompute with K', '  K is shared: either holder can make a tag', 'signature: σ = Sign(sk, m); verify: Verify(pk, m, σ)', '  only sk signs; anyone with pk verifies', 'integrity: both', 'non-repudiation: signatures only']) };
  }
})(globalThis.Sifer = globalThis.Sifer || {});
