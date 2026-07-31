// The cipher bench's cards on modes of operation. Real modes get defence cards (CB.defence), not runners: CBC padding
// errors, ECB, malleable CBC and CTR, and reused CTR and GCM nonces, each linking to the defensive topics of part 6.
// The hands-on labs, on toy and classical ciphers, are in bench-cipher-labs2.js.
//   S.CipherBench.labs: [{id, title, group, blurb, has(), render(box, ctx) -> {stop()}}]   ctx = {seed, save(), U}
(function (S) {
  'use strict';
  const { h, icon } = S.UI;
  const CB = (S.CipherBench = S.CipherBench || {});
  const L = (CB.labs = CB.labs || []);
  /** the steps of a trace as numbered cards, each with its sentence */
  CB.labSteps = (trace) => h('ol.lab-steps', ...trace.map((s) => h('li', ...S.BenchUI.say(s.say))));
  /** a run button and a "new scenario" button; onRun(seed) */
  CB.labButtons = (ctx, label, onRun, extra) => {
    const go = h('button.btn.primary', { type: 'button', id: 'labRun' }, icon('run'), label);
    const again = h('button.btn', { type: 'button', id: 'labNew', title: 'A different secret key and message' }, icon('shuffle'), 'New scenario');
    go.addEventListener('click', () => onRun(ctx.seed));
    again.addEventListener('click', () => { ctx.seed++; ctx.save(); onRun(ctx.seed); });
    return h('div.brow.lab-acts', go, again, extra || null);
  };

  /**
   * A defence card in place of a runner: what goes wrong, the rule that prevents it, and the topics that show it.
   * Runners that carry out attacks on real schemes are left to the defensive topics; the toy-cipher labs stay.
   */
  CB.defence = (o) => Object.assign({ has: () => true, defence: true }, o, {
    render(box) {
      const topics = (o.topics || []).map((id) => S.byId && S.byId(id)).filter(Boolean);
      box.append(h('div.lab-area.lab-defence',
        h('ul.lab-rules', ...o.rules.map((r) => h('li', ...S.UI.inline(r)))),
        topics.length ? h('div.lab-topics', h('span.k', 'See it worked through'), ...topics.map((t) => h('a.btn.small', { href: '#topic=' + t.id, dataset: { topic: t.id } }, icon('library'), t.title))) : null));
      return { stop() {} };
    },
  });

  // ---- CBC padding: authenticate before anything is decrypted ---------------------------------------------------------
  L.push(CB.defence({
    id: 'padding', group: 'Modes', title: 'CBC padding: check the tag first',
    blurb: 'A receiver that decrypts CBC and then tells the sender, by an error message or by its timing, whether the PKCS#7 padding was valid hands out one bit about the plaintext per query. The cure is to make tampered ciphertexts fail before decryption.',
    rules: [
      'Use an AEAD mode (GCM, ChaCha20-Poly1305) or **encrypt-then-MAC**: verify the tag over the IV and ciphertext first, and refuse anything that fails without decrypting it.',
      'Never let a padding error look different from a tag error: one error, one code path, the same time.',
      'Compare tags in constant time.',
    ],
    topics: ['integrity-order', 'integrity-malleable', 'modes-padding'],
  }));

  // ---- ECB: one block, one ciphertext, nothing binding them ----------------------------------------------------------------
  L.push(CB.defence({
    id: 'ecbcut', group: 'Modes', title: 'ECB: never for more than one block',
    blurb: 'ECB encrypts every block on its own, so equal blocks give equal ciphertext and blocks from different messages fit together. A token built from ECB blocks can be reassembled into one the server never issued, and nothing in the mode notices.',
    rules: [
      'Never use ECB for data longer than one block: use an AEAD mode (GCM, ChaCha20-Poly1305) with a fresh nonce per message.',
      'Treat any token or cookie the server will trust as needing **integrity**, not just secrecy: authenticate it with a MAC or an AEAD tag and check that first.',
      'Do not let the structure of a record line up with block boundaries as a security measure: alignment is not protection.',
    ],
    topics: ['modes-ecb', 'integrity-malleable'],
  }));

  // ---- CBC and CTR: malleable without a tag ---------------------------------------------------------------------------------------
  L.push(CB.defence({
    id: 'bitflip', group: 'Modes', title: 'CBC and CTR: encryption is not integrity',
    blurb: 'In CBC a change to one ciphertext block lands, bit for bit, in the next plaintext block; in CTR it lands in the same block. Escaping what a user types does not help, because the change is made after encryption. Only a tag the receiver checks catches it.',
    rules: [
      'Use an AEAD mode, or **encrypt-then-MAC** with a separate key: the tag covers the IV or nonce, the ciphertext and any header.',
      'Verify the tag first, in constant time, and refuse the message without decrypting it if it fails.',
      'Never act on a decrypted field (a role, an amount, a flag) unless the ciphertext it came from was authenticated.',
    ],
    topics: ['integrity-malleable', 'integrity-order'],
  }));

  // ---- a reused nonce: CTR, then the GCM rules ------------------------------------------------------------------------------------
  L.push(CB.defence({
    id: 'ctrreuse', group: 'Modes', title: 'CTR: one nonce, one keystream',
    blurb: 'Two messages under the same key and the same starting counter share a keystream, so it cancels: C1 ⊕ C2 = P1 ⊕ P2, and the key no longer stands between the two messages. Any one message known or guessed exposes the other.',
    rules: [
      'Never encrypt two messages under one key with the same nonce: derive the nonce from a counter that is stored durably and never reset.',
      'If nonces are random, make them long enough (96 bits or more) and rotate the key long before a repeat becomes likely.',
      'Where a repeat cannot be ruled out, use a misuse-resistant mode such as AES-GCM-SIV.',
    ],
    topics: ['integrity-nonce'],
  }));
  L.push(CB.defence({
    id: 'gcmreuse', group: 'Modes', title: 'GCM: one nonce, one message',
    blurb: 'A repeated GCM nonce costs more than the XOR of two plaintexts: it exposes the GHASH key H, and with H the tags no longer protect anything. Every rule here is about never letting a nonce repeat under one key.',
    rules: [
      'A 96-bit nonce from a counter, kept in durable storage and never reset, is the simplest safe choice.',
      'Random 96-bit nonces are safe only up to about 2³² messages per key: rotate the key well before that.',
      'Where a repeat cannot be ruled out (cloned machines, restored backups), use a misuse-resistant mode such as AES-GCM-SIV, which loses only the fact that two messages were equal.',
    ],
    topics: ['integrity-nonce', 'modes-gcm'],
  }));
})(globalThis.Sifer = globalThis.Sifer || {});
