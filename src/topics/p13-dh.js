// Part 13, Diffie–Hellman as message-sequence charts with real numbers: the plain exchange with an eavesdropper,
// Mallory in the middle running one exchange with each side and rewriting a message, and the exchange authenticated
// with signatures, where the same substitution is caught.
(function (S) {
  'use strict';
  const U = S.P12, Q = S.P13, Pr = () => S.Proto;
  /** a message's content with its real value, when it carries one */
  const term = (s) => {
    const vs = s.values ? Object.entries(s.values).filter(([k]) => /^g\^/.test(k)) : [];
    return vs.length ? vs.map(([k, v]) => k + ' = ' + U.cut(v, 14)).join(', ') + (s.terms.length > vs.length ? ', ' + s.content.split(', ').slice(vs.length).join(', ') : '') : s.content;
  };
  const bad = (id, a) => (id === 'M' || id === 'E') && /^g\^(a|b)(m|b)/.test(a);

  const DH = {
    dh: { run: (o) => Pr().dh(o), order: ['A', 'B', 'E'], check: ['(g^b)^a', '(g^a)^b: the same key'], note: ['group fixed; secrets a and b chosen', 'Eve saw g^a and g^b, nothing more'], sub: 'a shared key from two public messages' },
    mitm: { run: (o) => Pr().dhMitm(o), order: ['A', 'M', 'B'], check: ['tag verifies: Bob trusts it'], note: ['Alice shares a key with Mallory, and so does Bob', 'Mallory reads it and rewrites it'], sub: 'Mallory runs one exchange with each side' },
    auth: { run: (o) => Pr().dhAuth(o), order: ['A', 'B'], check: ['Bob\'s signature covers both shares', 'Alice\'s signature covers both', 'same g^ab, and both know who holds it'], note: ['each has a signing key, and trusts the other\'s public key'], sub: 'each side signs both shares' },
    'auth-mitm': { run: (o) => Pr().dhAuth(Object.assign({ mitm: true }, o)), order: ['A', 'M', 'B'], check: ['signature does not cover g^a: abort'], note: ['each has a signing key, and trusts the other\'s public key', 'Mallory cannot sign as Bob'], sub: 'the same substitution, now caught' },
  };
  function make(scenarios) {
    return (inp) => {
      const sc = DH[inp.scenario], res = sc.run({ seed: +inp.seed, group: inp.group });
      const frames = Q.mscFrames(res, { order: sc.order, check: sc.check, note: sc.note, sub: sc.sub, bad, term, hl: (s) => (s.type === 'message' ? [1] : s.type === 'check' ? [2] : [0]), facts: () => ({ resValues: res.values }) });
      const last = frames[frames.length - 1];
      last.say = last.say.replace(/([^.!?])$/, '$1.') + ' ' + res.summary;
      Object.assign(last.facts, { summary: res.summary, keysMatch: res.keysMatch, attack: res.attack });
      return { frames, def: U.def(scenarios === 'auth' ? 'Signed Diffie–Hellman' : 'Diffie–Hellman', scenarios === 'auth' ? ['A → B: g^a', 'B → A: g^b, sig_B(g^a, g^b, B)', 'A → B: sig_A(g^b, g^a, A)', 'each verifies with a public key it already trusts', 'key = g^ab, bound to both identities'] : ['public: a group and a generator g', 'A picks a, sends g^a;  B picks b, sends g^b', 'A computes (g^b)^a, B computes (g^a)^b: both g^ab', 'Eve sees g^a, g^b: finding g^ab is the DH problem', 'nothing says who sent a share: a man in the middle']) };
    };
  }
  const groupInput = { id: 'group', kind: 'choice', label: 'Group', def: 'toy64', options: [{ value: 'toy64', label: 'a 64-bit prime (readable numbers)' }, { value: 'x25519', label: 'X25519 (real size)' }] };
  S.topic({
    id: 'p13-dh', family: 'p13-pki', order: 10, title: 'Diffie–Hellman, and a man in the middle',
    blurb: 'Two public messages and a shared key no eavesdropper can compute. But nothing says who sent each share: Mallory runs one exchange with Alice and another with Bob, and reads and rewrites everything.',
    inputs: [{ id: 'scenario', kind: 'choice', label: 'Run', def: 'dh', options: [{ value: 'dh', label: 'the exchange, with an eavesdropper' }, { value: 'mitm', label: 'Mallory in the middle' }] }, groupInput, { id: 'seed', kind: 'number', label: 'Seed', def: 1, min: 1, max: 999 }],
    presets: [
      { label: 'The exchange', values: { scenario: 'dh', group: 'toy64' } },
      { label: 'X25519', values: { scenario: 'dh', group: 'x25519' } },
      { label: 'Man in the middle', values: { scenario: 'mitm', group: 'toy64' } },
      { label: 'Man in the middle, X25519', values: { scenario: 'mitm', group: 'x25519', seed: 5 } },
    ],
    run: make('dh'),
    predict: [
      { at: (f) => f.meta && f.meta.step && f.meta.step.type === 'message' && f.meta.step.i === 2, pick: 'option', options: ['yes', 'no'], ask: 'Both shares have crossed the wire. Can the eavesdropper (or Mallory) now compute Alice\'s key with Bob from what she saw alone?', answer: (fr, i, inp) => (inp.scenario === 'mitm' ? 'yes' : 'no'), explain: (fr, i, inp) => (inp.scenario === 'mitm' ? 'Mallory substituted her own shares, so each side\'s key is shared with her.' : 'She has g^a and g^b but neither a nor b.') },
    ],
    quiz: [
      { q: 'What does an eavesdropper on Diffie–Hellman see?', options: ['the key', 'g^a and g^b', 'a and b', 'nothing'], answer: 1, why: 'Only the public shares; computing g^ab from them is the Diffie–Hellman problem.' },
      { q: 'Why does the man in the middle succeed?', options: ['the group is too small', 'the shares are not authenticated, so each side completes an exchange with Mallory', 'AES is weak', 'Alice reuses a'], answer: 1, why: 'Diffie–Hellman alone gives secrecy against eavesdroppers, not authentication.' },
      { q: 'Does encrypting the later messages with AEAD stop Mallory?', options: ['yes', 'no: she holds both keys, so she decrypts and re-encrypts', 'only with GCM', 'only with long keys'], answer: 1, why: 'The tags verify because Mallory computes them with the right keys.' },
      { q: 'What fixes the attack?', options: ['a bigger prime', 'authenticating the shares, for example signing them with keys from certificates', 'sending the shares twice', 'hiding g'], answer: 1, why: 'See the authenticated exchange and TLS 1.3.' },
    ],
  });
  S.topic({
    id: 'p13-authdh', family: 'p13-pki', order: 20, title: 'Authenticated Diffie–Hellman',
    blurb: 'Each side signs both shares with a long-term key whose public half the other already trusts. Mallory can still swap the shares, but she cannot make Bob\'s signature over Alice\'s share, and Alice aborts.',
    inputs: [{ id: 'scenario', kind: 'choice', label: 'Run', def: 'auth', options: [{ value: 'auth', label: 'the signed exchange' }, { value: 'auth-mitm', label: 'Mallory tries again' }] }, groupInput, { id: 'seed', kind: 'number', label: 'Seed', def: 1, min: 1, max: 999 }],
    presets: [
      { label: 'The signed exchange', values: { scenario: 'auth', group: 'toy64' } },
      { label: 'Mallory is caught', values: { scenario: 'auth-mitm', group: 'toy64' } },
      { label: 'Mallory is caught, X25519', values: { scenario: 'auth-mitm', group: 'x25519' } },
    ],
    run: make('auth'),
    predict: [
      { at: (f) => f.meta && f.meta.step && f.meta.step.type === 'message' && /old signature/.test(f.meta.step.label), pick: 'option', options: ['accept', 'abort'], ask: 'Alice receives Mallory\'s share with Bob\'s old signature. Will she accept or abort?', answer: 'abort', explain: 'Bob signed (g^m, g^b), not (g^a, g^m′): the signature does not verify for her exchange.' },
      { at: (f) => f.meta && f.meta.step && f.meta.step.type === 'message' && f.meta.step.i === 2 && !/old/.test(f.meta.step.label) && f.meta.step.from === 'B', pick: 'option', options: ['only g^b', 'g^a and g^b and his name'], ask: 'What must Bob\'s signature cover for Alice to be sure?', answer: 'g^a and g^b and his name', explain: 'Covering her own g^a ties the signature to this exchange; it cannot be replayed into another.' },
    ],
    quiz: [
      { q: 'Why must Bob\'s signature cover Alice\'s share g^a too?', options: ['it need not', 'so the signature belongs to this exchange and cannot be reused in another', 'to encrypt it', 'for speed'], answer: 1, why: 'A signature over g^b alone could be replayed by Mallory into a different exchange.' },
      { q: 'Where does Alice get Bob\'s public key?', options: ['from Bob\'s first message', 'from something she already trusts, such as a certificate chain', 'from Mallory', 'she does not need it'], answer: 1, why: 'Trusting a key from the same channel would let Mallory send her own.' },
      { q: 'Which real protocol is built this way?', options: ['TLS 1.3, with CertificateVerify over the transcript', 'WEP', 'plain HTTP', 'Kerberos'], answer: 0, why: 'The server signs the handshake transcript, which includes both key shares.' },
      { q: 'If Bob\'s signing key is later stolen, are old session keys exposed?', options: ['yes', 'no: they came from ephemeral a and b, now erased (forward secrecy)', 'only the first', 'only with RSA'], answer: 1, why: 'Signatures only authenticate; the secrets were the ephemeral exponents.' },
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
