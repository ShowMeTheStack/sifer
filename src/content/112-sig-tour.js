// Part 11, digital signatures: the guided tour and the course, and the pages the diagram checker looks at. Both are
// taught from the signer's and the verifier's side: what each check protects, and how a nonce is kept safe.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.tours.has('sg-tour')) return;

  // ---- the guided tour ---------------------------------------------------------------------------------------------
  C.tour({
    id: 'sg-tour', title: 'Tour: digital signatures', blurb: 'What a signature gives that a MAC cannot, RSA-PSS, ECDSA with a derived nonce, Ed25519 and the nonce rules, in eight steps.',
    steps: [
      { route: 'part=signatures', target: '#main', text: 'Part 11 of the catalogue: digital signatures. Each card is a topic that runs on real values, from a toy RSA key to Ed25519 and ECDSA on P-256.' },
      { route: 'topic=p11-what', target: '#stageWrap', text: 'A MAC and a signature on the same message. Both catch a change; only the signature can be checked by a judge who holds no secret, and only one party could have made it.' },
      { target: '#btnPlay', text: 'Play steps through the run; the arrow keys go one step at a time, forwards or back.' },
      { route: 'topic=p11-pss', target: '#stageWrap', text: 'RSA-PSS field by field: the salted hash H, the data block masked by MGF1, the trailer bc, and the verifier taking it all apart again.' },
      { route: 'topic=p11-ecdsa', target: '#inputs', text: 'ECDSA with the nonce derived by RFC 6979. Change the message here and watch the HMAC chain give a new, unrelated k; sign the same message again and get the same k.' },
      { route: 'topic=p11-nonce', target: '#stageWrap', text: 'The three nonce rules, fresh, secret and uniform, and how a derived nonce keeps all three without trusting a generator.' },
      { route: 'lesson=sg-schnorr', target: '#lessonView', text: 'Lessons run the topics, ask for a prediction, and end with exercises. This one turns a proof of knowledge into a signature with a hash.' },
      { route: 'learn', target: '[data-chapter="sg-ch-rsa"]', text: 'The lessons and exercises of this part start here: sign and verify DSA, Elgamal, Schnorr and ECDSA by hand, write three verifiers, lay out a PSS block and clamp an Ed25519 scalar.' },
    ],
  });

  // ---- a course through every topic of the part --------------------------------------------------------------------
  C.course({
    id: 'sg-course', title: 'Digital signatures', blurb: 'All ten topics of part 11, from what a signature gives to choosing a scheme, with the lessons and a few exercises on the way.',
    steps: [
      { topic: 'p11-what', note: 'A MAC against a signature, and a dispute.' },
      { lesson: 'sg-what', note: 'Non-repudiation.' },
      { exercise: 'sg-x-mac-prop', note: 'The property a MAC lacks.' },
      { topic: 'p11-rsa-sign', note: 'Raw RSA signing, and hash-then-sign.' },
      { exercise: 'sg-x-rsa-crt', note: 'Sign by the CRT at toy size.' },
      { topic: 'p11-pss', note: 'The PSS block, field by field.' },
      { lesson: 'sg-pss', note: 'Encode, sign, verify.' },
      { exercise: 'sg-x-pss-table', note: 'Lay out the block.' },
      { topic: 'p11-elgamal', note: 'A nonce commitment and why it verifies.' },
      { topic: 'p11-dsa', note: 'Two lanes: modulo p and modulo q.' },
      { lesson: 'sg-dsa', note: 'From Elgamal to DSA.' },
      { exercise: 'sg-x-dsa-code', note: 'Write the verifier.' },
      { topic: 'p11-schnorr', note: 'Commit, challenge, respond; then a hash plays the verifier.' },
      { lesson: 'sg-schnorr', note: 'Fiat–Shamir.' },
      { exercise: 'sg-x-schnorr-code', note: 'Write Schnorr verification.' },
      { topic: 'p11-ecdsa', note: 'ECDSA with an RFC 6979 nonce.' },
      { exercise: 'sg-x-ecdsa-verify', note: 'Verify by hand on a 23-point curve.' },
      { exercise: 'sg-x-ecdsa-code', note: 'Write ECDSA verification.' },
      { topic: 'p11-ed25519', note: 'Clamping, a derived nonce, and the cofactor.' },
      { exercise: 'sg-x-ed-clamp', note: 'Clamp a scalar.' },
      { topic: 'p11-nonce', note: 'Fresh, secret, uniform.' },
      { lesson: 'sg-nonce', note: 'The nonce rules and their defences.' },
      { exercise: 'sg-x-nonce-fresh', note: 'Nonces on cloned servers.' },
      { topic: 'p11-compare', note: 'Sizes, costs and security levels.' },
      { lesson: 'sg-choose', note: 'Choosing a scheme.' },
      { exercise: 'sg-x-choose', note: 'Choose for a messaging app.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -------------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'lesson sg-what')) {
    const lessonReady = "document.querySelector('#lessonView')", exReady = "document.querySelector('#exerciseView')";
    for (const id of C.chapters.filter((c) => c.part === 'signatures').flatMap((c) => c.lessons)) S.Checks.push({ group: 'learn', name: 'lesson ' + id, hash: 'lesson=' + id, ready: lessonReady, sel: '#main' });
    for (const id of ['sg-x-dispute', 'sg-x-rsa-crt', 'sg-x-pss-table', 'sg-x-elg-sign', 'sg-x-dsa-verify', 'sg-x-dsa-code', 'sg-x-schnorr-code', 'sg-x-ecdsa-sign', 'sg-x-ecdsa-verify', 'sg-x-ecdsa-code', 'sg-x-ed-clamp', 'sg-x-sizes'])
      S.Checks.push({ group: 'learn', name: 'exercise ' + id, hash: 'exercise=' + id, ready: exReady, sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'course sg-course', hash: 'course=sg-course', ready: "document.querySelector('#courseView')", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
