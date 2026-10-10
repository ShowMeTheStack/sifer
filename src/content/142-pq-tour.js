// Part 14, post-quantum cryptography: the guided tour and the course, and the pages the diagram checker looks at.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.tours.has('pq-tour')) return;

  // ---- the guided tour ---------------------------------------------------------------------------------------------
  C.tour({
    id: 'pq-tour', title: 'Tour: post-quantum cryptography', blurb: 'What a quantum computer breaks, lattices and LWE, ML-KEM, and hash-based signatures, in eight steps.',
    steps: [
      { route: 'part=pq', target: '#main', text: 'Part 14 of the catalogue: post-quantum cryptography. Each card is a topic that runs on real values, from Grover\'s amplitudes to a full ML-KEM-768 exchange.' },
      { route: 'topic=pq-levels', target: '#stageWrap', text: 'What survives: Grover halves the exponent of a search, so AES-256 keeps 128 bits; Shor breaks RSA and elliptic curves at any size.' },
      { target: '#btnPlay', text: 'Play steps through the run; the arrow keys go one step at a time, forwards or back.' },
      { route: 'topic=pq-babai', target: '#stageWrap', text: 'A good basis and a bad basis of the same lattice: rounding finds the nearest point with one and misses with the other. That gap is lattice cryptography.' },
      { route: 'topic=pq-lwe', target: '#inputs', text: 'Learning with errors: change the noise bound here and watch decryption start to fail when the summed noise passes q/4.' },
      { route: 'topic=pq-mlkem-flow', target: '#stageWrap', text: 'ML-KEM-768 from seed to shared key: every polynomial vector, the compression, the noise left after decryption and the re-encryption check.' },
      { route: 'lesson=pq-lamport', target: '#lessonView', text: 'Hash-based signatures need nothing but a hash function. Lessons run the topics, ask for a prediction, and end with exercises.' },
      { route: 'learn', target: '[data-chapter="pq-ch-threat"]', text: 'The lessons and exercises of this part start here: count Grover iterations, reduce a basis, write the NTT, sign and verify with Lamport, and see why a one-time key must stay one-time.' },
    ],
  });

  // ---- a course through every topic of the part --------------------------------------------------------------------
  C.course({
    id: 'pq-course', title: 'Post-quantum cryptography', blurb: 'All eighteen topics of part 14, from Grover and Shor to McEliece, with the lessons and a few exercises on the way.',
    steps: [
      { topic: 'pq-grover', note: 'Amplitudes, sign flips and reflections.' },
      { topic: 'pq-levels', note: 'What each primitive keeps against a quantum attacker.' },
      { lesson: 'pq-grover', note: 'Why a k-bit key keeps k/2 bits.' },
      { topic: 'pq-shor', note: 'A period becomes a factor.' },
      { exercise: 'pq-x-shor-factor', note: 'Two gcds by hand.' },
      { topic: 'pq-lattice-bases', note: 'One lattice, a good basis and a bad one.' },
      { topic: 'pq-gram-schmidt', note: 'Measuring a basis.' },
      { topic: 'pq-gauss', note: 'Euclid on vectors.' },
      { exercise: 'pq-x-gauss-code', note: 'Write the reduction.' },
      { topic: 'pq-babai', note: 'The closest vector, by rounding.' },
      { topic: 'pq-lwe', note: 'A bit under noise you can see.' },
      { lesson: 'pq-lwe', note: 'Noise against failures.' },
      { exercise: 'pq-x-lwe-worst', note: 'Noise that can never cause a failure.' },
      { topic: 'pq-mlkem-flow', note: 'ML-KEM from seed to shared key.' },
      { topic: 'pq-ntt', note: 'The butterflies that make it fast.' },
      { exercise: 'pq-x-ntt-code', note: 'Write the NTT and check it against the standard\'s.' },
      { topic: 'pq-mlkem-noise', note: 'Compression and the noise budget.' },
      { topic: 'pq-mlkem-reject', note: 'Implicit rejection.' },
      { topic: 'pq-toysig', note: 'Lattice signatures abort to stay silent.' },
      { topic: 'pq-lamport', note: 'One key, one message.' },
      { exercise: 'pq-x-lamport-verify', note: 'Write Lamport verification.' },
      { topic: 'pq-winternitz', note: 'Chains and the checksum.' },
      { topic: 'pq-merkle', note: 'Many one-time keys under one root.' },
      { topic: 'pq-slhdsa', note: 'The stateless hypertree.' },
      { topic: 'pq-mceliece', note: 'A scrambled Goppa code.' },
      { lesson: 'pq-mceliece', note: 'Choosing a scheme.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -------------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'lesson pq-grover')) {
    const lessonReady = "document.querySelector('#lessonView')", exReady = "document.querySelector('#exerciseView')";
    for (const id of C.chapters.filter((c) => c.part === 'pq').flatMap((c) => c.lessons)) S.Checks.push({ group: 'learn', name: 'lesson ' + id, hash: 'lesson=' + id, ready: lessonReady, sel: '#main' });
    for (const id of ['pq-x-shor-bad-a', 'pq-x-gauss-table', 'pq-x-gauss-code', 'pq-x-lwe-fail', 'pq-x-ntt-table', 'pq-x-lamport-sign', 'pq-x-lamport-reuse', 'pq-x-wots-table', 'pq-x-merkle-path', 'pq-x-hamming'])
      S.Checks.push({ group: 'learn', name: 'exercise ' + id, hash: 'exercise=' + id, ready: exReady, sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'course pq-course', hash: 'course=pq-course', ready: "document.querySelector('#courseView')", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
