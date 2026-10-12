// Part 15, secure implementation of cryptography: the guided tour and the course, and the pages the diagram checker
// looks at. The tour and the course show each leak only as far as it explains a defence, then the defence at work.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.tours.has('im-tour')) return;

  // ---- the guided tour ---------------------------------------------------------------------------------------------
  C.tour({
    id: 'im-tour', title: 'Tour: secure implementation', blurb: 'Why correct crypto code can still leak, and the defences: constant time, masking and checking before release, in eight steps.',
    steps: [
      { route: 'part=side', target: '#main', text: 'Part 15 of the catalogue: side channels and implementation. Each topic runs on simulated measurements, so you can see a leak and then see a defence remove it.' },
      { route: 'topic=sc-trace', target: '#stageWrap', text: 'A power trace: each sample follows the Hamming weight of the value the chip handles. That dependence is what every defence in this part is about.' },
      { target: '#btnPlay', text: 'Play steps through the run; the arrow keys go one step at a time, forwards or back.' },
      { route: 'topic=sc-consttime', target: '#stageWrap', text: 'Leaky code beside constant-time code: a comparison that stops early against one that ORs every difference, a branch on a key bit against a mask select, and a secret table index against a full scan.' },
      { route: 'topic=sc-masking', target: '#inputs', text: 'Masking: the device holds x ⊕ m with a fresh random m, never x itself. Change the noise here and see how the single-point correlation disappears.' },
      { route: 'topic=sc-fault', target: '#inputs', text: 'Set the signer to check s^e = m first: a glitched RSA-CRT signature is then never released. One cheap verification closes the fault channel.' },
      { route: 'lesson=im-compare', target: '#lessonView', text: 'Lessons run the topics, ask for a prediction, and end with exercises. This one writes a constant-time comparison.' },
      { route: 'learn', target: '[data-chapter="im-ch-leak"]', text: 'The lessons and exercises of this part start here: count Hamming weights, write constant-time compare, select and minimum, fill in mask shares, size noise, and pick the defence that fits a threat model.' },
    ],
  });

  // ---- a course through every topic of the part --------------------------------------------------------------------
  C.course({
    id: 'im-course', title: 'Secure implementation of cryptography', blurb: 'All twelve topics of part 15, each followed by the defence it motivates, with the lessons and a few exercises on the way.',
    steps: [
      { topic: 'sc-trace', note: 'Power follows the Hamming weight.' },
      { topic: 'sc-models', note: 'Weight or distance: match the hardware.' },
      { lesson: 'im-leak', note: 'What it means to leak.' },
      { exercise: 'im-x-hw-table', note: 'Weights and distances by hand.' },
      { topic: 'sc-spa', note: 'A branch on a key bit, seen in one trace; then set it to multiply always.' },
      { topic: 'sc-dpa', note: 'Many traces average the noise away.' },
      { topic: 'sc-cache', note: 'Secret table indices and the cache.' },
      { lesson: 'im-channels', note: 'Time, branches and memory.' },
      { topic: 'sc-mac-timing', note: 'An early exit; then switch the comparison to constant time.' },
      { topic: 'sc-consttime', note: 'Leaky and constant-time code side by side.' },
      { lesson: 'im-compare', note: 'Comparing secrets.' },
      { exercise: 'im-x-code-eq', note: 'Write it.' },
      { lesson: 'im-select', note: 'Masks instead of branches.' },
      { exercise: 'im-x-code-select', note: 'A conditional select.' },
      { lesson: 'im-lookup', note: 'Lookups without secret addresses.' },
      { topic: 'sc-cpa', note: 'The leak stands out of the noise: why noise alone is not enough.' },
      { topic: 'sc-cpa-traces', note: 'Traces against noise: a sizing rule.' },
      { exercise: 'im-x-traces', note: 'Size it.' },
      { topic: 'sc-masking', note: 'Shares, and why one mask is not the end.' },
      { lesson: 'im-masking', note: 'Masking.' },
      { exercise: 'im-x-shares', note: 'Mask shares by hand.' },
      { topic: 'sc-fault', note: 'Set the signer to check first.' },
      { lesson: 'im-verify', note: 'Check before release.' },
      { topic: 'sc-defences', note: 'Every channel and its defence.' },
      { lesson: 'im-practice', note: 'Libraries, tests and threat models.' },
      { exercise: 'im-x-threat', note: 'Choose by the threat model.' },
    ],
  });

  // ---- what the diagram checker looks at on these pages -------------------------------------------------------------
  if (S.Checks && !S.Checks.some((c) => c.name === 'lesson im-leak')) {
    const lessonReady = "document.querySelector('#lessonView')", exReady = "document.querySelector('#exerciseView')";
    for (const id of C.chapters.filter((c) => c.id.startsWith('im-')).flatMap((c) => c.lessons)) S.Checks.push({ group: 'learn', name: 'lesson ' + id, hash: 'lesson=' + id, ready: lessonReady, sel: '#main' });
    for (const id of ['im-x-hw-table', 'im-x-ct-snippets', 'im-x-code-min', 'im-x-select-table', 'im-x-branch', 'im-x-shares', 'im-x-masked-sbox', 'im-x-ttest', 'im-x-practice'])
      S.Checks.push({ group: 'learn', name: 'exercise ' + id, hash: 'exercise=' + id, ready: exReady, sel: '#main' });
    S.Checks.push({ group: 'learn', name: 'course im-course', hash: 'course=im-course', ready: "document.querySelector('#courseView')", sel: '#main' });
  }
})(globalThis.Sifer = globalThis.Sifer || {});
