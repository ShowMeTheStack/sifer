// Part 15, secure implementation of cryptography: the chapters and the lessons. The exercises are in 151-impl-ex.js;
// the tour, the course and the pages the diagram checker looks at in 152-impl-tour.js. The unit is defensive: each
// lesson shows, with one of the part's topics, why a defence exists, and then teaches the defence. Every value quoted
// here was worked out by the engines (S.SC and its trace source, S.SC.Fault) on the topics' own inputs.
(function (S) {
  'use strict';
  const C = S.Content;
  if (!C || C.lessons.has('im-leak')) return;
  const X = (id) => ({ exercise: id });

  C.chapter({ id: 'im-ch-leak', part: 'side', n: 1, title: 'How implementations leak', blurb: 'A correct cipher can still give its key away through the power it draws, the time it takes and the memory it touches. What leaks, measured in Hamming weights and distances.' });
  C.chapter({ id: 'im-ch-ct', part: 'side', n: 2, title: 'Constant-time programming', blurb: 'Comparisons that look at every byte, selection with masks instead of branches, and table lookups that touch the same memory whatever the secret.' });
  C.chapter({ id: 'im-ch-defend', part: 'side', n: 3, title: 'Countermeasures in practice', blurb: 'Masking, checking a result before it leaves the device, and the engineering habits that keep all of it true: vetted libraries, timing tests and a threat model.' });

  // =========================================================================================================
  // Chapter 1: how implementations leak
  // =========================================================================================================
  C.lesson({
    id: 'im-leak', chapter: 'im-ch-leak', title: 'What it means to leak', minutes: 8,
    summary: 'A chip draws a little more power for every bit that is 1, or for every bit that changes. That makes the power trace a blurred copy of the data, and the Hamming weight is the unit of the blur.',
    blocks: [
      'You have written an AES that passes every test vector. It runs on a card that a stranger can hold, power and measure. The ciphertext gives nothing away; does anything else? The answer is in the electricity: the device has to move the key through its registers, and moving data costs energy that depends on the data.',
      { def: 'Hamming weight', text: 'HW(v), the number of 1 bits in v. HW(b8) = HW(10111000) = 4.' },
      { def: 'Hamming distance', text: 'HD(a, b) = HW(a ⊕ b), the number of bits that differ, and so the number that flip when a register holding a is overwritten with b.' },
      { topic: 'sc-trace', frame: 1, caption: 'Without noise, each sample of the trace is exactly the Hamming weight of the value handled. For byte 0: the plaintext byte b8 (weight 4), p ⊕ k = d0 (weight 3) and S(p ⊕ k) = 70 (weight 3). The last two depend on the key byte.' },
      'Real measurements are noisy, so one trace shows the weights only roughly. But noise averages out, and the dependence does not.',
      { topic: 'sc-trace', frame: 3, caption: 'Over 400 traces, the power at sample 4 plotted against the weight of S(pᵢ ⊕ kᵢ): every column is spread by noise, but the means climb in a straight line, with correlation ρ = 0.771. The line is the leak a defence has to remove.' },
      { predict: { q: 'A register holds 5a and is overwritten with c3. Both values have weight 4. On a device whose power follows the Hamming distance, how many bits draw power?', options: ['0, since the weights are equal', '4', '8', 'It cannot be known'], answer: 1, explain: '5a ⊕ c3 = 99 = 10011001: four bits flip. Equal weights say nothing about the distance; a design must think about transitions, not only values.' } },
      { topic: 'sc-models', frame: 1, caption: 'The distance model: the flips are 5a ⊕ c3 = 99, four bits. CMOS logic burns power on transitions, so this is often the better description of real hardware.' },
      { topic: 'sc-models', frame: 2, caption: 'The model matters: on the weight device the weight model sees |ρ| = 0.596 and the distance model 0.134; on the distance device, 0.186 and 0.554. When you evaluate your own design, test with the model that matches its hardware, or you will underestimate the leak.' },
      { tip: 'A leak is any dependence of something measurable on a secret. Power and electromagnetic radiation follow Hamming weights and distances; time follows branches and loop counts; cache state follows memory addresses. The next lesson takes time and memory.' },
      { h: 'Recap' },
      { list: ['Power follows the data: roughly a·HW(v) per value handled, or a·HD(old, new) per register update, plus noise.', 'Noise hides a single trace but averages away over many, so it slows a measurement down; it does not remove the dependence.', 'Know which model your hardware follows: it decides which values must never appear in the clear.'] },
      X('im-x-hw'), X('im-x-hd'), X('im-x-hw-table'), X('im-x-model'),
    ],
  });

  C.lesson({
    id: 'im-channels', chapter: 'im-ch-leak', title: 'Time, branches and memory', minutes: 8,
    summary: 'Power is not the only channel. A loop that stops early, a branch on a key bit and a table indexed by a secret all make the running time or the cache state depend on the secret, and those can be measured from much further away.',
    blocks: [
      'Power analysis needs a probe on the device. A web server is out of reach of any probe, yet it can leak too: through how long it takes to answer. What in ordinary code makes the time depend on a secret?',
      { h: 'An early exit' },
      { topic: 'sc-consttime', frame: 1, caption: 'Comparing a 4-byte tag, timed without noise: the version that returns at the first difference takes 105 cycles when the first byte is wrong and 120 when only the last is. The clock counts the matching bytes. The version that looks at every byte takes 125 and 125.' },
      'Counting matching bytes is all an outsider needs to work through a tag position by position, so a cost of 2³² guesses collapses to a few thousand queries. That is why a MAC or password check must not stop early.',
      { h: 'A branch on a key bit' },
      { topic: 'sc-spa', frame: 1, caption: 'Square-and-multiply does a multiplication only for the 1 bits of the exponent: for e = 46499 the trace has 23 bursts, and a multiplication burst is longer than a squaring. The sequence of operations is the sequence of key bits.' },
      { predict: { q: 'The same naive exponentiation is run with two exponents of 16 bits each: 40961 (binary 1010000000000001) and 65535 (sixteen 1 bits). Which takes longer?', options: ['They take the same time: same length', '65535: one multiplication per 1 bit after the first', '40961: it has more zeros', 'It depends on the base only'], answer: 1, explain: 'Both do 15 squarings, but 40961 does 2 multiplications and 65535 does 15. The time reveals the number of 1 bits, and the shape of the trace reveals where they are.' } },
      { topic: 'sc-consttime', frame: 2, caption: 'Branching on each bit: 40961 costs 15 S, 2 M and 65535 costs 15 S, 15 M. Multiplying every time and keeping the product with a select that does not branch gives 15 S, 15 M for both.' },
      { h: 'An address that depends on a secret' },
      { topic: 'sc-cache', frame: 1, caption: 'Fast table-based AES looks up T0 at pᵢ ⊕ kᵢ in the first round: byte 0 reads index 6d ⊕ 68 = 05, in cache line 0. Which line is touched depends on the key, and the cache is shared with other programs on the same processor.' },
      'A cache line holds 16 table entries here, so the line touched reveals the high nibble of pᵢ ⊕ kᵢ. Another process on the same machine can learn which lines were used from its own memory access times, without any privilege and without seeing the data.',
      { warn: 'None of these leaks is a bug in the cipher. AES, square-and-multiply and the comparison all give the right answer. The leak is in how the answer is computed, which is why test vectors cannot find it.' },
      { h: 'Recap' },
      { list: ['Time depends on the secret through early exits, branches and variable-time instructions.', 'Cache state depends on the secret through addresses: any T[secret] can be observed by a neighbour.', 'The three rules of constant-time code follow: no secret branches, no secret addresses, no variable-time instructions on secrets.'] },
      X('im-x-leak-kinds'), X('im-x-always-count'),
    ],
  });

  // =========================================================================================================
  // Chapter 2: constant-time programming
  // =========================================================================================================
  C.lesson({
    id: 'im-compare', chapter: 'im-ch-ct', title: 'Comparing secrets in constant time', minutes: 7,
    summary: 'To compare a received tag with the right one, look at every byte, OR the differences together, and test the result once. The loop then runs the same number of times whether the first byte or the last is wrong.',
    blocks: [
      'Every MAC check, password-hash check and padding check ends with a comparison. The obvious loop, which returns false at the first mismatch, is correct and fast. Why replace it?',
      { topic: 'sc-mac-timing', frame: 0, caption: 'The leaky server: it checks a 4-byte tag byte by byte and returns at the first difference, so a guess with one more right byte takes one more loop iteration, a few cycles under noise of σ = 3 cycles.' },
      'A few cycles under noise seems safe. It is not, because a caller can repeat a query and average. The defence is to make the difference zero, not small.',
      { code: '// constant time: every byte is visited, the result is tested once\nfunction tagsEqual(a, b) {          // a, b: byte arrays of the same, public, length\n  let d = 0;\n  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];\n  return d === 0;\n}' },
      { predict: { q: 'Why OR the differences into d rather than add them?', options: ['OR is faster than addition', 'OR never loses a difference and stays a byte: d is 0 exactly when every a[i] ⊕ b[i] is 0', 'Addition would leak through the carry', 'There is no reason; both are wrong'], answer: 1, explain: 'Each a[i] ⊕ b[i] is 0 only for equal bytes, and OR keeps every 1 bit it ever sees, so d = 0 if and only if all bytes match. A sum works too as long as it cannot overflow, but OR is the idiom: it is simple and cannot wrap around.' } },
      { topic: 'sc-mac-timing', frame: 2, input: { ct: 'yes' }, caption: 'The same averaging against the constant-time comparison: at every position the slowest value is wrong, and the tag pieced together, 92320852, is rejected. A constant-time comparison gives the clock nothing to read.' },
      { h: 'The details that matter' },
      { list: ['The lengths must be public, or compared first: a tag of the wrong length can be rejected at once, since its length is not a secret.', 'Turn d into a yes or no without a branch where you can: `((d - 1) >>> 8) & 1` is 1 exactly when d = 0 (for d up to 255).', 'Use the library\'s function when there is one: Node\'s `crypto.timingSafeEqual`, or the equivalent in your language, is written and reviewed for exactly this.'] },
      { h: 'Recap' },
      { list: ['An early exit makes time count the matching prefix; averaging defeats noise.', 'Visit every byte, OR the XORs into d, test d once.', 'Lengths are public; contents are not.'] },
      X('im-x-ct-snippets'), X('im-x-code-diff'), X('im-x-code-eq'),
    ],
  });

  C.lesson({
    id: 'im-select', chapter: 'im-ch-ct', title: 'Selection without branches', minutes: 8,
    summary: 'When a secret bit must choose between two values, compute both and pick one with a mask: m = −bit is all zeros or all ones, and y ⊕ ((x ⊕ y) & m) is x or y. The same trick gives branch-free minimum, maximum and conditional swaps.',
    blocks: [
      'Square-and-multiply needs to keep a product only when the key bit is 1. The ladder on an elliptic curve needs to swap two points only when the bit is 1. An `if` on the bit gives it away through time and through the processor\'s branch predictor. How do you choose without choosing?',
      { def: 'Mask', text: 'a word that is all zeros or all ones. In 32-bit arithmetic, m = −bit gives 00000000 for bit = 0 and ffffffff for bit = 1.' },
      { math: 'm = −bit                       (0 → 00000000, 1 → ffffffff)\nselect(bit, x, y) = y ⊕ ((x ⊕ y) & m)\n   bit = 0: y ⊕ 0 = y\n   bit = 1: y ⊕ x ⊕ y = x' },
      { predict: { q: 'With bit = 1, x = 3c5a96f0 and y = 0f0f1234, what is (x ⊕ y) & m?', options: ['00000000', '335584c4', 'ffffffff', '3c5a96f0'], answer: 1, explain: 'The mask is ffffffff, so (x ⊕ y) & m = x ⊕ y = 335584c4, and y ⊕ 335584c4 = 3c5a96f0 = x. With bit = 0 the mask clears it to 00000000 and the result is y.' } },
      { topic: 'sc-consttime', frame: 2, caption: 'Exponentiation done this way: multiply every time, keep the product with the mask select. 40961 and 65535 both cost 15 S, 15 M.' },
      { topic: 'sc-spa', frame: 2, input: { always: 'yes' }, caption: 'The same exponent, 46499, run multiply-always: the bursts alternate S, M, S, M whatever the bits, so any exponent of the same length gives a trace of the same shape. The sequence of operations no longer depends on the bits.' },
      { topic: 'sc-spa', frame: 3, input: { always: 'yes' }, caption: 'The price is about a third more work. And the extra multiplication must feed the result through the mask select: a dummy multiplication whose result is simply thrown away can be found by disturbing it and seeing whether the output changes.' },
      { h: 'Comparisons without branches' },
      'A minimum or maximum on secret words is a selection too: work out whether a < b as a bit, then select. The bit must come from arithmetic, not from `<`, which compilers often turn into a branch. For unsigned 32-bit words the borrow of a − b gives it:',
      { math: 'lt = (a ⊕ ((a ⊕ b) | ((a − b) ⊕ a))) ≫ 31      (1 if a < b, unsigned, else 0)\nmin(a, b) = select(lt, a, b)' },
      { warn: 'In JavaScript, numbers are doubles: write `>>> 0` to bring a result back to an unsigned 32-bit word, and `(a - b) >>> 0` for the 32-bit difference. In C, use unsigned types; signed overflow is undefined behaviour, and the compiler may then do anything.' },
      { tip: 'The Montgomery ladder does one squaring and one multiplication per bit whatever the bit, and swaps two registers with exactly this mask trick (a conditional swap). It is the standard shape for scalar multiplication on curves.' },
      { h: 'Recap' },
      { list: ['m = −bit is a mask of all zeros or all ones; y ⊕ ((x ⊕ y) & m) selects without a branch.', 'Compute both sides, then select; never discard a result in a way an outsider could detect.', 'Get comparison bits from arithmetic (the borrow), not from `<` or `?:`.'] },
      X('im-x-select-table'), X('im-x-code-select'), X('im-x-code-min'), X('im-x-branch'),
    ],
  });

  C.lesson({
    id: 'im-lookup', chapter: 'im-ch-ct', title: 'Table lookups without secret addresses', minutes: 7,
    summary: 'A lookup T[secret] tells the cache which line was needed. Constant-time code either reads every entry and keeps one with a mask, computes the function with bit operations instead of a table, or uses the processor\'s own instructions.',
    blocks: [
      'S-boxes and precomputed tables make ciphers fast. Their weakness is the address: the index is secret, and the address is not hidden from the cache. What can replace T[i]?',
      { topic: 'sc-cache', frame: 0, caption: 'Table-based AES: four tables of 256 four-byte entries, 16 cache lines each. In the first round the index is pᵢ ⊕ kᵢ, plaintext mixed with key, so which line is touched follows the key.' },
      { topic: 'sc-consttime', frame: 3, caption: 'Reading every entry and keeping the one wanted with a mask touches the same lines every time. The three rules: no secret branches, no secret addresses, no variable-time instructions on secrets.' },
      { code: '// constant time: read all 256 entries, keep entry idx with a mask\nfunction ctLookup(table, idx) {\n  let r = 0;\n  for (let i = 0; i < 256; i++) {\n    const m = -(((i ^ idx) - 1) >>> 31) & 0xff;   // ff when i = idx, else 00\n    r |= table[i] & m;\n  }\n  return r;\n}' },
      { predict: { q: 'The scan reads 256 entries for every lookup instead of 1. AES does 16 lookups per round. Roughly how much slower is a full scan per lookup, ignoring the cache?', options: ['No slower', 'About twice', 'About 256 times', 'About 16 times'], answer: 2, explain: 'Each lookup costs 256 reads and masks instead of one read. That is why real constant-time AES does not scan; it computes the S-box with bit operations (bitslicing) or uses the processor\'s AES instructions.' } },
      { h: 'Three ways out' },
      { table: [['Approach', 'How it avoids secret addresses', 'Cost'], ['Scan with masks', 'reads every entry, keeps one', 'one read per table entry, per lookup'], ['Bitslicing', 'computes the S-box as a fixed circuit of AND, XOR and NOT on many blocks at once', 'fast when many blocks are processed together'], ['Hardware instructions (AES-NI and the like)', 'the S-box is inside the processor, with no memory access', 'fastest; needs the hardware']], caption: 'For AES, use the hardware instructions when present and a bitsliced implementation otherwise. A scan is the fallback for small tables.' },
      { topic: 'sc-defences', frame: 4, caption: 'The map of defences: cache timing is answered by no secret-dependent addresses. Run against T-table AES the measurement recovers 16 of 16 high nibbles; with no secret addresses there is nothing to time.' },
      { warn: 'Random delays do not fix a timing leak. They add noise, which averages away over more measurements, exactly like the noise in a power trace.' },
      { h: 'Recap' },
      { list: ['T[secret] leaks the cache line through the time of other code on the same processor.', 'Replace it: a masked scan for small tables, bitslicing or hardware instructions for ciphers.', 'Noise and delays only raise the number of measurements; they do not remove the dependence.'] },
      X('im-x-code-lookup'), X('im-x-lookup-fix'),
    ],
  });

  // =========================================================================================================
  // Chapter 3: countermeasures in practice
  // =========================================================================================================
  C.lesson({
    id: 'im-masking', chapter: 'im-ch-defend', title: 'Masking', minutes: 9,
    summary: 'Split each secret value into random shares that XOR back to it, and compute on the shares. Each share on its own is uniformly random, so its Hamming weight says nothing about the secret, and a measurement must combine several points at once.',
    blocks: [
      'Constant-time code fixes time and addresses, but on a device a stranger can probe, the power still follows the Hamming weight of every value handled. Making that weight independent of the secret is the job of masking. Why is it needed, when noise is already there?',
      { topic: 'sc-cpa-traces', frame: 4, caption: 'Noise only raises the price. As medians over three runs: σ = 2 needs 100 traces, σ = 4 needs 200, σ = 6 needs 300, σ = 8 needs 800. The number grows roughly like σ², and a determined attacker can collect more traces.' },
      { math: 'ρ ≈ √(Var HW / (Var HW + σ²)),   Var HW = 2 for a uniform byte\ntraces needed N ≈ c / ρ²   (c between about 20 and 30)\n⇒ N ≈ c·(2 + σ²) / 2' },
      'This is a sizing rule for a defender. With c = 25 and σ = 4 it predicts 225 traces, near the 200 the topic measured. Doubling the noise multiplies the cost only by about four, so noise is a support for masking, never a replacement.',
      { h: 'Shares' },
      { def: 'Boolean masking', text: 'hold x as two shares, x ⊕ m and m, with m fresh and uniformly random for every run. Neither share alone depends on x.' },
      { topic: 'sc-masking', frame: 0, caption: 'A masked S-box lookup with mIn = 5a and mOut = c3: the table is recomputed as T[x ⊕ mIn] = S(x) ⊕ mOut. The device holds x ⊕ mIn = 36, never x = 6c; T[36] = 93, and only the final unmasking gives S(x) = 50.' },
      { predict: { q: 'x = 6c has weight 4. With a fresh uniformly random mask m, what is the chance that x ⊕ m has weight 4?', options: ['1, it always has the weight of x', 'The same as for any uniform byte: 70/256', '0', '1/2'], answer: 1, explain: 'x ⊕ m with uniform m is itself a uniform byte, whatever x is, so its weight is 4 with chance C(8, 4)/256 = 70/256. That independence is the whole point.' } },
      { topic: 'sc-masking', frame: 1, caption: 'Against 2000 traces of the masked device, the first-order correlation of the true key byte is only 0.052, below the best wrong guess\'s 0.183; it ranks 207 of 256. The single-point leak is gone.' },
      { topic: 'sc-masking', frame: 3, caption: 'One mask is not the end: combining the sample of the mask with the sample of the masked value brings the dependence back, a second-order measurement. Every extra share raises the order again, and with noise the cost grows steeply with the order.' },
      { list: ['First-order masking (two shares) forces a measurement to combine two points; masking with d + 1 shares forces it to combine d + 1.', 'Masks must be fresh for every run and never reach a register together with the value they hide: on a Hamming-distance device, overwriting x ⊕ m with m leaks HW(x).', 'Linear steps (XOR, shifts, MixColumns) work share by share; non-linear steps (the S-box, AND) need a masked table or a masked gadget.'] },
      { h: 'Recap' },
      { list: ['Noise multiplies the trace count by roughly σ²; it slows a measurement but does not stop it.', 'Masking splits x into random shares, so no single value handled depends on x.', 'More shares raise the order of the measurement needed; masking plus noise plus shuffling is the standard combination.'] },
      X('im-x-shares'), X('im-x-masked-sbox'), X('im-x-traces'), X('im-x-noise-design'), X('im-x-share-order'),
    ],
  });

  C.lesson({
    id: 'im-verify', chapter: 'im-ch-defend', title: 'Check before release', minutes: 7,
    summary: 'A glitch in the clock or the supply voltage can corrupt one step of a computation. If a corrupted result leaves the device, it can be worth more to an attacker than a correct one. The defence is to verify every result before it is released, and release nothing when the check fails.',
    blocks: [
      'Side channels watch a device; fault attacks disturb it. A brief spike on the power line, a laser on the die or a clock pulse that comes too early can flip a bit in a register. Most of the time the output is merely wrong. Why would a wrong signature be dangerous?',
      { topic: 'sc-fault', frame: 1, caption: 'RSA signing with the Chinese remainder theorem: two half-size exponentiations, s_p = m^dp mod p and s_q = m^dq mod q, joined by Garner\'s formula, about four times faster than one exponentiation mod N.' },
      'The speed-up comes from computing modulo each prime separately. If a fault spoils only one half, the released signature is right modulo one prime and wrong modulo the other, and that asymmetry is enough to expose a factor of N. One faulty signature costs the whole key. The topic shows that it happens; the lesson here is what to do about it.',
      { predict: { q: 'Which check catches every fault in either half, at the lowest cost?', options: ['Sign twice and compare the two signatures', 'Verify s^e ≡ m (mod N) with the public exponent before releasing s', 'Check that s is smaller than N', 'Add random delays to the signer'], answer: 1, explain: 'Verifying with the public key costs one exponentiation with e = 65537, which is 17 multiplications, and it catches any fault that changes s. Signing twice doubles the cost and misses a fault that strikes both runs the same way.' } },
      { topic: 'sc-fault', frame: 2, input: { check: 'yes' }, caption: 'With the check: the glitch still flips bit 5 of s_q, the signer computes s^e, sees that it is not m, and releases nothing.' },
      { topic: 'sc-fault', frame: 3, input: { check: 'yes' }, caption: 'The faulty signature never leaves the device. The check costs one exponentiation with the small public exponent: cheap next to the signing itself.' },
      { h: 'The general pattern' },
      { list: ['Verify before release: re-encrypt and compare, verify a signature, or run an inverse operation, then output only on success.', 'On failure output nothing useful: no partial result, no detailed error, and possibly a counter that locks the device after repeated failures.', 'Make the check itself hard to skip: a single fault on a branch can jump over it, so hardened code checks twice, or folds the check into the result (an error word ORed into the output).', 'Use hardware help where it exists: glitch and light sensors, and clock and voltage monitors.'] },
      { warn: 'Faults also defeat dummy operations. If a multiply-always exponentiation throws away the dummy result, a fault there leaves the output correct, and a fault in a real step does not: the output then tells which steps were real. Feed every result into the output through a mask select.' },
      { h: 'Recap' },
      { list: ['A fault in one half of RSA-CRT turns one released signature into a factor of N.', 'Verify s^e ≡ m before releasing s: 17 multiplications for e = 65537.', 'Release nothing on failure, protect the check itself, and avoid results that are computed and silently discarded.'] },
      X('im-x-verify-cost'), X('im-x-fault-fit'),
    ],
  });

  C.lesson({
    id: 'im-practice', chapter: 'im-ch-defend', title: 'Engineering practice', minutes: 8,
    summary: 'Write as little cryptographic code as you can: use a vetted library. For the code you do write, state the threat model, test constant-time behaviour statistically and with tools, and remember that compilers and processors can undo what the source says.',
    blocks: [
      'The previous lessons gave the techniques. Each one fails silently: a constant-time function still passes its test vectors after a compiler turns its mask back into a branch, and a masked implementation still decrypts correctly with a mask that is never refreshed. What practice catches that?',
      { topic: 'sc-defences', frame: 0, caption: 'The attacks of this part on the left, the defences on the right, and a line for each defence that answers an attack. No single defence covers every channel.' },
      { h: 'Start from a threat model' },
      'Which channels can an attacker reach? A server on the internet faces timing over the network. A virtual machine in a shared cloud faces cache timing from its neighbours. A card or a meter in the attacker\'s hands faces power, electromagnetic probes and faults. The answer decides what you must defend against, and what you may leave out.',
      { table: [['Setting', 'Reachable channels', 'Defences that fit'], ['Server answering over a network', 'response time', 'constant-time comparison and arithmetic'], ['Virtual machine on shared hardware', 'time, cache state', 'constant time, no secret addresses'], ['Smartcard or meter in the attacker\'s hands', 'power, EM, time, faults', 'all of the above, plus masking, shuffling, checks before release, sensors']], caption: 'The threat model decides which defences are required; each one costs speed, code size or randomness.' },
      { predict: { q: 'A team needs to compare HMAC tags in a Node.js service. What should they do?', options: ['Write a loop that returns at the first difference', 'Call crypto.timingSafeEqual on two buffers of equal length', 'Compare the hex strings with ===', 'Add a random sleep after the comparison'], answer: 1, explain: 'The library\'s function is constant time and reviewed. String equality may stop at the first difference, and a random sleep only adds noise that averages away.' } },
      { h: 'Test it' },
      { list: ['Statistical timing tests: time the code on two classes of input, one fixed and one random, many thousands of times each, and compare the means with Welch\'s t-test. A |t| above about 4.5 says the time depends on the input.', 'Tools that track secret data through the compiled program (taint analysis under a memory checker, or a constant-time verifier) and report any branch or address that depends on it.', 'Look at the compiled code for the hot paths: optimisers can turn a mask select back into a conditional jump.', 'For devices: measure the real thing, with the attacks of this part as the test suite, as the map of defences does.'] },
      { math: 't = (mean₁ − mean₂) / √(s₁²/n₁ + s₂²/n₂)\n|t| > 4.5  ⇒  the timing depends on the class: a leak' },
      { topic: 'sc-defences', frame: 7, caption: 'Every defence has a price, so real devices stack them and are tested by trying the attacks.' },
      { tip: 'Use vetted libraries for the primitives and protocols: their constant-time code, masked implementations and fault checks have been reviewed and attacked by many people. Your own code should be the glue around them, and that glue should never branch on, index with, or log a secret.' },
      { h: 'Recap' },
      { list: ['Write a threat model first: it says which channels you must close.', 'Prefer a vetted library; test what you write with statistical timing tests and constant-time tools.', 'Check the compiled output; source that is constant time is not always machine code that is.'] },
      X('im-x-ttest'), X('im-x-threat'), X('im-x-practice'),
    ],
  });
})(globalThis.Sifer = globalThis.Sifer || {});
