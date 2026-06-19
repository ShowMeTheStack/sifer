// Square-and-multiply: x^e mod n by reading the exponent's bits from the left, with BigInt. Each bit squares the
// running value; a 1 bit also multiplies by x. The trace has one step per bit.
//   S.ModExp.pow(x, e, n) -> {value, bits, steps: [{i, bit, sq, mul, value}], squarings, multiplications, trace}
(function (S) {
  'use strict';
  const { step } = S.bytes;
  const M = (S.ModExp = {});
  const short = (v) => { const s = v.toString(); return s.length > 24 ? s.slice(0, 10) + '…' + s.slice(-10) + ' (' + s.length + ' digits)' : s; };
  M.short = short;
  M.pow = (x, e, n) => {
    x = BigInt(x); e = BigInt(e); n = BigInt(n);
    const bits = e.toString(2);
    let v = 1n, squarings = 0, multiplications = 0;
    const steps = [], trace = [];
    x %= n;
    for (let i = 0; i < bits.length; i++) {
      const bit = bits[i] === '1';
      // the first bit is always 1: the value starts as x itself, with nothing to square
      let sq = null, mul = null;
      if (i === 0) { v = x; mul = v; }
      else {
        v = (v * v) % n; sq = v; squarings++;
        if (bit) { v = (v * x) % n; mul = v; multiplications++; }
      }
      steps.push({ i, bit: bit ? 1 : 0, sq, mul, value: v });
      trace.push(step('bit', i === 0 ? `The first bit is 1: start with x = ${short(v)}.`
        : bit ? `Bit ${i} is 1: square to ${short(sq)}, then multiply by x to get ${short(v)}.` : `Bit ${i} is 0: square to ${short(v)} and do not multiply.`, { i, bit: bit ? 1 : 0, value: v }));
    }
    return { value: v, bits, steps, squarings, multiplications, trace };
  };
})(globalThis.Sifer = globalThis.Sifer || {});
