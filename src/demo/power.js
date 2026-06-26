// Square-and-multiply: the exponent's bits read from the left, each one squaring the running value and each 1 also
// multiplying it by x. First on a 16-bit exponent with every value shown, then on the 2048-bit private exponent
// of our own RSA key, whose bits are drawn as a carpet with a lens on the part being read.
(function (S) {
  'use strict';
  const D = S.Demo, M = S.ModExp, KB = S.Kit.bits, box = D.box;
  // an RSA-2048 key of our own, made for this page (n, e and d in hex)
  D.rsa = {"n":"c4e2496973f5051ba6a6166c9718c87f27f7e9e5a05fcb72d2be12e2b093dd339f802c23937c49410cb6ac7aadf9b7d8e951d3d68f560249f5de16514d7ea4c47b206552ad372469fe9eccf22ba9df078003cef3f1ae038370f8124dcc801cd181c1eb6d08e6a8eb2f1e03a0bc108da9d9557594f8cd8974ced1ef7f0f0d48735c9320e61920c0b91e2c032d633ad19342123889b638a9fdda53589888680ab5271cbcb2a1a840c83d38d8d9d5f76ad73926bab4666c499f4b33e7ac116348e9ddd64d9558e65662799d6541c745de4558e21b16600df6fa8102111613f0a6681d44f5bb4ec87dc86c4eab583551bdcee4a7e6f73bf20fb8509dffb8a5045de7","e":"010001","d":"08d4490c8499b957eb1a49a927018284494b91dead597e6b30ce3b54952c9c5fe34841327b3bb8a1452bb0027468dd78c9c5d4a52b9a64d1e247ca626d023feb5bc631250b058d097fd4a94636f5103e6adc40dca9baef0766fa88ff9a2b289fb09cfcacd0185ffce409098a9cc47545e7ac3070b4d3aad5652cfefb88b644c86b6bfecc793ba95254a4191d4628468695d739edcfc969baf7bc7dd0bd365bafe119bfae489337b093e95e20eed89a5301ed2ffa305db73f7fdedac1fdca01100ea19c66d6223f4dcda35720d164a47f492d041e83996c24c961f33868186cba8dc2504f25c6f89a67a8ecf6ebc6645b9e173279f45126a87332d8a5b3d75339"};
  const hexShort = (v) => { const h = v.toString(16); return h.slice(0, 10) + '…' + h.slice(-10); };

  D.add({
    id: 'sqm-16', order: 80, tag: 'RSA · square-and-multiply', short: 'Square-and-multiply', title: 'Square-and-multiply on a 16-bit exponent',
    blurb: 'Read the exponent from its top bit. Each bit squares the running value, which doubles the power reached so far; a 1 bit then multiplies by x, adding one.',
    frames({ narrow }) {
      const x = 29, e = 0b1011010011100101, n = 1000003, r = M.pow(x, e, n), bits = r.bits;
      const frames = [];
      const power = (i) => parseInt(bits.slice(0, i + 1), 2);
      if (narrow) {
        const view = box(-4, -40, 392, 560), bw = 88, bh = 104;
        const block = (i, at) => {
          const s = r.steps[i], X = (i % 4) * (bw + 6), Y = Math.floor(i / 4) * (bh + 12), on = i <= at, cur = i === at;
          return [
            { key: 'sq:b' + i, kind: 'cell', x: X, y: Y, w: bw, h: 40, rx: 5, text: bits[i], size: 20, cls: 'hex ' + (cur ? 'act' : on && s.bit ? 'one bit' : on ? '' : 'soft') },
            { key: 'sq:o' + i, kind: 'text', x: X + bw / 2, y: Y + 58, text: on ? (i === 0 ? 'start' : s.bit ? 'S · M' : 'S') : '', anchor: 'middle', size: 13, cls: s.bit ? 'hot' : 'act' },
            { key: 'sq:v' + i, kind: 'text', x: X + bw / 2, y: Y + 80, text: on ? String(s.value) : '', anchor: 'middle', size: 14, cls: 'mono' },
            { key: 'sq:p' + i, kind: 'text', x: X + bw / 2, y: Y + 98, text: on ? String(power(i)) : '', anchor: 'middle', size: 13, cls: cur ? 'act' : '' },
          ];
        };
        const head = [{ key: 'sq:h', kind: 'text', x: 0, y: -14, text: 'x = 29, n = 1000003, e = 46309', cls: 'strong', size: 14 }];
        for (let at = 0; at < 16; at++) { const items = [...head]; for (let i = 0; i < 16; i++) items.push(...block(i, at)); frames.push({ view, items, say: r.trace[at].say.replace(/(\d{3,})/g, '`$1`') + (at ? ` The power reached is ${power(at)}.` : '') }); }
        frames.push({ view, items: frames[15].items, say: `29^46309 mod 1000003 = \`${r.value}\`, in ${r.squarings} squarings and ${r.multiplications} multiplications, not 46308.` });
        return frames;
      }
      const view = box(0, -10, 1164, 470), x0 = 134, pitch = 64, cw = 58;
      const build = (at) => {
        const items = [];
        items.push({ key: 'sq:h', kind: 'text', x: 20, y: 18, text: `x = ${x},   e = ${bits.replace(/(.{4})(?!$)/g, '$1 ')}₂ = ${e},   n = ${n}`, cls: 'strong', size: 17 });
        const rows = [['bit', 58], ['step', 122], ['value', 172], ['exponent so far', 222]];
        rows.forEach(([t, y], k) => items.push({ key: 'sq:r' + k, kind: 'text', x: x0 - 14, y: y + (k ? 4 : 6), text: t, anchor: 'end', size: 14, cls: 'strong' }));
        items.push(...KB.columns({ prefix: 'sq', x: x0, pitch, cw, bits, steps: r.steps, at, rows: { bit: 34, op: 126, value: 176, power: 226 } }));
        // the operations in the order they happen: what a power trace would show
        items.push({ key: 'sq:ot', kind: 'text', x: 20, y: 300, text: 'the operations, in order', cls: 'title' });
        const ops = KB.ops({ prefix: 'sq', x: 20, y: 314, steps: r.steps, at });
        items.push(...ops.items);
        items.push({ key: 'sq:tally', kind: 'text', x: 20, y: 420, text: `${ops.squarings} squarings, ${ops.multiplications} multiplications so far`, size: 16, cls: 'strong' });
        return items;
      };
      for (let at = 0; at < 16; at++) frames.push({ view, items: build(at), say: r.trace[at].say.replace(/(\d{3,})/g, '`$1`') + (at ? ` The power reached is ${bits.slice(0, at + 1)}₂ = ${power(at)}.` : '') });
      frames.push({ view, items: build(15), say: `29^46309 mod 1000003 = \`${r.value}\`, in ${r.squarings} squarings and ${r.multiplications} multiplications instead of 46308. And notice the row of operations: an S followed by an M means a 1 bit. Anyone who can tell them apart, by timing or power, reads the exponent off it.` });
      return frames;
    },
  });

  D.add({
    id: 'sqm-2048', order: 81, tag: 'RSA · real size', short: 'RSA-2048 exponent', title: 'The same loop on a 2048-bit private exponent',
    blurb: 'The private exponent d of our own RSA-2048 key, drawn as a carpet of bits. The lens shows the bits being read; each 2048-bit squaring and multiplication is done with BigInt.',
    frames({ narrow }) {
      const n = BigInt('0x' + D.rsa.n), d = BigInt('0x' + D.rsa.d), e = BigInt('0x' + D.rsa.e);
      const msg = Array.from(S.bytes.utf8('Sifer signs this line with a 2048-bit key.'));
      const m = BigInt('0x' + S.bytes.hex(msg));
      const r = M.pow(m, d, n), bits = r.bits, N = bits.length;
      const back = M.pow(r.value, e, n).value === m;
      const per = narrow ? 64 : 128, cs = narrow ? 5.5 : 8;
      const L = narrow ? { view: box(-6, -30, 396, 446), cx: 10, cy: 0, zy: 250, zcw: 21, zper: 16, vy: 340 } : { view: box(0, -30, 1160, 420), cx: 68, cy: 0, zy: 220, zcw: 32, zper: 32, vy: 330 };
      const build = (from, upto, lens) => {
        const items = [KB.carpet({ prefix: 'rs', x: L.cx, y: L.cy, bits, per, cs, upto, gap: narrow ? 1 : 1.5 })];
        items.push({ key: 'rs:t', kind: 'text', x: L.cx, y: L.cy - 10, text: `d: ${N} bits, ${per} to a row`, cls: 'strong', size: 14 });
        if (lens) items.push(...KB.lens({ prefix: 'rs', x: L.cx, y: L.cy, cs, per, from, width: L.zper, zoomY: L.zy, zcw: L.zcw, bits, steps: r.steps, at: upto, size: narrow ? 13 : 15, opSize: narrow ? 12 : 13 }));
        const sq = Math.max(0, upto), mu = r.steps.slice(1, upto + 1).filter((s) => s.bit).length, v = upto >= 0 ? r.steps[upto].value : null;
        items.push({ key: 'rs:v', kind: 'text', x: L.cx, y: L.vy, text: v === null ? 'value: m, before the first bit' : `value: ${hexShort(v)}  (${v.toString(2).length} bits)`, cls: 'mono', size: narrow ? 13 : 16 });
        if (narrow) {
          items.push({ key: 'rs:n', kind: 'text', x: L.cx, y: L.vy + 24, text: `bits read: ${upto + 1} of ${N}`, cls: 'strong', size: 13 });
          items.push({ key: 'rs:n2', kind: 'text', x: L.cx, y: L.vy + 46, text: `${sq} squarings · ${mu} multiplications`, cls: 'strong', size: 13 });
        } else items.push({ key: 'rs:n', kind: 'text', x: L.cx, y: L.vy + 30, text: `bits read: ${upto + 1} of ${N} · ${sq} squarings · ${mu} multiplications`, cls: 'strong', size: 15 });
        return items;
      };
      const frames = [];
      const view = L.view;
      const ones = bits.split('').filter((c) => c === '1').length;
      frames.push({ view, items: build(0, -1, false), say: `d has ${N} bits, ${ones} of them 1. The message “Sifer signs this line with a 2048-bit key.” as a number is m; the loop computes m^d mod n, a signature.` });
      const w = L.zper;
      for (const from of [0, Math.floor(N / 2 / w) * w, N - w]) {
        const upto = from + w - 1;
        frames.push({ view, items: build(from, upto, true), say: from === 0 ? `The first ${w} bits: one squaring per bit, and a multiplication for each 1. Every value is a 2048-bit number, reduced modulo n each time.` : from === N - w ? `The last ${w} bits. The result is the signature, \`${hexShort(r.value)}\`.` : `Halfway: ${upto + 1} bits read. The running value already looks like any other 2048-bit number.` });
      }
      frames.push({ view, items: build(N - w, N - 1, false), say: `In all ${r.squarings} squarings and ${r.multiplications} multiplications, about 3000 operations, where multiplying by m over and over would take about 2^${N - 1} multiplications. Raising the signature to e = ${e} gives m back: ${back ? 'checked' : 'NOT checked'}.` });
      return frames;
    },
  });
})(globalThis.Sifer = globalThis.Sifer || {});
