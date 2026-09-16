// Part 15's own helpers, on top of part 14's (S.P14): our default AES key, keys from text, a trace plot that knows
// the device's time-sample layout (two set-up samples, then load, add key, S-box for each byte), and the shading of
// the samples where one byte is handled.
(function (S) {
  'use strict';
  const V = (S.P15 = S.P15 || {});
  /** our own key: sixteen bytes of text, never a published test key */
  V.key = (text) => new TextEncoder().encode(String(text || 'harbour-lights-7').padEnd(16, '.').slice(0, 16));
  V.keyCheck = (v) => (!v || [...v].length !== 16 || /[^\x20-\x7e]/.test(v) ? 'Key: exactly 16 plain characters' : null);
  V.OPS = { load: 'load pᵢ', ark: 'pᵢ ⊕ kᵢ', sbox: 'S(pᵢ ⊕ kᵢ)' };
  /**
   * A trace plot over the 52 samples. o: {prefix, x, y, w, h, yr, byte (the one to shade), ylabel, ticks}.
   * Returns the plot (from S.P14.plot) with .shade(byte, op?) and .trace(key, samples, cls, audit).
   */
  V.tracePlot = function (o) {
    const U = S.P14;
    const T = o.T || 52;
    const pl = U.plot({ prefix: o.prefix, x: o.x, y: o.y, w: o.w, h: o.h, xr: [-0.5, T - 0.5], yr: o.yr, xticks: o.xticks || [0, 2, 14, 26, 38, 50], yticks: o.yticks || [], fy: o.fy, ylabel: o.ylabel, xlabel: o.xlabel === undefined ? 'time sample' : o.xlabel, zero: o.zero, tickSize: 13 });
    pl.shade = (byte, op, cls) => {
      const t0 = op ? S.SC.sampleOf(byte, op) : 2 + 3 * byte, t1 = op ? t0 : t0 + 2;
      return { key: o.prefix + ':sh' + byte + (op || ''), kind: 'path', d: `M${pl.X(t0 - 0.5)},${o.y} H${pl.X(t1 + 0.5)} V${o.y + o.h} H${pl.X(t0 - 0.5)} Z`, cls: 'band ' + (cls || 'act'), audit: 'ignore', layer: 'back' };
    };
    pl.trace = (key, samples, cls, audit) => U.line(pl, key, Array.from(samples, (_, t) => t), Array.from(samples), 'trace ' + (cls || ''), audit || 'ignore');
    /** a step plot: each sample held flat across its slot */
    pl.steps = (key, samples, cls) => {
      let d = '';
      const [y0, y1] = o.yr, cl = (v) => Math.max(y0, Math.min(y1, v));
      Array.from(samples).forEach((v, t) => { d += (t ? 'L' : 'M') + pl.X(t - 0.5) + ',' + pl.Y(cl(v)) + ' L' + pl.X(t + 0.5) + ',' + pl.Y(cl(v)) + ' '; });
      return { key, kind: 'path', d, cls: 'dline trace ' + (cls || ''), audit: 'ignore' };
    };
    return pl;
  };
})(globalThis.Sifer = globalThis.Sifer || {});
