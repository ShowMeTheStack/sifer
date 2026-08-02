// Machine sounds, made on the spot with WebAudio (no recordings): the clack of a key going down, and a short metallic
// tick for each rotor the pawls move. Silent unless "Machine sounds" is on (Settings, or the button on the page);
// the audio context is only created on the first sound, after a click, as browsers require.
(function (S) {
  'use strict';
  let ac = null;
  const on = () => !!(S.app && S.app.settings && S.app.settings.sound);
  const ctx = () => {
    if (!ac) { const A = typeof window !== 'undefined' && (window.AudioContext || window.webkitAudioContext); if (!A) return null; try { ac = new A(); } catch (e) { return null; } }
    if (ac.state === 'suspended') ac.resume().catch(() => {});
    return ac;
  };
  /** a burst of filtered noise: the body of a mechanical click */
  function noise(a, t, dur, freq, q, gain) {
    const n = Math.ceil(a.sampleRate * dur), buf = a.createBuffer(1, n, a.sampleRate), d = buf.getChannelData(0);
    for (let i = 0; i < n; i++) d[i] = (Math.random() * 2 - 1) * Math.pow(1 - i / n, 3);
    const src = a.createBufferSource(), f = a.createBiquadFilter(), g = a.createGain();
    src.buffer = buf; f.type = 'bandpass'; f.frequency.value = freq; f.Q.value = q;
    g.gain.setValueAtTime(gain, t); g.gain.exponentialRampToValueAtTime(0.0008, t + dur);
    src.connect(f).connect(g).connect(a.destination);
    src.start(t); src.stop(t + dur + 0.02);
  }
  /** a short decaying tone: the ring of metal */
  function ping(a, t, freq, dur, gain) {
    const o = a.createOscillator(), g = a.createGain();
    o.type = 'triangle'; o.frequency.setValueAtTime(freq, t); o.frequency.exponentialRampToValueAtTime(freq * 0.82, t + dur);
    g.gain.setValueAtTime(gain, t); g.gain.exponentialRampToValueAtTime(0.0008, t + dur);
    o.connect(g).connect(a.destination);
    o.start(t); o.stop(t + dur + 0.02);
  }
  S.EnigmaSound = {
    get enabled() { return on(); },
    /** a key press that moved n rotors */
    press(n) {
      if (!on()) return;
      const a = ctx(); if (!a) return;
      const t = a.currentTime + 0.005;
      noise(a, t, 0.05, 1900, 0.9, 0.5);
      noise(a, t + 0.012, 0.09, 420, 1.4, 0.35);
      for (let k = 0; k < (n || 1); k++) { noise(a, t + 0.03 + k * 0.035, 0.04, 3600, 4, 0.22); ping(a, t + 0.03 + k * 0.035, 2350 - k * 260, 0.07, 0.05); }
    },
    /** a thumbwheel notch or a plug pushed home */
    click() {
      if (!on()) return;
      const a = ctx(); if (!a) return;
      const t = a.currentTime + 0.005;
      noise(a, t, 0.035, 3000, 3, 0.25);
      ping(a, t, 1800, 0.05, 0.04);
    },
  };
})(globalThis.Sifer = globalThis.Sifer || {});
