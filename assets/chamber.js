/* The cloud chamber — Positron's hero signature.
   Particle pairs are born at a vertex and curl in opposite directions
   (a magnetic field bends opposite charges opposite ways), leaving
   fading trails: blue for the log stream, rose for the trace stream. */
(() => {
  'use strict';

  const canvas = document.querySelector('[data-chamber]');
  if (!canvas) return;
  const ctx = canvas.getContext('2d', { alpha: false });
  if (!ctx) return;

  const DEEP = '#131320';           /* --deep */
  const BLUE = { h: '#87a6f8', glow: 'rgba(135, 166, 248, 0.55)' };
  const ROSE = { h: '#ef93c3', glow: 'rgba(239, 147, 195, 0.5)' };
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  let w = 0, h = 0, dpr = 1;

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    const rect = canvas.getBoundingClientRect();
    w = Math.max(1, Math.round(rect.width));
    h = Math.max(1, Math.round(rect.height));
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = DEEP;
    ctx.fillRect(0, 0, w, h);
    drawRings();
  }

  /* Faint concentric chamber rings behind everything. */
  function drawRings() {
    const cx = w * 0.72, cy = h * 0.4;
    ctx.save();
    ctx.strokeStyle = 'rgba(120, 130, 190, 0.07)';
    ctx.lineWidth = 1;
    for (let r = 90; r < Math.max(w, h); r += 130) {
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.stroke();
    }
    ctx.restore();
  }

  /* A particle curls: velocity rotates at a constant rate; the trail decays. */
  function spawnPair(particles, x, y) {
    const speed = 0.5 + Math.random() * 0.7;
    const angle = Math.random() * Math.PI * 2;
    const curl = (0.008 + Math.random() * 0.014);
    const life = 260 + Math.random() * 240;
    for (const sign of [1, -1]) {
      particles.push({
        x, y,
        vx: Math.cos(angle) * speed * (sign === 1 ? 1 : 0.82),
        vy: Math.sin(angle) * speed * (sign === 1 ? 1 : 0.82),
        curl: curl * sign,
        color: sign === 1 ? BLUE : ROSE,
        age: 0,
        life,
      });
    }
  }

  function step(particles) {
    /* Fade the whole field slightly toward DEEP — this is what turns
       moving points into decaying trails. */
    ctx.fillStyle = 'rgba(19, 19, 32, 0.045)';
    ctx.fillRect(0, 0, w, h);

    for (let i = particles.length - 1; i >= 0; i--) {
      const p = particles[i];
      const cos = Math.cos(p.curl), sin = Math.sin(p.curl);
      const vx = p.vx * cos - p.vy * sin;
      const vy = p.vx * sin + p.vy * cos;
      p.vx = vx; p.vy = vy;
      const nx = p.x + vx, ny = p.y + vy;

      const t = p.age / p.life;
      const alpha = t < 0.08 ? t / 0.08 : 1 - (t - 0.08) / 0.92;
      ctx.strokeStyle = p.color.h;
      ctx.globalAlpha = Math.max(0, alpha * 0.85);
      ctx.lineWidth = 1.4;
      ctx.lineCap = 'round';
      ctx.beginPath();
      ctx.moveTo(p.x, p.y);
      ctx.lineTo(nx, ny);
      ctx.stroke();
      ctx.globalAlpha = 1;

      p.x = nx; p.y = ny; p.age++;
      if (p.age >= p.life || nx < -40 || nx > w + 40 || ny < -40 || ny > h + 40) {
        particles.splice(i, 1);
      }
    }
  }

  /* Reduced motion or no rAF: render one composed static frame. */
  function staticFrame() {
    resize();
    const particles = [];
    for (let i = 0; i < 7; i++) {
      spawnPair(particles, w * (0.15 + Math.random() * 0.75), h * (0.12 + Math.random() * 0.7));
    }
    for (let f = 0; f < 420 && particles.length; f++) step(particles);
  }

  if (reduced) {
    staticFrame();
    window.addEventListener('resize', staticFrame);
    return;
  }

  const particles = [];
  let running = true;
  let frame = 0;

  function loop() {
    if (!running) return;
    frame++;
    /* Sparse, physical pacing: a new pair roughly every ~1.4s, capped. */
    if (frame % 85 === 0 && particles.length < 26) {
      spawnPair(particles, w * (0.12 + Math.random() * 0.8), h * (0.1 + Math.random() * 0.75));
    }
    if (frame % 200 === 0) drawRings();
    step(particles);
    requestAnimationFrame(loop);
  }

  document.addEventListener('visibilitychange', () => {
    running = document.visibilityState === 'visible';
    if (running) requestAnimationFrame(loop);
  });

  resize();
  window.addEventListener('resize', resize);
  /* Seed the field so the hero is alive on first paint. */
  for (let i = 0; i < 4; i++) {
    spawnPair(particles, w * (0.2 + Math.random() * 0.65), h * (0.15 + Math.random() * 0.6));
  }
  for (let f = 0; f < 160; f++) step(particles);
  requestAnimationFrame(loop);
})();
