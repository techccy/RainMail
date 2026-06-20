/* =============================================================================
 * weather-bg.js —— #weather-background 的 Canvas 天气粒子
 *
 * 让 templates 里一直存在的空占位 <div id="weather-background"> 真正生效。
 *   - 雨天：下落雨线（带风偏）
 *   - 晴天：缓慢漂浮的光斑/尘粒
 *
 * 切换：监听 document.body 的 class 变化（sunny-mode / rainy-mode，由 app.js
 *       updateInterface 设置），GSAP 对粒子整体 alpha 交叉淡入淡出。
 * 无障碍：prefers-reduced-motion 时不进入 rAF 循环（与 style.css 守卫一致）。
 * 性能：固定粒子数（移动端减半）、DPR 适配、页面不可见时暂停。
 * ========================================================================== */
(function () {
  'use strict';
  if (typeof window === 'undefined') return;
  if (window.RainMailWeatherBG) return;

  var gsap = window.gsap;
  var host = document.getElementById('weather-background');
  if (!host) return;

  var reduceMQ = '(prefers-reduced-motion: reduce)';
  function prefersReduced() {
    return window.matchMedia && window.matchMedia(reduceMQ).matches;
  }

  // ---------- Canvas 装配
  var canvas = document.createElement('canvas');
  canvas.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;display:block;';
  host.appendChild(canvas);
  var ctx = canvas.getContext('2d');
  var dpr = Math.min(window.devicePixelRatio || 1, 2);

  var W = 0, H = 0;
  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = host.clientWidth || window.innerWidth;
    H = host.clientHeight || window.innerHeight;
    canvas.width = Math.floor(W * dpr);
    canvas.height = Math.floor(H * dpr);
    canvas.style.width = W + 'px';
    canvas.style.height = H + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  resize();
  window.addEventListener('resize', resize);

  // ---------- 粒子系统
  var mode = /rainy-mode/.test(document.body.className) ? 'rainy' : 'sunny';

  // 粒子强度（受可见 alpha 调制，用于切换时淡入淡出）
  var intensity = { v: 1 };

  function particleCount(base) {
    // 移动端（窄屏）减半
    var narrow = window.matchMedia('(max-width: 799px)').matches;
    return Math.max(20, Math.floor(base * (narrow ? 0.5 : 1)));
  }

  // 雨滴
  var RAIN_N = particleCount(180);
  var rain = [];
  function initRain() {
    rain = [];
    for (var i = 0; i < RAIN_N; i++) {
      rain.push({
        x: Math.random() * W,
        y: Math.random() * H,
        len: 10 + Math.random() * 18,
        speed: 6 + Math.random() * 8,
        alpha: 0.08 + Math.random() * 0.18,
      });
    }
  }

  // 晴天光斑
  var SUN_N = particleCount(34);
  var sun = [];
  function initSun() {
    sun = [];
    for (var i = 0; i < SUN_N; i++) {
      sun.push({
        x: Math.random() * W,
        y: Math.random() * H,
        r: 1 + Math.random() * 2.4,
        vx: (Math.random() - 0.5) * 0.18,
        vy: (Math.random() - 0.5) * 0.18,
        alpha: 0.05 + Math.random() * 0.16,
        tw: Math.random() * Math.PI * 2, // 闪烁相位
      });
    }
  }

  initRain();
  initSun();

  // ---------- 绘制
  function drawRain() {
    var g = intensity.v;
    if (g <= 0) return;
    ctx.lineWidth = 1;
    ctx.strokeStyle = 'rgba(200, 220, 240, 1)'; // 雨滴色（淡蓝白），用 strokeStyle + globalAlpha 调明暗
    for (var i = 0; i < rain.length; i++) {
      var p = rain[i];
      ctx.globalAlpha = p.alpha * g;
      ctx.beginPath();
      ctx.moveTo(p.x, p.y);
      ctx.lineTo(p.x - 1.5, p.y + p.len); // 轻微风偏
      ctx.stroke();
      // 更新
      p.y += p.speed;
      p.x -= 0.8;
      if (p.y > H) { p.y = -p.len; p.x = Math.random() * W; }
      if (p.x < -10) p.x = W + 10;
    }
    ctx.globalAlpha = 1;
  }

  function drawSun() {
    var g = intensity.v;
    if (g <= 0) return;
    for (var i = 0; i < sun.length; i++) {
      var p = sun[i];
      p.tw += 0.02;
      var a = (p.alpha + Math.sin(p.tw) * 0.04) * g;
      ctx.globalAlpha = Math.max(0, a);
      ctx.fillStyle = 'rgba(229, 196, 110, 1)'; // kinpaku-ish 金色光斑
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();
      // 漂移
      p.x += p.vx; p.y += p.vy;
      if (p.x < -5) p.x = W + 5; else if (p.x > W + 5) p.x = -5;
      if (p.y < -5) p.y = H + 5; else if (p.y > H + 5) p.y = -5;
    }
    ctx.globalAlpha = 1;
  }

  // ---------- 主循环
  var rafId = null;
  var running = false;
  function frame() {
    ctx.clearRect(0, 0, W, H);
    if (mode === 'rainy') drawRain();
    else drawSun();
    if (running) rafId = window.requestAnimationFrame(frame);
  }

  function start() {
    if (running || prefersReduced()) return;
    running = true;
    rafId = window.requestAnimationFrame(frame);
  }
  function stop() {
    running = false;
    if (rafId) cancelAnimationFrame(rafId);
    rafId = null;
  }

  // 页面可见性：隐藏时暂停 rAF，节省电量
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) stop();
    else start();
  });

  // ---------- 模式切换：监听 body class
  var prevMode = mode;
  function syncFromBody() {
    var next = /rainy-mode/.test(document.body.className) ? 'rainy' : 'sunny';
    if (next === prevMode) return;
    prevMode = next;
    switchMode(next);
  }

  function switchMode(next) {
    if (gsap && !prefersReduced()) {
      // 淡出当前 → 切 mode → 淡入
      gsap.to(intensity, {
        v: 0, duration: 0.4, ease: 'power2.out',
        onComplete: function () {
          mode = next;
          if (next === 'rainy') initRain(); else initSun();
          gsap.to(intensity, { v: 1, duration: 0.6, ease: 'power2.in' });
        },
      });
    } else {
      mode = next;
      if (next === 'rainy') initRain(); else initSun();
      intensity.v = prefersReduced() ? 0.25 : 1;
    }
  }

  // 用 MutationObserver 监听 body.className 变化（app.js updateInterface 直接改 className）
  var bodyObserver = new MutationObserver(function () { syncFromBody(); });
  bodyObserver.observe(document.body, { attributes: true, attributeFilter: ['class'] });

  // resize 时重建粒子分布（密度随尺寸变化）
  var resizeTimer = null;
  window.addEventListener('resize', function () {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      RAIN_N = particleCount(180); SUN_N = particleCount(34);
      initRain(); initSun();
    }, 200);
  });

  // ---------- 启动
  if (!prefersReduced()) {
    start();
  } else {
    // 减少动态效果：画一帧静态、低强度
    intensity.v = 0.25;
    ctx.clearRect(0, 0, W, H);
    if (mode === 'rainy') drawRain(); else drawSun();
  }

  window.RainMailWeatherBG = { start: start, stop: stop, switchMode: switchMode };
})();
