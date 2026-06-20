/* =============================================================================
 * motion.js —— RainMail 全局动画层（基于 GSAP）
 *
 * 设计原则（遵循 gsap/skills/）：
 *   - 只动 transform / opacity / autoAlpha，避免 layout 属性
 *   - gsap.context(scope) 作用域隔离，便于 revert
 *   - gsap.matchMedia() 的 reduceMotion 条件镜像 style.css 的 prefers-reduced-motion
 *   - SplitText 在 document.fonts.ready 后运行
 *   - 所有公开钩子用 window.RainMailMotion?.xxx 调用，GSAP 未加载时降级到原有行为
 *
 * 缓动/时长与 style.css 的设计 token 对齐：
 *   --ks-ease: cubic-bezier(0.2,0.8,0.2,1)  →  注册为 "ks"
 *   --ks-duration-fast/base/slow: 0.15/0.3/0.5s
 * ========================================================================== */
(function () {
  'use strict';

  if (typeof window === 'undefined') return;
  // 防止重复初始化
  if (window.RainMailMotion) return;

  var gsap = window.gsap;
  if (!gsap) {
    // GSAP 未加载：暴露空实现，调用方靠可选链安全降级
    window.RainMailMotion = { available: false };
    return;
  }

  // 注册插件（按存在性）
  var ScrollTrigger = window.ScrollTrigger;
  var SplitText = window.SplitText;
  var ScrollToPlugin = window.ScrollToPlugin;
  if (ScrollTrigger) gsap.registerPlugin(ScrollTrigger);
  if (SplitText) gsap.registerPlugin(SplitText);
  if (ScrollToPlugin) gsap.registerPlugin(ScrollToPlugin);

  // ---------------------------------------------------------------- 常量
  // 与 style.css :root 的 motion token 对齐
  var DUR = { fast: 0.15, base: 0.3, slow: 0.5 };
  // 注册品牌缓动 cubic-bezier(0.2,0.8,0.2,1) 为命名 ease "ks"
  try { gsap.parseEase('ks = cubic-bezier(0.2,0.8,0.2,1)'); }
  catch (e) { /* parseEase 命名注册语法失败时退回 power2.out */ }
  function ksEase() { return 'ks'; }

  var reduceMQ = '(prefers-reduced-motion: reduce)';
  function prefersReduced() {
    return window.matchMedia && window.matchMedia(reduceMQ).matches;
  }

  // ---------------------------------------------------------------- 状态
  var ctx = null;            // gsap.context 实例
  var mm = null;             // gsap.matchMedia 实例
  var pageTL = null;         // 页面入场时间线
  var splitInstances = [];   // SplitText 实例，便于 revert

  // ---------------------------------------------------------------- 工具
  function qsa(sel, scope) {
    return Array.prototype.slice.call((scope || document).querySelectorAll(sel));
  }

  /** 把当前可见接口淡出再隐藏，目标接口淡入 */
  function crossfadeInterfaces(fromEl, toEl, done) {
    if (!fromEl || !toEl) { if (done) done(); return; }
    if (prefersReduced()) {
      gsap.set(fromEl, { autoAlpha: 0 });
      gsap.set(toEl, { autoAlpha: 1 });
      if (done) done();
      return;
    }
    var tl = gsap.timeline({ onComplete: done });
    tl.to(fromEl, { autoAlpha: 0, duration: DUR.base, ease: 'ks' })
      // 确保目标在淡出之后才淡入，避免叠加
      .fromTo(toEl, { autoAlpha: 0 }, { autoAlpha: 1, duration: DUR.slow, ease: 'ks' }, '-=' + (DUR.base * 0.4));
    return tl;
  }

  // ---------------------------------------------------------------- 入场：品牌
  function animateBrand(scope) {
    var mark = (scope || document).querySelector('.ks-mark');
    var wordmark = (scope || document).querySelector('.ks-wordmark');
    if (!mark && !wordmark) return null;
    if (prefersReduced()) {
      gsap.set([mark, wordmark].filter(Boolean), { autoAlpha: 1, y: 0, scale: 1 });
      return null;
    }
    var tl = gsap.timeline();
    if (mark) tl.from(mark, { autoAlpha: 0, scale: 0.6, rotation: -8, duration: DUR.slow, ease: 'ks' });
    if (wordmark) {
      // wordmark 尝试逐字符（字体加载后更稳，见 initFontsReady）
      tl.from(wordmark, { autoAlpha: 0, y: 8, duration: DUR.base, ease: 'ks' }, mark ? '-=' + (DUR.slow * 0.3) : 0);
    }
    return tl;
  }

  /** 字体加载后对 wordmark 做逐字符 stagger 揭示（若启用 SplitText） */
  function animateWordmarkSplit(scope) {
    if (!SplitText || prefersReduced()) return;
    var wordmark = (scope || document).querySelector('.ks-wordmark');
    if (!wordmark || wordmark.dataset.ksSplit) return;
    wordmark.dataset.ksSplit = '1';
    try {
      var split = new SplitText(wordmark, { type: 'chars', aria: 'auto' });
      splitInstances.push(split);
      gsap.from(split.chars, {
        autoAlpha: 0, y: 6, stagger: 0.03, duration: DUR.base, ease: 'ks',
      });
    } catch (e) { /* ignore */ }
  }

  // ---------------------------------------------------------------- 入场：容器
  function animateContainerEntrance(scope) {
    var container = (scope || document).querySelector('.container');
    if (!container) return null;
    if (prefersReduced()) { gsap.set(container, { autoAlpha: 1, y: 0 }); return null; }
    return gsap.from(container, { autoAlpha: 0, y: 16, duration: DUR.slow, ease: 'ks' });
  }

  // ---------------------------------------------------------------- 首页
  function animateHomeForm(scope) {
    var s = scope || document;
    var groups = qsa('#sunny-interface .form-group, #rainy-interface .form-group, .delivery-option', s);
    if (!groups.length) return null;
    if (prefersReduced()) { gsap.set(groups, { autoAlpha: 1, y: 0 }); return null; }
    return gsap.from(groups, { autoAlpha: 0, y: 12, stagger: 0.05, duration: DUR.base, ease: 'ks', delay: 0.1 });
  }

  /** renderMessages 注入后调用：消息卡片 stagger */
  function animateMessages(container) {
    var items = qsa('.message-item', container || document);
    if (!items.length) return null;
    if (prefersReduced()) { gsap.set(items, { autoAlpha: 1, y: 0 }); return null; }
    return gsap.from(items, {
      autoAlpha: 0, y: 14, stagger: 0.06, duration: DUR.base, ease: 'ks', overwrite: 'auto',
    });
  }

  /** inbox 加载后调用：letter-item stagger */
  function animateLetters(container) {
    var items = qsa('.letter-item', container || document);
    if (!items.length) return null;
    if (prefersReduced()) { gsap.set(items, { autoAlpha: 1, y: 0 }); return null; }
    return gsap.from(items, {
      autoAlpha: 0, y: 14, stagger: 0.07, duration: DUR.base, ease: 'ks', overwrite: 'auto',
    });
  }

  // ---------------------------------------------------------------- 天气切换
  // 由 app.js updateInterface 调用：接管 #sunny-interface ↔ #rainy-interface 交叉淡入淡出
  // 返回值：true 表示 motion 已接管显示逻辑（调用方不应再用 .hidden 硬切）；
  //        false 表示未接管，调用方按原逻辑处理。
  function onWeatherChange(weather) {
    var sunny = document.getElementById('sunny-interface');
    var rainy = document.getElementById('rainy-interface');
    if (!sunny || !rainy) return false;
    var showing = weather === 'rainy' ? rainy : sunny;
    var hiding = weather === 'rainy' ? sunny : rainy;
    // 先保证两者可见（移除 .hidden / 强制 display），交给 GSAP autoAlpha 控制透明度
    showing.classList.remove('hidden');
    showing.style.display = '';
    hiding.classList.remove('hidden');
    hiding.style.display = '';
    // 设置初态：读取当前 autoAlpha（0 或 1），保留平滑过渡
    gsap.set(showing, { autoAlpha: gsap.getProperty(showing, 'autoAlpha') || 0 });
    crossfadeInterfaces(hiding, showing);
    // 收尾：淡出后恢复 hiding 的 .hidden 语义（visibility:hidden 已让它不可见，
    // 加 .hidden 仅是出于布局/语义统一）。延迟回调里重新读取当前 body 模式，
    // 避免天气在窗口内二次切换时，过期回调误隐藏当前正在显示的 interface。
    var delay = prefersReduced() ? 0 : DUR.slow + DUR.base;
    gsap.delayedCall(delay, function () {
      var currentMode = /rainy-mode/.test(document.body.className) ? 'rainy' : 'sunny';
      var stillHiding = currentMode === 'rainy' ? sunny : rainy;
      if (stillHiding === hiding) {
        hiding.classList.add('hidden');
        gsap.set(hiding, { autoAlpha: 0, clearProps: 'autoAlpha' });
      }
    });
    return true;
  }

  // ---------------------------------------------------------------- 模态框
  function modalIn(modal) {
    if (!modal) return null;
    modal.classList.remove('hidden');
    modal.style.display = 'flex';
    var content = modal.querySelector('.modal-content, .processing-content');
    if (prefersReduced()) {
      gsap.set(modal, { autoAlpha: 1 });
      if (content) gsap.set(content, { scale: 1, y: 0 });
      return null;
    }
    gsap.set(modal, { autoAlpha: 0 });
    var tl = gsap.timeline();
    tl.to(modal, { autoAlpha: 1, duration: DUR.base, ease: 'ks' });
    if (content) tl.from(content, { scale: 0.94, y: 12, duration: DUR.base, ease: 'ks' }, 0);
    return tl;
  }

  function modalOut(modal) {
    if (!modal) return null;
    if (prefersReduced()) {
      modal.classList.add('hidden');
      modal.style.display = 'none';
      gsap.set(modal, { autoAlpha: 0, clearProps: 'autoAlpha' });
      return null;
    }
    return gsap.to(modal, {
      autoAlpha: 0, duration: DUR.fast, ease: 'ks',
      onComplete: function () {
        modal.classList.add('hidden');
        modal.style.display = 'none';
        gsap.set(modal, { clearProps: 'autoAlpha' });
      },
    });
  }

  // ---------------------------------------------------------------- 公共信件页：正文揭示 + 回复 scroll stagger
  function animatePublicMessage(scope) {
    var s = scope || document;
    var body = s.querySelector('.letter-body');
    var replies = qsa('.reply-item', s);
    if (!ScrollTrigger) return null;
    if (prefersReduced()) {
      if (body) gsap.set(body, { autoAlpha: 1, y: 0 });
      gsap.set(replies, { autoAlpha: 1, y: 0 });
      return null;
    }
    var tl = null;
    // 正文逐行揭示（SplitText lines，字体加载后）
    if (body && SplitText) {
      try {
        var split = new SplitText(body, { type: 'lines', aria: 'auto', linesClass: 'ks-line' });
        splitInstances.push(split);
        // 包裹 overflow hidden 实现擦除感（仅作用于行容器）
        split.lines.forEach(function (line) {
          line.style.overflow = 'hidden';
          gsap.set(line, { display: 'block' });
        });
        tl = gsap.timeline({
          scrollTrigger: { trigger: body, start: 'top 80%', once: true },
        });
        tl.from(split.lines, { yPercent: 100, autoAlpha: 0, stagger: 0.08, duration: DUR.slow, ease: 'ks' });
      } catch (e) { /* ignore */ }
    } else if (body) {
      tl = gsap.timeline({ scrollTrigger: { trigger: body, start: 'top 80%', once: true } });
      tl.from(body, { autoAlpha: 0, y: 16, duration: DUR.slow, ease: 'ks' });
    }
    // 回复列表滚动入场
    if (replies.length) {
      gsap.from(replies, {
        scrollTrigger: { trigger: s.querySelector('.replies-section') || s, start: 'top 85%', once: true },
        autoAlpha: 0, y: 16, stagger: 0.08, duration: DUR.base, ease: 'ks',
      });
    }
    return tl;
  }

  // ---------------------------------------------------------------- 设置/认证页基础
  function animateAuthAndSettings(scope) {
    var s = scope || document;
    var cards = qsa('.settings-card, .auth-form .form-group', s);
    if (!cards.length) return null;
    if (prefersReduced()) { gsap.set(cards, { autoAlpha: 1, y: 0 }); return null; }
    return gsap.from(cards, { autoAlpha: 0, y: 12, stagger: 0.05, duration: DUR.base, ease: 'ks', delay: 0.1 });
  }

  // ---------------------------------------------------------------- 回复表单（letter.html）
  function slideToggle(el, show) {
    if (!el) return null;
    if (prefersReduced()) {
      if (show) { el.classList.remove('hidden'); el.style.display = 'block'; gsap.set(el, { autoAlpha: 1, y: 0 }); }
      else { gsap.set(el, { autoAlpha: 0 }); el.style.display = 'none'; el.classList.add('hidden'); }
      return null;
    }
    if (show) {
      el.classList.remove('hidden');
      el.style.display = 'block';
      return gsap.fromTo(el, { autoAlpha: 0, y: 12 }, { autoAlpha: 1, y: 0, duration: DUR.base, ease: 'ks' });
    }
    return gsap.to(el, {
      autoAlpha: 0, y: 8, duration: DUR.fast, ease: 'ks',
      onComplete: function () { el.style.display = 'none'; el.classList.add('hidden'); gsap.set(el, { clearProps: 'y' }); },
    });
  }

  // ---------------------------------------------------------------- 页面装配
  function setupPage() {
    var body = document.body;
    if (!body) return;

    // 标记 GSAP 已就绪：CSS 据此关闭 .fade-in 的重复动画
    document.documentElement.classList.add('gsap-ready');

    // 容器入场（取代 .fade-in）
    animateContainerEntrance(document);

    // 品牌揭幕
    animateBrand(document);

    // 按页面分派
    var page = detectPage(body);
    switch (page) {
      case 'home': animateHomeForm(document); break;
      case 'inbox':
        // inbox 由内联脚本 fetch 注入；延迟到 loadInbox 完成后由钩子触发，
        // 但首屏 loading 也可淡入一下
        break;
      case 'message': animatePublicMessage(document); break;
      case 'auth':
      case 'settings': animateAuthAndSettings(document); break;
      default: break;
    }

    // 字体加载后：SplitText 标题 + 刷新 ScrollTrigger 度量
    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(function () {
        animateWordmarkSplit(document);
        if (ScrollTrigger) ScrollTrigger.refresh();
      });
    }
  }

  function detectPage(body) {
    // 首页：同时存在 sunny/rainy 两个 interface
    if (document.getElementById('sunny-interface') && document.getElementById('rainy-interface')) return 'home';
    if (body.classList.contains('auth-page')) return 'auth';
    var container = document.querySelector('.container');
    if (container) {
      if (container.classList.contains('letter-view-container')) {
        // 公共信件页含 .replies-section；用户信件页含 #reply-form
        return container.querySelector('.replies-section') ? 'message' : 'letter';
      }
      if (container.querySelector('.inbox-container')) return 'inbox';
      if (container.querySelector('.settings-container')) return 'settings';
    }
    return 'other';
  }

  // ---------------------------------------------------------------- 初始化
  function init() {
    // gsap.context 作用域：便于整体 revert（这里主要为 SplitText 清理）
    ctx = gsap.context(setupPage, document.body);

    // matchMedia：当 reduceMotion 状态变化时，GSAP 3.11+ 会自动 revert/重建
    if (gsap.matchMedia) {
      mm = gsap.matchMedia();
      mm.add({
        reduceMotion: reduceMQ,
      }, function (context) {
        // 仅在 reduceMotion 时把已存在的时间线置为终态
        if (context.conditions && context.conditions.reduceMotion) {
          gsap.globalTimeline.timeScale(0.0001);
        } else {
          gsap.globalTimeline.timeScale(1);
        }
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // ---------------------------------------------------------------- 公开 API
  window.RainMailMotion = {
    available: true,
    DUR: DUR,
    init: init,
    // 钩子（外部用可选链调用）
    animateMessages: animateMessages,
    animateLetters: animateLetters,
    onWeatherChange: onWeatherChange,
    modalIn: modalIn,
    modalOut: modalOut,
    slideToggle: slideToggle,
    prefersReduced: prefersReduced,
  };
})();
