// =============================================================================
// WeatherBackground —— 全屏天气粒子背景
// 移植自 static/js/weather-bg.js，改为 React <canvas>，props 驱动 mode。
//   rainy: 180 条下落雨线（rgba(200,220,240)），风偏移
//   sunny: 34 颗金色尘埃（rgba(229,196,110) / yellow-400），闪烁漂浮
// 无障碍/性能：
//   - prefers-reduced-motion → 只画一帧静态（intensity 0.25）
//   - 页面隐藏暂停 rAF
//   - resize 节流 200ms 重算粒子数
//   - DPR clamp 到 2
//   - GSAP 渐变改为 intensity 插值（不引入 GSAP）
// =============================================================================
import { useEffect, useRef } from 'react';
import type { WeatherStatus } from '@/types/api';

interface Props {
  mode: WeatherStatus;
}

interface RainDrop {
  x: number;
  y: number;
  len: number;
  speed: number;
  alpha: number;
}

interface SunMote {
  x: number;
  y: number;
  r: number;
  vx: number;
  vy: number;
  alpha: number;
  tw: number;
}

const MAX_DPR = 2;

function particleBase(width: number): number {
  return width > 0 && width <= 799 ? 0.5 : 1;
}

export default function WeatherBackground({ mode }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const modeRef = useRef<WeatherStatus>(mode);
  const intensityRef = useRef<number>(1);
  const intensityTargetRef = useRef<number>(1);

  useEffect(() => {
    modeRef.current = mode;
    intensityTargetRef.current = 0; // 切换时淡出
  }, [mode]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let W = 0;
    let H = 0;
    let dpr = 1;
    let rainN = 180;
    let sunN = 34;
    const rain: RainDrop[] = [];
    const sun: SunMote[] = [];

    function resize() {
      const host = canvas!;
      const rect = host.getBoundingClientRect();
      W = rect.width;
      H = rect.height;
      dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR);
      host.width = Math.floor(W * dpr);
      host.height = Math.floor(H * dpr);
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
      const factor = particleBase(W);
      rainN = Math.max(20, Math.floor(180 * factor));
      sunN = Math.max(20, Math.floor(34 * factor));
      initParticles();
    }

    function initRain() {
      rain.length = 0;
      for (let i = 0; i < rainN; i++) {
        rain.push({
          x: Math.random() * W,
          y: Math.random() * H,
          len: 10 + Math.random() * 18,
          speed: 6 + Math.random() * 8,
          alpha: 0.08 + Math.random() * 0.18,
        });
      }
    }

    function initSun() {
      sun.length = 0;
      for (let i = 0; i < sunN; i++) {
        sun.push({
          x: Math.random() * W,
          y: Math.random() * H,
          r: 1 + Math.random() * 2.4,
          vx: (Math.random() - 0.5) * 0.18,
          vy: (Math.random() - 0.5) * 0.18,
          alpha: 0.05 + Math.random() * 0.16,
          tw: Math.random() * Math.PI * 2,
        });
      }
    }

    function initParticles() {
      initRain();
      initSun();
    }

    function drawRain() {
      const v = intensityRef.current;
      ctx!.lineWidth = 1;
      ctx!.strokeStyle = 'rgba(200,220,240,1)';
      for (const p of rain) {
        ctx!.globalAlpha = p.alpha * v;
        ctx!.beginPath();
        ctx!.moveTo(p.x, p.y);
        ctx!.lineTo(p.x - 1.5, p.y + p.len);
        ctx!.stroke();
        p.y += p.speed;
        p.x -= 0.8;
        if (p.y > H) {
          p.y = -p.len;
          p.x = Math.random() * W;
        }
        if (p.x < 0) p.x = W;
      }
      ctx!.globalAlpha = 1;
    }

    function drawSun() {
      const v = intensityRef.current;
      ctx!.fillStyle = 'rgba(229,196,110,1)';
      for (const m of sun) {
        ctx!.globalAlpha = m.alpha * v * (0.6 + 0.4 * Math.sin(m.tw));
        ctx!.beginPath();
        ctx!.arc(m.x, m.y, m.r, 0, Math.PI * 2);
        ctx!.fill();
        m.x += m.vx;
        m.y += m.vy;
        m.tw += 0.02;
        if (m.x < 0 || m.x > W) m.vx *= -1;
        if (m.y < 0 || m.y > H) m.vy *= -1;
      }
      ctx!.globalAlpha = 1;
    }

    function drawStatic() {
      ctx!.clearRect(0, 0, W, H);
      intensityRef.current = 0.25;
      if (modeRef.current === 'rainy') drawRain();
      else drawSun();
    }

    let rafId = 0;
    let running = true;

    function frame() {
      // intensity 朝 target 缓动（无 GSAP）
      const cur = intensityRef.current;
      const tgt = intensityTargetRef.current;
      if (Math.abs(cur - tgt) > 0.01) {
        intensityRef.current = cur + (tgt - cur) * 0.12;
      } else {
        intensityRef.current = tgt;
        // 淡出完成后切到新模式的实色
        if (tgt === 0) {
          intensityTargetRef.current = 1;
        }
      }

      ctx!.clearRect(0, 0, W, H);
      if (modeRef.current === 'rainy') drawRain();
      else drawSun();

      if (running) rafId = window.requestAnimationFrame(frame);
    }

    resize();
    let resizeTimer: number | undefined;
    const onResize = () => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(resize, 200);
    };
    window.addEventListener('resize', onResize);

    const onVisibility = () => {
      if (document.hidden) {
        running = false;
        if (rafId) window.cancelAnimationFrame(rafId);
      } else if (!prefersReduced) {
        running = true;
        rafId = window.requestAnimationFrame(frame);
      }
    };
    document.addEventListener('visibilitychange', onVisibility);

    if (prefersReduced) {
      drawStatic();
    } else {
      rafId = window.requestAnimationFrame(frame);
    }

    return () => {
      running = false;
      if (rafId) window.cancelAnimationFrame(rafId);
      window.removeEventListener('resize', onResize);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      className="pointer-events-none fixed inset-0 -z-10 h-full w-full"
    />
  );
}
