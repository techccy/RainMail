import { useEffect, useId, useState } from 'react';

/**
 * RainMail 动态 Logo（pixel2motion 方法论 · 信任/专业气质）
 *
 * 结构（与 frontend/public/brand/logo.svg 同源）：
 *   - #cloud        蓝渐变云朵（内含信封负形 evenodd 镂空）
 *   - #raindrops    4 滴从云中落下的雨滴
 *   - #wordmark     "RainMail" 深岩灰文字
 *
 * 编排（黄金比 20:50:30，总时长 1400ms）：
 *   1. 云朵轻微 scale 0.94→1 + 淡入（staging，ease-out）
 *   2. 4 滴雨滴错峰淡入 + 轻微下落（overlap）
 *   3. 文字 mask-wipe 左→右 + 2px 漂移归位（follow-through）
 *
 * 规则遵循：
 *   - keyframe 内缓动写字面 cubic-bezier（不写 var()，避免 Chromium 静默降级为 linear）
 *   - 只动 transform / opacity / clip-path（性能）
 *   - prefers-reduced-motion → 立即静态终态（Final Frame Contract）
 *   - 揭示只播一次（animation 1 次），不随路由重放
 *
 * 仅播放一次（不 loop）。如需 hover 重放，可在外层加 key 触发 remount。
 */
export type RainMailLogoProps = {
  /** 渲染宽度（px）。默认 320。 */
  width?: number;
  /** 额外 className（作用于外层容器）。 */
  className?: string;
};

export default function RainMailLogo({ width = 320, className }: RainMailLogoProps) {
  // 唯一化渐变 id，避免同页多实例冲突
  const uid = useId().replace(/[:]/g, '');
  const gradId = `rm-grad-${uid}`;
  const clipId = `rm-wipe-${uid}`;

  // 等页面完全加载后再播放（window.load）。
  // 组件可能晚于 load 才挂载（如路由切换），此时 readyState 已是 complete，立即播放。
  const [loaded, setLoaded] = useState(
    () => typeof document !== 'undefined' && document.readyState === 'complete',
  );
  useEffect(() => {
    if (loaded) return;
    const onLoad = () => setLoaded(true);
    window.addEventListener('load', onLoad, { once: true });
    return () => window.removeEventListener('load', onLoad);
  }, [loaded]);

  return (
    <div
      className={['rm-logo', loaded && 'rm-play', className].filter(Boolean).join(' ')}
      style={{ width }}
    >
      {/* biome-ignore lint/a11y/useUniqueIds: gradient/clip ids are namespaced by useId */}
      <style>{cssFor(gradId, clipId)}</style>
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 1000 936.9"
        role="img"
        aria-labelledby={`${uid}-title`}
        style={{ width: '100%', height: 'auto', display: 'block' }}
      >
        <title id={`${uid}-title`}>RainMail 雨天信箱</title>
        <defs>
          <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#3492EC" />
            <stop offset="0.5" stopColor="#2478DF" />
            <stop offset="1" stopColor="#1B6BDA" />
          </linearGradient>
          {/* 文字 mask-wipe：从左向右擦除揭示 */}
          <clipPath id={clipId}>
            <rect className="rm-wipe-rect" x="0" y="780" width="1000" height="160" />
          </clipPath>
        </defs>

        {/* 云朵（含信封负形镂空） */}
        <g id={`cloud-${uid}`} className="rm-cloud" style={{ transformBox: 'fill-box', transformOrigin: '50% 60%' }}>
          <path
            fill={`url(#${gradId})`}
            fillRule="evenodd"
            d={CLOUD_D}
          />
        </g>

        {/* 4 滴雨滴，错峰落下 */}
        <g className="rm-raindrops">
          {DROP_D.map((d, i) => (
            <path
              key={i}
              id={`drop-${uid}-${i + 1}`}
              className={`rm-drop rm-drop-${i + 1}`}
              fill={`url(#${gradId})`}
              d={d}
            />
          ))}
        </g>

        {/* 文字 RainMail（mask-wipe 揭示） */}
        <g clipPath={`url(#${clipId})`}>
          <text
            id={`wordmark-${uid}`}
            className="rm-wordmark"
            x="499.3"
            y="915.8"
            textAnchor="middle"
            dominantBaseline="alphabetic"
            fontFamily="'DM Sans', system-ui, sans-serif"
            fontSize="170"
            fontWeight="700"
            letterSpacing="-3"
            fill="#1D2939"
          >
            RainMail
          </text>
        </g>
      </svg>
    </div>
  );
}

/**
 * 动画 CSS。token 仅用于 animation 简写与文档；keyframe 内全部写字面 cubic-bezier。
 * 气质：Trustworthy（ease-out 族，无过冲，无 squash）。
 *
 * 速度：已下调至原速 60%（duration / delay 同比 ×1.667），总时长由 1400ms → 2333ms。
 * 触发：默认 paused，待外层 .rm-logo.rm-play 出现才播放（等页面 load 完成）。
 */
function cssFor(gradId: string, clipId: string): string {
  // gradId/clipId 不直接用于 keyframe，但保留以便未来 per-instance 调参。
  void gradId;
  void clipId;
  return `
.rm-logo { display: inline-block; line-height: 0; }

/* ===== 揭示（播放一次，forwards 固定终态）===== */
/* 速度 ×1.667（=1/0.6）；原 20:50:30 = 280 / 700 / 420 → 现 467 / 1167 / 700；总 2333ms */

/* 1) 云朵：scale 0.94→1 + 淡入。ease-out = cubic-bezier(0,0,0.2,1)（信任族，一致） */
.rm-cloud {
  opacity: 0;
  transform: scale(0.94);
  animation: rm-cloud-in 1667ms cubic-bezier(0, 0, 0.2, 1) 133ms forwards paused;
  will-change: transform, opacity;
}
@keyframes rm-cloud-in {
  0%   { opacity: 0; transform: scale(0.94); }
  /* staging：先轻微沉降一拍（克制版 anticipation，无大幅形变） */
  18%  { opacity: 0.5; transform: scale(0.92); }        /* token: ease-enter 段 */
  60%  { opacity: 1; transform: scale(1.0); }           /* 到位 */
  100% { opacity: 1; transform: scale(1.0); }
}

/* 2) 雨滴：错峰淡入 + 轻微下落。ease-out = cubic-bezier(0,0,0.2,1) */
.rm-drop {
  opacity: 0;
  transform: translateY(-10px);
  transform-box: fill-box;
  transform-origin: center;
  animation: rm-drop-in 1067ms cubic-bezier(0, 0, 0.2, 1) forwards paused;
  will-change: transform, opacity;
}
/* 自然书写顺序错峰：inner-left / inner-right / bottom-left / bottom-right */
.rm-drop-1 { animation-delay: 867ms; }
.rm-drop-2 { animation-delay: 1000ms; }
.rm-drop-3 { animation-delay: 1133ms; }
.rm-drop-4 { animation-delay: 1267ms; }
@keyframes rm-drop-in {
  0%   { opacity: 0; transform: translateY(-10px); }
  55%  { opacity: 1; }                                   /* token: ease-enter */
  100% { opacity: 1; transform: translateY(0); }
}

/* 3) 文字：mask-wipe 左→右（clip rect 宽度 0→100%）+ 2px 漂移归位 */
.rm-wipe-rect {
  /* 起始：完全裁掉（宽度 0）。注意 SVG <rect> 的 width 用 CSS 动画在 Chromium 可用 */
  transform: scaleX(0);
  transform-origin: left center;
  transform-box: fill-box;
  animation: rm-wipe 1200ms cubic-bezier(0, 0, 0.2, 1) 1067ms forwards paused;
  will-change: transform;
}
@keyframes rm-wipe {
  0%   { transform: scaleX(0); }
  100% { transform: scaleX(1); }
}
.rm-wordmark {
  opacity: 0;
  transform: translateX(2px);
  transform-box: fill-box;
  transform-origin: center;
  animation: rm-wordmark-drift 1200ms cubic-bezier(0, 0, 0.2, 1) 1067ms forwards paused;
  will-change: transform, opacity;
}
@keyframes rm-wordmark-drift {
  0%   { opacity: 0; transform: translateX(2px); }
  30%  { opacity: 1; }                                    /* token: ease-enter */
  100% { opacity: 1; transform: translateX(0); }
}

/* ===== 页面完全加载后才开始播放 ===== */
.rm-play .rm-cloud,
.rm-play .rm-drop,
.rm-play .rm-wipe-rect,
.rm-play .rm-wordmark {
  animation-play-state: running;
}

/* ===== Reduced motion：立即静态终态（Final Frame Contract）===== */
@media (prefers-reduced-motion: reduce) {
  .rm-cloud,
  .rm-drop,
  .rm-wordmark {
    opacity: 1 !important;
    transform: none !important;
    animation: none !important;
    will-change: auto !important;
  }
  .rm-wipe-rect {
    transform: scaleX(1) !important;
    animation: none !important;
    will-change: auto !important;
  }
}
`;
}

/* ---- 几何数据（与 frontend/public/brand/logo.svg 同源，实测像素拟合，图标 IoU≈0.915）---- */
// 云朵外轮廓 + 信封负形（evenodd 镂空）
const CLOUD_D =
  'M 715.3 507.0 C 714.2 506.6 710.2 533.6 709.0 504.9 C 707.8 476.1 736.9 340.0 708.3 334.5 C 679.7 329.0 570.6 447.1 537.2 471.9 C 503.8 496.7 516.6 481.8 507.7 483.2 C 498.8 484.6 490.9 482.5 483.9 480.4 C 476.9 478.3 496.9 494.8 465.6 470.5 C 434.3 446.2 324.3 328.8 295.9 334.5 C 267.5 340.2 300.6 476.4 295.2 504.9 C 289.8 533.4 275.0 507.1 263.7 505.6 C 252.4 504.1 240.5 501.9 227.2 495.8 C 213.9 489.7 198.3 483.2 183.7 469.1 C 169.1 455.0 149.3 429.2 139.6 410.9 C 129.9 392.5 127.8 372.6 125.5 359.0 C 123.2 345.4 123.9 341.5 125.5 329.6 C 127.1 317.7 130.2 301.1 135.3 287.5 C 140.5 273.9 145.8 261.6 156.4 248.2 C 167.1 234.8 184.4 217.3 199.2 206.9 C 214.0 196.5 230.8 190.1 245.4 185.8 C 260.0 181.5 278.0 189.2 286.8 180.9 C 295.6 172.6 292.9 149.8 298.0 136.0 C 303.1 122.2 309.8 110.4 317.7 98.2 C 325.6 86.0 334.8 74.0 345.7 63.1 C 356.6 52.2 369.0 41.8 382.9 33.0 C 396.8 24.2 412.6 16.1 429.2 10.5 C 445.8 4.9 465.9 0.9 482.5 -0.7 C 499.1 -2.3 513.1 -1.6 528.8 0.7 C 544.4 3.0 560.0 6.5 576.4 13.3 C 592.8 20.1 611.8 30.3 626.9 41.4 C 642.0 52.5 655.5 66.0 666.9 79.9 C 678.2 93.8 687.4 107.8 695.0 124.8 C 702.6 141.8 699.5 169.8 712.5 181.6 C 725.5 193.4 753.5 186.5 772.8 195.7 C 792.1 204.9 814.8 223.8 828.2 237.0 C 841.6 250.2 847.3 263.4 853.4 274.9 C 859.5 286.4 862.4 290.1 864.7 305.8 C 867.1 321.5 871.0 347.9 867.5 368.9 C 864.0 389.9 852.6 415.8 843.6 432.0 C 834.6 448.2 823.0 457.3 813.5 466.3 C 804.0 475.3 797.3 480.1 786.8 486.0 C 776.3 491.9 762.3 497.9 750.4 501.4 C 738.5 504.9 721.1 506.1 715.3 507.0 C 709.4 507.9 716.3 507.4 715.3 507.0 Z M 510.5 452.3 C 505.6 451.1 502.4 459.6 481.1 445.3 C 459.8 431.1 411.8 390.1 382.9 366.8 C 354.0 343.6 320.6 319.0 307.9 305.8 C 295.2 292.6 305.0 291.6 306.5 287.5 C 308.0 283.4 253.5 282.2 317.0 281.2 C 380.4 280.1 623.5 279.9 687.2 281.2 C 750.9 282.5 697.2 285.5 699.2 288.9 C 701.2 292.3 700.7 297.6 699.2 301.5 C 697.7 305.4 721.5 287.0 690.0 312.1 C 658.5 337.2 540.4 428.9 510.5 452.3 C 480.6 475.7 515.4 453.5 510.5 452.3 Z';

// 4 滴雨滴（顺序：inner-left, inner-right, bottom-left, bottom-right）
const DROP_D = [
  'M 314.2 633.2 C 312.8 633.2 308.7 634.2 305.8 633.2 C 302.9 632.2 298.6 630.5 296.6 626.9 C 294.6 623.3 285.6 632.1 293.8 611.5 C 302.0 590.9 335.8 522.5 345.7 503.5 C 355.6 484.4 349.8 498.2 353.4 497.2 C 357.0 496.1 363.6 495.4 367.5 497.2 C 371.4 498.9 375.1 504.3 376.6 507.7 C 378.1 511.1 385.2 497.9 376.6 517.5 C 368.0 537.1 335.1 606.2 324.7 625.5 C 314.3 644.8 315.9 631.9 314.2 633.2 C 312.4 634.5 315.6 633.2 314.2 633.2 Z',
  'M 527.3 633.2 C 525.4 633.0 519.2 633.3 516.1 631.8 C 513.0 630.3 509.7 628.0 508.4 624.1 C 507.1 620.2 499.8 629.0 508.4 608.7 C 517.0 588.4 549.9 520.9 560.3 502.1 C 570.7 483.3 567.4 496.6 570.8 495.8 C 574.2 495.0 577.4 495.4 580.6 497.2 C 583.8 498.9 588.0 503.1 589.8 506.3 C 591.6 509.5 599.9 496.2 591.2 516.1 C 582.6 536.0 548.5 606.0 537.9 625.5 C 527.2 645.0 529.1 631.9 527.3 633.2 C 525.5 634.5 529.2 633.4 527.3 633.2 Z',
  'M 401.1 676.7 C 398.3 676.0 387.9 675.6 384.3 672.5 C 380.7 669.4 376.2 668.4 379.4 657.8 C 382.5 647.2 396.5 618.2 403.2 608.7 C 409.9 599.2 414.5 600.8 419.4 601.0 C 424.3 601.2 430.2 606.7 432.7 610.1 C 435.1 613.5 437.9 611.2 434.1 621.3 C 430.4 631.3 415.7 661.2 410.2 670.4 C 404.7 679.6 402.6 675.7 401.1 676.7 C 399.6 677.8 403.9 677.4 401.1 676.7 Z',
  'M 621.3 655.7 C 619.1 654.9 610.9 654.4 608.0 650.8 C 605.1 647.2 600.8 644.4 603.8 633.9 C 606.8 623.4 621.0 596.7 626.2 587.7 C 631.5 578.7 631.7 581.2 635.3 579.9 C 638.9 578.6 644.4 578.6 648.0 579.9 C 651.6 581.2 655.6 584.1 657.1 587.7 C 658.6 591.3 661.1 591.4 657.1 601.7 C 653.1 612.0 639.2 640.4 633.2 649.4 C 627.2 658.4 623.3 654.7 621.3 655.7 C 619.3 656.8 623.5 656.5 621.3 655.7 Z',
];
