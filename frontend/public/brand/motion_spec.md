# RainMail 动态 Logo — Motion Spec

源图：`resources/rainmail.png`（1254×1254）+ `resources/rainmail-Small.jpeg`（320×320 压缩版）。
方法：`pixel2motion/`（像素→矢量→动作）。交付形式：React 组件 + 内联 SVG + CSS 动画（无第三方依赖）。

## Phase 1 — 像素读取结论（以 Python 读 PNG 真实像素为准）

### 布局（关键修正：纵向堆叠，非横向 lockup；图标含 4 滴雨滴）
- 整体 logo 前景 bbox（1254 画布内）：x[272,984] y[270,937]，即 712×667。
- **纵向三段**：图标（顶部 y[270,752]，72%）→ 空白间隙（72–82%）→ 文字（y[813,937]，82–100%）。
- 图标 = **云朵 + 信封负形 + 4 滴雨滴**（4 滴为与云朵断开的独立连通分量）：
  - 云朵主体：101671 px，x[362,891] y[270,631]。
  - 信封负形镂空：20234 px，bbox x-norm 0.306–0.701 y-norm 0.301–0.483，顶宽下窄（V 翻盖）。
  - 雨滴×4：内侧左/右（各 ~2380 px，高 97px）+ 外侧左/右（各 ~1240 px，高 53px），从云朵下方落下。

### 配色（实际像素，非视觉猜测）
- **图标 = 蓝色纵向渐变云朵**：
  - y≈0（顶部边缘抗锯齿）`#BADFFA`（伪值，忽略）
  - y≈0.17 `#3492EC`（浅蓝起点）
  - y≈0.50 `#2478DF`（中段）
  - y≈0.67 `#1B6BDA`（最深）
  - y≈1（底部边缘抗锯齿）`#C8EAFD`（伪值，忽略）
  - → 渐变 stops：`#3492EC`（顶）→ `#2478DF`（中）→ `#1B6BDA`（底）。
- **云朵内部 = 信封负形镂空**（露出背景白）：bbox x-norm 0.306–0.701，y-norm 0.301–0.483；形状为顶宽下窄（信封翻盖 V 形）。
- **图标底部中心**有一个收窄的水滴尖（x-norm 0.45–0.55，从 25px 收到 7px）——云朵下沿的滴水。
- **文字 "RainMail"**：纯深色 `#1D2939`（深岩灰，略偏蓝；均值 `#244F8E`）。R、M 大写，其余小写。8 字符 ✓。

> 说明：用户回答倾向「深青蓝单色」，但实际像素中文字是深岩灰 `#1D2939`、云是蓝渐变。以真实像素为准（还原度优先），二者同属冷调蓝灰，整体观感一致。若后续需统一，可一键改文字为 `#1B6BDA`。

## Phase 2 — 矢量结构（motion-ready）

复杂度梯队选用「原始件组合 + 少量平滑曲线」：
- 云朵轮廓 = 平滑 cubic path（3 个顶部凸起 + 圆弧下沿 + 底部滴水尖），低结点，G1 连续。
- 信封负形 = 单 path（梯形信封体 + 顶部 V 形翻盖），用 `fill-rule:evenodd` 与云朵合并，得到同色镂空。
- 文字 = SVG `<text>`（DM Sans，与站点字体一致），`font-weight: 700`。
- 纵向线性渐变 `#3492EC→#2478DF→#1B6BDA` 填充云朵（含信封负形自动镂空）。

### 部件清单与稳定 id
| id | 部件 | 动作 |
|---|---|---|
| `#cloud` | 云朵（含信封负形，渐变填充） | scale 0.92→1 + 淡入 |
| `#envelope-cutout` | 信封负形（cloud 的镂空子路径） | 跟随 cloud；额外淡入 |
| `#wordmark` | "RainMail" 文字 | mask-wipe 左→右 + 2px drift |
| `#raindrop` | 云底滴水尖（cloud 底部） | 跟随 cloud |

> 镂空用 evenodd：cloud path 含外轮廓 + 信封子路径，单一 fill 即可镂空。`#envelope-cutout` 是逻辑语义 id（标记子路径），不单独动（其可见性随 cloud）。

### 几何 QA 计划
- 终态截图与 `resources/rainmail.png` 叠加比对（青色 overlay），记录 IoU 与残差。
- 检查：云朵三凸起位置、底部滴水尖、信封 V 形镂空、文字基线与字间距。

### 几何 QA 结果（实测，见 outputs/）
- **图标 IoU = 0.915**（云朵 + 信封负形 + 4 雨滴）。残差主要为信封负形边缘抗锯齿与雨滴轮廓微差，视觉忠实。
- **文字 IoU = 0.191**：纯字体栅格化差异（headless Chrome 未加载 DM Sans，用 fallback）。采用 live `<text>`（平滑度规则推荐），站点加载 DM Sans 后即接近原字。结构正确（8 字符 RainMail）。
- **路径审计**：53 段三次曲线，0 切线结点告警，1 处 5.19px 短段（雨滴细节，可接受）→ 平滑门通过。

## Phase 3 — 动作编排（信任/专业 Trustworthy）

气质参数（`references/motion-personality.md` Trustworthy 预设）：
```
--p2m-duration: 1400ms
--p2m-ease-enter:  cubic-bezier(0, 0, 0.2, 1)   /* confident ease-out */
--p2m-ease-settle: cubic-bezier(0.4, 0, 0.2, 1)
无过冲、无 squash、无随机；缓动族全程一致 = 「可预测 = 稳定感」。
```

时间线（黄金比 20:50:30）：
1. **0–280ms（anticipation/staging）**：整体 opacity 0→，云朵轻微预收缩。
2. **280–980ms（action）**：cloud `scale 0.92→1` + opacity→1（ease-out）；信封负形随之显现。
3. **560–1260ms（overlap）**：wordmark `clip-path` mask-wipe 左→右 + `translateX 2px→0` drift，错峰 40% 开始于 cloud 接近就位时。
4. **980–1400ms（settle）**：全部归位，终态 = 静态 logo（Final Frame Contract）。

### 关键规则遵循
- **keyframe 内缓动写字面 cubic-bezier**（不写 `var()`，避免 Chromium 静默降级为 linear）。
- 只动 `transform / opacity / clip-path`（性能）。
- `prefers-reduced-motion: reduce` → 立即静态终态。
- 揭示只播放一次（每页加载/会话），不在每次路由切换重放。

### 12 原则取舍
- ✅ Staging（云先、字后，阅读顺序引导）
- ✅ Slow In/Slow Out（ease-out 族，无 linear）
- ✅ Timing（1400ms 沉稳）
- ✅ Solid Drawing（不变形，仅 scale/clip/opacity）
- ✅ Appeal（克制、几何、可预测）
- ✅ Follow Through / Overlap（wordmark 错峰漂移）
- ✖️ Squash & Stretch、Exaggeration、Anticipation 大幅动作（信任气质禁用）

## Phase 4 — 集成
- `frontend/src/components/brand/RainMailLogo.tsx`：内联 SVG + 组件级 `<style>`（reduce-motion 安全）。
- `Home.tsx`：顶部居中播放 `<RainMailLogo />`，下方保留「雨天信箱 / The Raindrop Box / 构建中」。
- 静态后备：`frontend/public/brand/logo.svg`（同矢量，无动画）。

## Phase 5 — QA
- 终态 overlay 比对（IoU + 残差说明）。
- reduced-motion 即时终态。
- 无 clip、无台阶、各部件错峰不齐步。

### 动作 QA 结果（实测，见 outputs/motion_frames/ + motion_strip.png）
- 帧序列 t=0/280/700/1000/1400ms 已捕获：t=0 全隐 → t=280 云朵浮现 → t=700 云朵就位 + 雨滴错峰落下 + 文字开始 wipe → t=1400 全部归位。
- **Final Frame Contract 通过**：`?static=1` 与 `?t=1400` 同管线像素差 = **0**（完全一致）。
- **Reduced-motion 通过**：`force-prefers-reduced-motion` 下立即显示静态终态（墨水量 43762 px，与终态一致）。
- **错峰验证**：4 滴雨滴延迟 520/600/680/760ms，自然书写顺序级联，无 lockstep。
- **缓动验证**：keyframe 内全部字面 `cubic-bezier(0,0,0.2,1)`（信任族 ease-out），无 `var()` 降级风险。
