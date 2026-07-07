// =============================================================================
// 日期格式化 —— 按访问者位置时区展示公开信息时间
// 后端 created_at 为 nowIso() 产生的 "YYYY-MM-DD HH:MM:SS"（无时区标记，实为 UTC）。
// 直接 new Date(str) 会被当成本地时间（错误），故这里显式补 'Z' 标记为 UTC 再格式化。
// =============================================================================

/** 把后端 "YYYY-MM-DD HH:MM:SS"（UTC）或 ISO 串规整为可被 Date 正确解析为 UTC 的串 */
function toUtcIso(iso: string): string {
  const trimmed = iso.trim();
  // 后端格式 "YYYY-MM-DD HH:MM:SS"（空格分隔、无时区）→ 视为 UTC
  if (/^\d{4}-\d{2}-\d{2}[ ]\d{2}:\d{2}:\d{2}$/.test(trimmed)) {
    return trimmed.replace(' ', 'T') + 'Z';
  }
  // 已经带 T 或时区标记的 ISO 串原样返回
  return trimmed;
}

/**
 * 按 IANA 时区格式化时间为本地短日期+短时间。
 * @param iso 后端 created_at（UTC "YYYY-MM-DD HH:MM:SS" 或 ISO 串）
 * @param timeZone IANA 时区（如 "Asia/Shanghai"）；省略则用访问者运行环境默认时区
 */
export function formatDateTime(iso: string, timeZone?: string): string {
  try {
    const d = new Date(toUtcIso(iso));
    if (isNaN(d.getTime())) return iso;
    const opts: Intl.DateTimeFormatOptions = { dateStyle: 'short', timeStyle: 'short' };
    if (timeZone) opts.timeZone = timeZone;
    return new Intl.DateTimeFormat('zh-CN', opts).format(d);
  } catch {
    return iso;
  }
}
