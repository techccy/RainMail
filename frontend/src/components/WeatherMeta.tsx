// =============================================================================
// WeatherMeta —— 天气元信息条：location · weather_text · N 分钟后刷新
// 数据来自 useWeather 的 /api/weather/meta 轮询
// =============================================================================
import { useWeather } from '@/hooks/useWeather';

export default function WeatherMeta() {
  const { meta } = useWeather();
  if (!meta) return null;
  return (
    <p className="font-mono text-xs text-muted-foreground">
      {[meta.location, meta.weather_text, meta.next_refresh_desc ?? (meta.next_refresh_in_minutes != null ? `${meta.next_refresh_in_minutes} 分钟后刷新` : null)]
        .filter(Boolean)
        .join(' · ')}
    </p>
  );
}
