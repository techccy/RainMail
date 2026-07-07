// =============================================================================
// 天气上下文 —— 双轮询 + 主题驱动
//   GET /api/weather       每 5min（DashboardData，驱动 weather_status）
//   GET /api/weather/meta  每 1min（weather_text/location/refresh，仅文本展示）
// 主题映射：rainy → document.documentElement 加 .dark，sunny → 去掉
// =============================================================================
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { api } from '@/lib/api';
import type { DashboardData, WeatherMeta, WeatherStatus } from '@/types/api';

const STATUS_INTERVAL = 5 * 60 * 1000; // 5min
const META_INTERVAL = 60 * 1000; // 1min

interface WeatherState {
  status: WeatherStatus;
  city: string;
  meta: WeatherMeta | null;
  messageCount: number;
  loading: boolean;
  refresh: () => Promise<void>;
}

const WeatherContext = createContext<WeatherState | null>(null);

export function WeatherProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<WeatherStatus>('sunny');
  const [city, setCity] = useState('');
  const [messageCount, setMessageCount] = useState(0);
  const [meta, setMeta] = useState<WeatherMeta | null>(null);
  const [loading, setLoading] = useState(true);
  const appliedTheme = useRef<WeatherStatus | null>(null);

  const applyTheme = useCallback((s: WeatherStatus) => {
    if (appliedTheme.current === s) return;
    appliedTheme.current = s;
    const root = document.documentElement;
    if (s === 'rainy') root.classList.add('dark');
    else root.classList.remove('dark');
  }, []);

  const fetchStatus = useCallback(async () => {
    const res = await api<DashboardData>('/api/weather');
    if (res.ok) {
      setStatus(res.data.weather_status);
      setCity(res.data.city);
      setMessageCount(res.data.message_count);
      applyTheme(res.data.weather_status);
    }
    setLoading(false);
  }, [applyTheme]);

  const fetchMeta = useCallback(async () => {
    const res = await api<WeatherMeta>('/api/weather/meta');
    if (res.ok) setMeta(res.data);
  }, []);

  useEffect(() => {
    void fetchStatus();
    void fetchMeta();
    const sTimer = setInterval(() => void fetchStatus(), STATUS_INTERVAL);
    const mTimer = setInterval(() => void fetchMeta(), META_INTERVAL);
    return () => {
      clearInterval(sTimer);
      clearInterval(mTimer);
    };
  }, [fetchStatus, fetchMeta]);

  const value = useMemo<WeatherState>(
    () => ({ status, city, meta, messageCount, loading, refresh: fetchStatus }),
    [status, city, meta, messageCount, loading, fetchStatus],
  );

  return <WeatherContext.Provider value={value}>{children}</WeatherContext.Provider>;
}

export function useWeather(): WeatherState {
  const ctx = useContext(WeatherContext);
  if (!ctx) throw new Error('useWeather 必须在 WeatherProvider 内使用');
  return ctx;
}
