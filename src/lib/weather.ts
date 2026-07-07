// =============================================================================
// 和风天气 —— 多 API 轮换 + 数据库缓存 + 强制降雨
// 对齐 Python get_weather_status / get_dashboard_data / update_weather_cache
// =============================================================================
import { eq } from 'drizzle-orm';
import { db, nowIso } from '../db/index.js';
import { locationWeatherCache, messages } from '../db/schema.js';
import { getConfig } from '../config.js';

export interface ApiPair {
  host: string;
  key: string;
}

/** 从 config 读取多组 HEFENG_HOST{n}/HEFENG_KEY{n} */
export function loadApiPairs(): ApiPair[] {
  const cfg = getConfig();
  const pairs: ApiPair[] = [];
  let i = 1;
  while (true) {
    const host = cfg[`HEFENG_HOST${i}`] as string | undefined;
    const key = cfg[`HEFENG_KEY${i}`] as string | undefined;
    if (host && key) {
      pairs.push({ host, key });
      console.log(`[INFO] Loaded API Pair ${i}: ${host.substring(0, 20)}.../${key.substring(0, 5)}...`);
      i++;
    } else {
      break;
    }
  }
  if (pairs.length === 0) {
    console.error('[ERROR] 未找到任何有效的 HEFENG_HOST*/HEFENG_KEY* 配置，天气功能将不可用。');
  } else {
    console.log(`[INFO] 总共加载了 ${pairs.length} 组天气API。`);
  }
  return pairs;
}

let apiPairs: ApiPair[] = [];
let apiAvailable = false;
export function initWeather(): void {
  apiPairs = loadApiPairs();
  apiAvailable = apiPairs.length > 0;
}
export function isApiAvailable(): boolean {
  return apiAvailable;
}
export function getApiPairs(): ApiPair[] {
  return apiPairs;
}

// 强制降雨状态（内存）
let forceRainUntil: Date | null = null;

export function forceRain(durationMinutes: number): { until: string } {
  forceRainUntil = new Date(Date.now() + durationMinutes * 60_000);
  return { until: forceRainUntil.toISOString().replace('T', ' ').substring(0, 19) };
}

function isForceRaining(): boolean {
  return forceRainUntil !== null && new Date() < forceRainUntil;
}

interface WeatherFetchResult {
  status: 'sunny' | 'rainy';
  text: string;
  icon: string;
  rawData: string;
  usedApiIndex: number;
}

/** 调用和风天气 API 获取天气，按轮换索引尝试所有 API 对 */
async function fetchWeatherFromApi(city: string, cache: typeof locationWeatherCache.$inferSelect | undefined): Promise<WeatherFetchResult> {
  const numApis = apiPairs.length;
  if (numApis === 0) {
    console.error(`[ERROR] No API pairs available for ${city}`);
    const lastIdx = cache?.last_used_api_index ?? 0;
    return { status: 'sunny', text: 'API配置缺失', icon: '999', rawData: 'null', usedApiIndex: lastIdx };
  }

  const startIndex = cache?.last_used_api_index ?? 0;
  for (let i = 0; i < numApis; i++) {
    const idx = (startIndex + 1 + i) % numApis;
    const { host, key } = apiPairs[idx]!;
    try {
      console.log(`[INFO] Trying API ${idx + 1} for ${city}: ${host.substring(0, 20)}.../${key.substring(0, 5)}...`);
      // 城市查询
      const geoUrl = `https://${host}/geo/v2/city/lookup?location=${encodeURIComponent(city)}&key=${key}`;
      const geoResp = await fetch(geoUrl, { signal: AbortSignal.timeout(10000) });
      if (!geoResp.ok) {
        console.warn(`[WARN] Geo lookup request failed for ${city} using API ${idx + 1} (${host}), status ${geoResp.status}`);
        continue;
      }
      const geoData = (await geoResp.json()) as { code?: string; location?: { id: string }[] };
      if (geoData.code !== '200' || !geoData.location?.length) {
        console.warn(`[WARN] Geo lookup failed for ${city} using API ${idx + 1} (${host})`);
        continue;
      }
      const locationId = geoData.location[0]!.id;
      console.log(`[INFO] Found location ID ${locationId} for ${city}`);

      // 实时天气
      const weatherUrl = `https://${host}/v7/weather/now?location=${locationId}&key=${key}`;
      const weatherResp = await fetch(weatherUrl, { signal: AbortSignal.timeout(10000) });
      if (weatherResp.status === 429) {
        console.warn(`[WARN] API ${idx + 1} (${host}) rate limited (429) for ${city}.`);
        continue;
      }
      if (!weatherResp.ok) {
        console.warn(`[WARN] Weather API request failed for ${city}, status ${weatherResp.status}`);
        continue;
      }
      const weatherData = (await weatherResp.json()) as { code?: string; now?: { text?: string; icon?: string; precip?: string } };
      if (weatherData.code !== '200' || !weatherData.now) {
        console.warn(`[WARN] Weather API returned error for ${city}: code=${weatherData.code}`);
        continue;
      }
      const nowInfo = weatherData.now;
      const weatherText = nowInfo.text ?? '';
      const iconCode = nowInfo.icon ?? '';
      const isRainy = weatherText.includes('雨') || iconCode.startsWith('3');
      const status: 'sunny' | 'rainy' = isRainy ? 'rainy' : 'sunny';
      console.log(`[INFO] Successfully fetched weather for ${city}: ${weatherText} (${status})`);
      return {
        status,
        text: weatherText,
        icon: iconCode,
        rawData: JSON.stringify(nowInfo),
        usedApiIndex: idx,
      };
    } catch (e) {
      console.error(`[ERROR] Request failed for ${city} using API ${idx + 1} (${host}):`, e);
      continue;
    }
  }

  console.error(`[ERROR] All ${numApis} API pairs failed to fetch weather for ${city}.`);
  const lastIdx = cache?.last_used_api_index ?? 0;
  return { status: 'sunny', text: '获取失败', icon: '999', rawData: 'null', usedApiIndex: lastIdx };
}

function parseIso(v: string | null | undefined): Date | null {
  if (!v) return null;
  const d = new Date(v.includes('T') ? v : v.replace(' ', 'T') + 'Z');
  return isNaN(d.getTime()) ? null : d;
}

/** 获取天气状态（带缓存与强制降雨） */
export async function getWeatherStatus(city = '广州'): Promise<'sunny' | 'rainy'> {
  const askTimes = Number(getConfig().times ?? 3600) * 1000;

  if (isForceRaining()) {
    const cache = db.select().from(locationWeatherCache).where(eq(locationWeatherCache.city, city)).limit(1).all()[0];
    if (cache) {
      db.update(locationWeatherCache)
        .set({ weather_status: 'rainy', weather_text: '强制降雨', icon_code: '300', last_updated: nowIso() })
        .where(eq(locationWeatherCache.id, cache.id))
        .run();
    }
    return 'rainy';
  }

  let cache = db.select().from(locationWeatherCache).where(eq(locationWeatherCache.city, city)).limit(1).all()[0];
  const lastUpdated = parseIso(cache?.last_updated);
  if (cache && lastUpdated && Date.now() - lastUpdated.getTime() < askTimes) {
    console.log(`[INFO] Cache for ${city} is fresh, returning cached status: ${cache.weather_status}`);
    return cache.weather_status === 'rainy' ? 'rainy' : 'sunny';
  }

  console.log(`[INFO] Cache for ${city} is stale or missing, updating...`);
  const result = await fetchWeatherFromApi(city, cache);
  const now = nowIso();
  if (cache) {
    db.update(locationWeatherCache)
      .set({
        weather_status: result.status,
        weather_text: result.text,
        icon_code: result.icon,
        raw_weather_data: result.rawData,
        last_updated: now,
        last_used_api_index: result.usedApiIndex,
      })
      .where(eq(locationWeatherCache.id, cache.id))
      .run();
  } else {
    db.insert(locationWeatherCache)
      .values({
        city,
        weather_status: result.status,
        weather_text: result.text,
        icon_code: result.icon,
        raw_weather_data: result.rawData,
        last_updated: now,
        last_used_api_index: result.usedApiIndex,
      })
      .run();
    cache = db.select().from(locationWeatherCache).where(eq(locationWeatherCache.city, city)).limit(1).all()[0];
  }
  console.log(`[INFO] Updated cache for ${city}: ${result.text} (${result.status}), using API ${result.usedApiIndex + 1}`);
  return result.status;
}

export interface DashboardData {
  weather_status: 'sunny' | 'rainy';
  precip_prob: string;
  cpu_temp: number;
  message_count: number;
  city: string;
  /** 访问者位置的 IANA 时区（MaxMind 命中时下发）；未定位时省略，前端回退浏览器本地时区 */
  timezone?: string | null;
}

/** 获取仪表盘数据 */
export async function getDashboardData(city = '广州', timezone: string | null = null): Promise<DashboardData> {
  const weatherStatus = await getWeatherStatus(city);
  const cache = db.select().from(locationWeatherCache).where(eq(locationWeatherCache.city, city)).limit(1).all()[0];
  let precipProb = '0';
  if (cache?.raw_weather_data && cache.raw_weather_data !== 'null') {
    try {
      const raw = JSON.parse(cache.raw_weather_data) as { precip?: string };
      precipProb = raw.precip ?? '0';
    } catch {
      precipProb = '0';
    }
  }

  // 仅统计已通过 AI 审核的消息（pending/rejected 不计入展示计数）
  const messageCount = db.select().from(messages).all().filter((m) => (m.review_status ?? 'approved') === 'approved').length;
  return {
    weather_status: weatherStatus,
    precip_prob: precipProb,
    cpu_temp: Math.round(getCpuTemperature() * 10) / 10,
    message_count: messageCount,
    city,
    timezone: timezone || undefined,
  };
}

/** 获取 CPU 温度（简化：返回默认值，原 Python 用 powermetrics 仅 macOS） */
function getCpuTemperature(): number {
  return 45.0;
}

/** 天气元信息（/api/weather/meta） */
export async function getWeatherMeta(city: string, timezone: string | null = null): Promise<Record<string, any>> {
  const askTimes = Number(getConfig().times ?? 3600);
  const cache = db.select().from(locationWeatherCache).where(eq(locationWeatherCache.city, city)).limit(1).all()[0];
  if (cache) {
    const lastUpdated = parseIso(cache.last_updated)!;
    const elapsed = Date.now() / 1000 - lastUpdated.getTime() / 1000;
    const remaining = Math.max(0, askTimes - elapsed);
    return {
      location: city,
      weather_text: cache.weather_text,
      last_update: lastUpdated.toISOString().replace('T', ' ').substring(0, 19),
      next_refresh_in_seconds: Math.floor(remaining),
      next_refresh_in_minutes: Math.floor(remaining / 60),
      next_refresh_desc: `最快 ${Math.round(askTimes / 60)} 分钟后刷新`,
      current_state: cache.weather_status,
      city_specific: true,
      timezone: timezone || undefined,
    };
  }
  return {
    location: city,
    weather_text: '未知',
    last_update: null,
    next_refresh_in_seconds: 0,
    next_refresh_desc: `最快 ${Math.round(askTimes / 60)} 分钟后刷新`,
    current_state: 'sunny',
    city_specific: true,
    timezone: timezone || undefined,
  };
}
