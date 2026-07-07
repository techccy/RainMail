// =============================================================================
// IP 城市查询 —— MaxMind 离线库为主，ipip.net / 腾讯接口兜底
// 对齐 Python get_city_by_ip：保留 30 天 SQLite 缓存、本地 IP 短路、LOCATION_NAME 兜底
// =============================================================================
import path from 'node:path';
import { eq } from 'drizzle-orm';
import maxmind, { Reader, type CityResponse } from 'maxmind';
import { db, nowIso } from '../db/index.js';
import { ipLocationCache } from '../db/schema.js';
import { PROJECT_ROOT, getConfig } from '../config.js';

// 30 天缓存有效期
const CACHE_EXPIRY_MS = 30 * 24 * 3_600_000;

function parseIso(v: string | null | undefined): Date | null {
  if (!v) return null;
  const d = new Date(v.includes('T') ? v : v.replace(' ', 'T') + 'Z');
  return isNaN(d.getTime()) ? null : d;
}

// 内部统一的地理位置结构
interface IpInfo {
  country?: string;
  province?: string;
  city?: string;
}

// ----------------------------------------------------------------------------
// MaxMind 离线库（懒加载，模块级缓存，仅打开一次）
// ----------------------------------------------------------------------------
let maxmindReaderPromise: Promise<Reader<CityResponse> | null> | null = null;

function defaultMmdbPath(): string {
  const cfg = getConfig() as Record<string, unknown>;
  const configured = typeof cfg.MAXMIND_DB_PATH === 'string' ? cfg.MAXMIND_DB_PATH.trim() : '';
  return configured || path.join(PROJECT_ROOT, 'data', 'GeoLite2-City.mmdb');
}

async function getMaxmindReader(): Promise<Reader<CityResponse> | null> {
  if (!maxmindReaderPromise) {
    maxmindReaderPromise = (async () => {
      const dbPath = defaultMmdbPath();
      try {
        const reader = await maxmind.open<CityResponse>(dbPath);
        console.log(`[ipgeo] MaxMind 离线库已加载: ${dbPath}`);
        return reader;
      } catch (e) {
        console.warn(`[ipgeo] MaxMind 离线库不可用 (${dbPath})，将仅使用网络兜底:`, (e as Error).message);
        return null;
      }
    })();
  }
  return maxmindReaderPromise;
}

/** 优先取中文名，缺省回退英文 */
function pickName(names?: { 'zh-CN'?: string; en?: string }): string | undefined {
  if (!names) return undefined;
  return names['zh-CN']?.trim() || names.en?.trim() || undefined;
}

async function lookupByMaxmind(ip: string): Promise<IpInfo | null> {
  const reader = await getMaxmindReader();
  if (!reader) return null;
  try {
    const resp = reader.get(ip);
    if (!resp) return null;
    const info: IpInfo = {};
    const country = pickName(resp.country?.names);
    const province = pickName(resp.subdivisions?.[0]?.names);
    const city = pickName(resp.city?.names);
    if (country) info.country = country;
    if (province) info.province = province;
    if (city) info.city = city;
    return Object.keys(info).length ? info : null;
  } catch (e) {
    console.warn('[ipgeo] MaxMind 查询失败:', (e as Error).message);
    return null;
  }
}

// ----------------------------------------------------------------------------
// ipip.net 免费接口兜底
// 返回格式：["country","province","city",...]
// ----------------------------------------------------------------------------
async function lookupByIpip(ip: string): Promise<IpInfo | null> {
  try {
    const url = `https://freeapi.ipip.net/${encodeURIComponent(ip)}`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) {
      console.warn(`[ipgeo] ipip.net 请求失败 status=${resp.status}`);
      return null;
    }
    const data = (await resp.json()) as unknown;
    if (!Array.isArray(data) || data.length === 0) return null;
    const info: IpInfo = {};
    const clean = (v: unknown) => (typeof v === 'string' ? v.trim() : '');
    const country = clean(data[0]);
    const province = clean(data[1]);
    const city = clean(data[2]);
    if (country && country !== 'N/A') info.country = country;
    if (province && province !== 'N/A') info.province = province;
    if (city && city !== 'N/A') info.city = city;
    return Object.keys(info).length ? info : null;
  } catch (e) {
    console.warn('[ipgeo] ipip.net 查询失败:', (e as Error).message);
    return null;
  }
}

// ----------------------------------------------------------------------------
// 腾讯 ip2city 接口兜底（免费免 Key）
// 实测响应为扁平结构：{ ret:0, country, province, city, district, isp, ... }
// 兼容部分版本可能返回的嵌套结构 result.ad_info.{nation,province,city}
// ----------------------------------------------------------------------------
interface TencentIpResponse {
  ret?: number;
  country?: string;
  province?: string;
  city?: string;
  result?: {
    ad_info?: {
      nation?: string;
      province?: string;
      city?: string;
    };
  };
}

async function lookupByTencent(ip: string): Promise<IpInfo | null> {
  try {
    const url = `https://r.inews.qq.com/api/ip2city?ip=${encodeURIComponent(ip)}`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) {
      console.warn(`[ipgeo] 腾讯 ip2city 请求失败 status=${resp.status}`);
      return null;
    }
    const data = (await resp.json()) as TencentIpResponse;
    // 优先扁平字段，回退嵌套 ad_info
    const country = data.country?.trim() || data.result?.ad_info?.nation?.trim();
    const province = data.province?.trim() || data.result?.ad_info?.province?.trim();
    const city = data.city?.trim() || data.result?.ad_info?.city?.trim();
    if (!country && !province && !city) return null;
    const info: IpInfo = {};
    if (country) info.country = country;
    if (province) info.province = province;
    if (city) info.city = city;
    return info;
  } catch (e) {
    console.warn('[ipgeo] 腾讯 ip2city 查询失败:', (e as Error).message);
    return null;
  }
}

/** 按 city → province → country → 'Unknown' 优先级挑选结果 */
function pickCity(info: IpInfo): string {
  const candidates = [info.city, info.province, info.country];
  for (const v of candidates) {
    if (v && v.toLowerCase() !== 'unknown') return v;
  }
  return 'Unknown';
}

/** 是否为本地/内网 IP，无需走查询链 */
function isLocalIp(ip: string): boolean {
  if (ip === '127.0.0.1' || ip === '::1') return true;
  // IPv4 内网段：10.x / 172.16-31.x / 192.168.x
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  return false;
}

/**
 * 根据 IP 查询城市名称。查询链：MaxMind 离线 → ipip.net → 腾讯 → 'Unknown'
 * 本地/内网 IP 直接返回 LOCATION_NAME；结果缓存 30 天。
 */
export async function getCityByIp(ipAddress: string): Promise<string> {
  // 本地 IP 短路
  if (isLocalIp(ipAddress)) {
    return String(getConfig().LOCATION_NAME ?? '广州');
  }

  // 命中缓存（30 天内）则直接返回
  const cache = db.select().from(ipLocationCache).where(eq(ipLocationCache.ip_address, ipAddress)).limit(1).all()[0];
  const updatedAt = parseIso(cache?.updated_at);
  if (cache && updatedAt && Date.now() - updatedAt.getTime() < CACHE_EXPIRY_MS) {
    return cache.city;
  }
  if (cache) {
    console.log(`[ipgeo] 缓存已过期，重新查询 ${ipAddress}`);
  }

  // 三段式查询链：任一成功即返回
  let info: IpInfo | null =
    (await lookupByMaxmind(ipAddress)) ??
    (await lookupByIpip(ipAddress)) ??
    (await lookupByTencent(ipAddress));

  const city = info ? pickCity(info) : 'Unknown';
  console.log(`[ipgeo] ${ipAddress} -> ${city}`);

  // 兜底失败时使用默认城市
  const finalCity = city === 'Unknown' ? String(getConfig().LOCATION_NAME ?? '广州') : city;

  // 写回缓存
  const now = nowIso();
  if (cache) {
    db.update(ipLocationCache).set({ city: finalCity, updated_at: now }).where(eq(ipLocationCache.id, cache.id)).run();
  } else {
    db.insert(ipLocationCache).values({ ip_address: ipAddress, city: finalCity, created_at: now, updated_at: now }).run();
  }

  return finalCity;
}
