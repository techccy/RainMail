// =============================================================================
// IP 城市查询 —— 腾讯位置服务 LBS 为主（多 Key 轮询），MaxMind 离线库 / ipip.net 兜底
// 对齐 Python get_city_by_ip：保留 30 天 SQLite 缓存、本地 IP 短路、LOCATION_NAME 兜底
// =============================================================================
import path from 'node:path';
import crypto from 'node:crypto';
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
// 腾讯位置服务 LBS IP 定位（官方接口，主数据源）
// 文档：https://lbs.qq.com/service/webService/webServiceGuide/position/webServiceIp
// 每个 Key 每日 6000 次配额，支持填入多个 Key（逗号分隔）轮询叠加。
// 开启 SN 校验的 Key 需配置 SK，按腾讯规则计算 sig 参数。
// 签名算法：https://lbs.qq.com/faq/serverFaq/webServiceKey
// ----------------------------------------------------------------------------
interface TencentLbsResponse {
  status: number;
  message?: string;
  result?: {
    ad_info?: {
      nation?: string;
      province?: string;
      city?: string;
      district?: string;
      adcode?: string;
    };
  };
}

interface TencentKey {
  key: string;
  /** 开启 SN 校验时填入（Secret Key / SK）；未开启则省略 */
  sk?: string;
}

// 腾讯返回 status 码：0 成功；111 签名验证失败；120 每日配额耗尽；130/311 鉴权失败
const TENCENT_STATUS_DAILY_LIMIT = 120;
const TENCENT_STATUS_AUTH_FAIL = new Set([111, 130, 311]);

// 单进程内存态轮询：跨所有 IP 共享，无需 Redis
let tencentIpKeys: TencentKey[] | null = null;
let tencentNextKeyIndex = 0;
let tencentKeyCooldownUntil: number[] = [];
// 每日配额耗尽冷却 24h；鉴权/签名异常冷却 1h
const COOLDOWN_DAILY_MS = 24 * 60 * 60 * 1000;
const COOLDOWN_AUTH_MS = 60 * 60 * 1000;

/**
 * 读取 config.TENCENT_IP_KEYS（逗号分隔，格式 `key` 或 `key:sk`）。
 * trim、去空、去重（按 key），懒加载且仅加载一次。
 */
function loadTencentIpKeys(): TencentKey[] {
  if (tencentIpKeys !== null) return tencentIpKeys;
  const raw = getConfig().TENCENT_IP_KEYS;
  const value = typeof raw === 'string' ? raw : '';
  const seen = new Set<string>();
  const keys: TencentKey[] = [];
  for (const part of value.split(',')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    // 仅以第一个冒号分隔，允许 SK 中包含冒号（虽不常见）
    const sep = trimmed.indexOf(':');
    const key = (sep >= 0 ? trimmed.slice(0, sep) : trimmed).trim();
    const sk = sep >= 0 ? trimmed.slice(sep + 1).trim() : '';
    if (!key || seen.has(key)) continue;
    seen.add(key);
    keys.push(sk ? { key, sk } : { key });
  }
  tencentIpKeys = keys;
  tencentKeyCooldownUntil = new Array(keys.length).fill(0);
  if (keys.length === 0) {
    console.warn('[ipgeo] 未配置 TENCENT_IP_KEYS，IP 查询将仅使用 MaxMind / ipip.net 兜底');
  } else {
    const signed = keys.filter((k) => k.sk).length;
    console.log(
      `[ipgeo] 腾讯 LBS 已加载 ${keys.length} 个 Key（每日配额 ${keys.length * 6000} 次），其中 ${signed} 个开启 SN 签名校验`,
    );
  }
  return keys;
}

/** 小写 hex MD5 */
function md5Hex(s: string): string {
  return crypto.createHash('md5').update(s, 'utf8').digest('hex');
}

/**
 * 按腾讯规则构造带签名的请求 URL。
 * 签名串 = 请求路径 + "?" + 参数(按名升序、原始值未编码、k=v&...) + SK
 * 实际请求参数值需 encodeURIComponent；sig 单独附加。
 * 参考：https://lbs.qq.com/faq/serverFaq/webServiceKey
 */
function buildSignedUrl(ip: string, cred: TencentKey): string {
  const REQUEST_PATH = '/ws/location/v1/ip';
  // 参数按名称升序排序（ip < key）
  const params: Array<[string, string]> = [
    ['ip', ip],
    ['key', cred.key],
  ];
  params.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

  // 签名用原始值（不编码）
  const rawQuery = params.map(([k, v]) => `${k}=${v}`).join('&');
  // 实际请求用编码后的值
  const encodedQuery = params.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');

  if (cred.sk) {
    const sig = md5Hex(`${REQUEST_PATH}?${rawQuery}${cred.sk}`);
    return `https://apis.map.qq.com${REQUEST_PATH}?${encodedQuery}&sig=${sig}`;
  }
  return `https://apis.map.qq.com${REQUEST_PATH}?${encodedQuery}`;
}

async function lookupByTencentLbs(ip: string): Promise<IpInfo | null> {
  const keys = loadTencentIpKeys();
  if (keys.length === 0) return null;

  const now = Date.now();
  // 从上一次成功的下一个 Key 开始轮询，最多遍历一圈
  for (let step = 0; step < keys.length; step++) {
    const i = (tencentNextKeyIndex + step) % keys.length;
    // 跳过仍在冷却中的 Key
    if (tencentKeyCooldownUntil[i] > now) continue;

    const cred = keys[i]!;
    try {
      const url = buildSignedUrl(ip, cred);
      const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
      if (!resp.ok) {
        console.warn(`[ipgeo] 腾讯 LBS Key${i + 1} 请求失败 status=${resp.status}`);
        continue;
      }
      const data = (await resp.json()) as TencentLbsResponse;
      if (data.status === 0) {
        const ad = data.result?.ad_info ?? {};
        const country = ad.nation?.trim();
        const province = ad.province?.trim();
        const city = ad.city?.trim();
        if (!country && !province && !city) {
          // 接口成功但无地理信息，视为有效空结果：推进指针并返回 null 走兜底
          tencentNextKeyIndex = (i + 1) % keys.length;
          return null;
        }
        const info: IpInfo = {};
        if (country) info.country = country;
        if (province) info.province = province;
        if (city) info.city = city;
        // 成功：推进 round-robin 指针，下次从下一个 Key 开始均衡负载
        tencentNextKeyIndex = (i + 1) % keys.length;
        return info;
      }

      // 业务错误：根据 status 决定冷却策略
      const msg = data.message ?? '';
      if (data.status === TENCENT_STATUS_DAILY_LIMIT || msg.includes('每日') || msg.includes('每天') || msg.includes('上限')) {
        tencentKeyCooldownUntil[i] = now + COOLDOWN_DAILY_MS;
        console.warn(`[ipgeo] 腾讯 LBS Key${i + 1} 当日配额耗尽，冷却 24h：${msg}`);
      } else if (TENCENT_STATUS_AUTH_FAIL.has(data.status)) {
        // 111 签名失败 / 130 / 311 鉴权失败
        tencentKeyCooldownUntil[i] = now + COOLDOWN_AUTH_MS;
        const hint = data.status === 111 ? '（请检查 Key 的 SN 校验开关及 SK 配置）' : '';
        console.warn(`[ipgeo] 腾讯 LBS Key${i + 1} 鉴权/签名失败 (${data.status})，冷却 1h${hint}：${msg}`);
      } else {
        console.warn(`[ipgeo] 腾讯 LBS Key${i + 1} 业务错误 status=${data.status}：${msg}`);
      }
      // 继续尝试下一个 Key
    } catch (e) {
      // 网络/超时等瞬时错误：不标记冷却，下次仍可尝试该 Key
      console.warn(`[ipgeo] 腾讯 LBS Key${i + 1} 查询异常:`, (e as Error).message);
    }
  }

  // 一圈内所有 Key 均不可用
  return null;
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
 * 根据 IP 查询城市名称。查询链：腾讯 LBS（多 Key 轮询）→ MaxMind 离线 → ipip.net → 'Unknown'
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
    (await lookupByTencentLbs(ipAddress)) ??
    (await lookupByMaxmind(ipAddress)) ??
    (await lookupByIpip(ipAddress));

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
