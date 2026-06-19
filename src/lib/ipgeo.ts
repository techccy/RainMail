// =============================================================================
// IP -> 城市（ip-api.com）+ 数据库缓存
// 对齐 Python get_city_by_ip（缓存 30 天）
// =============================================================================
import { and, eq } from 'drizzle-orm';
import { db } from '../db/index.js';
import { ipLocationCache } from '../db/schema.js';
import { getConfig } from '../config.js';

const CACHE_EXPIRY_MS = 30 * 24 * 3_600_000;

function parseIso(v: string | null | undefined): Date | null {
  if (!v) return null;
  const d = new Date(v.includes('T') ? v : v.replace(' ', 'T') + 'Z');
  return isNaN(d.getTime()) ? null : d;
}

export async function getCityByIp(ipAddress: string): Promise<string> {
  if (!ipAddress || ipAddress === '127.0.0.1' || ipAddress === '::1') {
    return String(getConfig().LOCATION_NAME ?? '广州');
  }

  // 缓存命中？
  const cached = db.select().from(ipLocationCache).where(eq(ipLocationCache.ip_address, ipAddress)).limit(1).all()[0];
  if (cached) {
    const updated = parseIso(cached.updated_at);
    if (updated && Date.now() - updated.getTime() < CACHE_EXPIRY_MS) {
      console.log(`[INFO] Resolved ${ipAddress} to '${cached.city}' from cache.`);
      return cached.city;
    }
    console.log(`[INFO] Cache for ${ipAddress} is expired, fetching fresh data...`);
  }

  try {
    const url = `http://ip-api.com/json/${encodeURIComponent(ipAddress)}?fields=status,message,country,regionName,city`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(10000) });
    const data = (await resp.json()) as {
      status?: string;
      city?: string;
      regionName?: string;
      country?: string;
      message?: string;
    };

    if (data.status === 'success') {
      let result = 'Unknown';
      if (data.city && data.city.toLowerCase() !== 'unknown') result = data.city;
      else if (data.regionName && data.regionName.toLowerCase() !== 'unknown') result = data.regionName;
      else if (data.country && data.country.toLowerCase() !== 'unknown') result = data.country;

      console.log(`[INFO] Resolved ${ipAddress} to '${result}' via ip-api.com`);

      const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
      if (cached) {
        db.update(ipLocationCache)
          .set({ city: result, updated_at: now })
          .where(eq(ipLocationCache.id, cached.id))
          .run();
      } else {
        db.insert(ipLocationCache)
          .values({ ip_address: ipAddress, city: result, created_at: now, updated_at: now })
          .run();
      }
      return result;
    }

    console.warn(`[ipgeo] ip-api.com failed for ${ipAddress}: ${data.message ?? 'Unknown error'}`);
    return String(getConfig().LOCATION_NAME ?? '广州');
  } catch (e) {
    console.error(`[ipgeo] Error resolving ${ipAddress}:`, e);
    return String(getConfig().LOCATION_NAME ?? '广州');
  }
}

void and; // 保留以备后续组合查询
