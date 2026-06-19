// =============================================================================
// 天气解锁后台任务 —— 每 5 分钟运行一次
// 对齐 Python weather_unlock_worker：扫描 pending 信件，收件人城市下雨则解锁
// =============================================================================
import { eq } from 'drizzle-orm';
import { db, nowIso } from '../db/index.js';
import { letterDeliveries, notifications } from '../db/schema.js';
import { getWeatherStatus } from '../lib/weather.js';
import { sendLetterUnlockedNotification } from '../lib/mail.js';
import { pseudoContext } from '../lib/pseudoContext.js';
import { getConfig } from '../config.js';

const c = pseudoContext();

async function runOnce(): Promise<void> {
  try {
    const pending = db.select().from(letterDeliveries).where(eq(letterDeliveries.delivery_status, 'pending')).all();
    if (pending.length === 0) return;

    const cfg = getConfig();
    const title = String(cfg.NOTIFICATION_LETTER_UNLOCKED_TITLE ?? '🌧️ 信件已解锁');
    const content = String(cfg.NOTIFICATION_LETTER_UNLOCKED_CONTENT ?? '雨天已至，你有一封来自远方的信已解锁，快去查看吧！');

    let unlocked = 0;
    for (const delivery of pending) {
      try {
        const city = delivery.recipient_city || '广州';
        const weather = await getWeatherStatus(city);
        if (weather === 'rainy') {
          db.update(letterDeliveries)
            .set({ delivery_status: 'delivered', unlocked_at: nowIso() })
            .where(eq(letterDeliveries.id, delivery.id))
            .run();

          if (delivery.recipient_user_id) {
            db.insert(notifications)
              .values({
                user_id: delivery.recipient_user_id,
                notification_type: 'letter_unlocked',
                title,
                content,
                related_id: delivery.message_id,
                created_at: nowIso(),
              })
              .run();
          }

          sendLetterUnlockedNotification(c, delivery);
          unlocked++;
          console.log(`[WeatherUnlockWorker] 信件 ${delivery.id} 已解锁（城市：${city}，天气：${weather}）`);
        }
      } catch (e) {
        console.error(`[WeatherUnlockWorker] 解锁信件 ${delivery.id} 时出错:`, e);
      }
    }
    if (unlocked > 0) console.log(`[WeatherUnlockWorker] 本次解锁了 ${unlocked} 封信件`);
  } catch (e) {
    console.error('[WeatherUnlockWorker] 任务出错:', e);
  }
}

export function startWeatherUnlockWorker(): NodeJS.Timeout {
  console.log('[WeatherUnlockWorker] 启动天气解锁检查');
  // 启动后立即跑一次
  runOnce().catch(() => {});
  return setInterval(() => {
    runOnce().catch((e) => console.error('[WeatherUnlockWorker] error:', e));
  }, 300_000);
}
