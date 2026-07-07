// =============================================================================
// API 类型 —— 对齐 Hono 后端契约（见探索报告中的端点表）
// =============================================================================

/** 天气状态：晴天信箱封存，雨天公开广播 */
export type WeatherStatus = 'sunny' | 'rainy';

/** GET /api/bootstrap —— 前端启动配置 */
export interface BootstrapConfig {
  app_name: string;
  app_name_cn: string;
}

/** GET /api/weather —— DashboardData */
export interface DashboardData {
  weather_status: WeatherStatus;
  precip_prob: string;
  cpu_temp: number;
  message_count: number;
  city: string;
  /** 访问者位置的 IANA 时区（MaxMind 命中时下发）；未定位时不存在，前端回退浏览器本地时区 */
  timezone?: string;
}

/** GET /api/weather/meta */
export interface WeatherMeta {
  location: string;
  weather_text: string;
  last_update?: string;
  next_refresh_in_seconds?: number;
  next_refresh_in_minutes?: number;
  next_refresh_desc?: string;
  current_state?: string;
  city_specific?: string;
  timezone?: string;
}

/** GET /api/messages 列表项 / GET /api/user/sent 列表项 */
export interface PublicMessage {
  id: number;
  content: string;
  created_at: string;
  location: string | null;
  unique_identifier: string;
  delivery_type: 'public' | 'private';
  is_anonymous: boolean;
  hugs_count: number;
}

export interface MessagesResponse {
  messages: PublicMessage[];
  weather_status: WeatherStatus;
  city: string;
  timezone?: string;
}

/** POST /api/messages 响应的 share_data */
export interface ShareData {
  message_id: number;
  unique_identifier: string;
  share_url: string;
  full_share_url: string;
  total_messages: number;
  created_at: string;
  weather_status: WeatherStatus;
  delivery_type: 'public' | 'private';
  review_status?: 'pending' | 'approved' | 'rejected';
  /** 删除安全码（16 位，4 位一段空格隔开）—— 仅在发布响应中明文返回一次 */
  security_code: string;
}

/** POST /api/messages 提交体 */
export interface SubmitMessageBody {
  content: string;
  delivery_type: 'public' | 'private';
  delivery_options: { type: 'public' | 'private'; recipient_email?: string; emailNotification?: boolean };
  reply_notification: 'none' | 'email';
  is_anonymous: boolean;
  public_after_reply: boolean;
  sender_email: string;
  // 行为验证
  form_token: string;
  page_stay_time: number;
  input_focus_count: number;
  input_char_count: number;
  // 蜜罐（必须为空）
  website: string;
}

/** GET /api/user/profile */
export interface UserProfile {
  id: number;
  email: string;
  username: string;
  city: string | null;
  is_verified: boolean;
  created_at: string;
}

export interface ProfileResponse {
  user: UserProfile;
}

/** GET /api/user/inbox 列表项 */
export interface InboxLetter {
  id: number;
  message_id: number;
  sender_location: string | null;
  is_unlocked: boolean;
  is_read: boolean;
  created_at: string;
  unlocked_at: string | null;
}

export interface InboxResponse {
  letters: InboxLetter[];
}

/** GET /api/user/notifications 列表项 */
export interface AppNotification {
  id: number;
  type: string;
  title: string;
  content: string;
  related_id?: number;
  is_read: boolean;
  created_at: string;
}

/** /m/:id 公开消息详情页：回复列表项 */
export interface MessageReply {
  id: number;
  reply_content: string;
  reply_type: 'text' | 'hug';
  created_at: string;
  replier_user_id?: number | null;
  replier_email?: string | null;
}

/** GET /api/letters/:id 信件详情 */
export interface LetterDetail {
  delivery_id: number;
  message_id: number;
  is_unlocked: boolean;
  is_read: boolean;
  location: string | null;
  created_at: string;
  unlocked_at: string | null;
  content: string | null;
  hugs_count: number;
}

/** GET /m/:id 公开消息详情（含 message + replies）—— 由后端 SSR 提供；
 *  SPA 通过该页直接渲染（首屏数据在 HTML 内）。前端用专用接口可选。 */
export interface PublicMessageDetail {
  message: PublicMessage & { delivery_type: 'public' | 'private' };
  replies: MessageReply[];
}

/** 统一错误响应 */
export interface ApiError {
  error: string;
  [key: string]: unknown;
}
