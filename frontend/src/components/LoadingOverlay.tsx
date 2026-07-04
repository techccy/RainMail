/**
 * LoadingOverlay —— 投信时的全屏加载遮罩。
 *
 * 半透明黑底遮罩 + 旋转图标 + 「投递中…」文字，用于投信请求期间防重复提交、
 * 给用户明确反馈。请求完成（成功/失败/需登录）后由父组件关闭。
 */
import { LoaderCircle } from 'lucide-react';

interface LoadingOverlayProps {
  /** 点击遮罩关闭（仅在请求卡住等异常场景允许） */
  onCancel?: () => void;
}

export function LoadingOverlay({ onCancel }: LoadingOverlayProps) {
  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/75 backdrop-blur-sm"
      role="status"
      aria-live="polite"
      aria-label="投递中"
      onClick={onCancel}
    >
      <div className="flex flex-col items-center gap-3 text-stone-200">
        <LoaderCircle className="size-10 animate-spin" />
        <span className="text-sm tracking-wide">投递中…</span>
      </div>
    </div>
  );
}

export default LoadingOverlay;
