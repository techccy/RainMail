import { Link } from 'react-router-dom';

/** M1 占位页面 —— 后续里程碑填充实际内容 */
export default function Placeholder({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <main className="mx-auto max-w-3xl px-6 py-16 animate-fade-in">
        <Link to="/" className="font-mono text-sm text-muted-foreground hover:text-foreground">
          ← RainMail
        </Link>
        <h1 className="mt-8 text-3xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-2 text-muted-foreground">{subtitle}</p>}
        <p className="mt-8 text-sm text-muted-foreground font-mono">（构建中）</p>
      </main>
    </div>
  );
}
