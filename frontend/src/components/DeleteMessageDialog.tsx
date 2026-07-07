// =============================================================================
// DeleteMessageDialog —— 凭安全码删除消息的确认弹窗
// 由 PublicMessage 详情页的「消息ID」旁垃圾桶按钮触发。
// 所有删除一律校验安全码（POST /api/messages/:unique_id/delete，body: { security_code }）。
// =============================================================================
import { useEffect, useState } from 'react';
import { Trash2 } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from '@/lib/api';

interface Props {
  uniqueId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDeleted: () => void;
}

export default function DeleteMessageDialog({ uniqueId, open, onOpenChange, onDeleted }: Props) {
  const [securityCode, setSecurityCode] = useState('');
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState('');

  // 弹窗关闭时清空状态，避免下次打开残留旧值
  useEffect(() => {
    if (!open) {
      setSecurityCode('');
      setDeleting(false);
      setError('');
    }
  }, [open]);

  const handleDelete = async () => {
    setDeleting(true);
    setError('');
    const res = await api<{ success: boolean }>(`/api/messages/${uniqueId}/delete`, {
      method: 'POST',
      json: { security_code: securityCode.trim() },
    });
    setDeleting(false);

    if (res.ok) {
      onOpenChange(false);
      onDeleted();
      return;
    }
    setError(res.data.error || '删除失败');
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>凭安全码删除</DialogTitle>
          <DialogDescription>
            此操作不可撤销，删除后消息及其所有回复将永久消失。
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2">
          <Input
            value={securityCode}
            onChange={(e) => setSecurityCode(e.target.value)}
            placeholder="删除安全码"
            className="font-mono tracking-wider"
            autoComplete="off"
            autoFocus
          />
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>

        <DialogFooter>
          <Button variant="destructive" onClick={handleDelete} disabled={deleting || securityCode.trim().length === 0}>
            <Trash2 className="size-4" />
            <span className="ml-1">{deleting ? '删除中…' : '删除'}</span>
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
