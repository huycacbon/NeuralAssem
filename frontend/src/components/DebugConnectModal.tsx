/**
 * Debug modal - local-launch only.
 *
 * The earlier version of this modal also offered a "remote" mode (connect
 * to a `dbgsrv` process server the user ran themselves, e.g. inside an
 * isolated VM) backed by `ComtypesDebugBridge`'s `dbgeng.dll`/COM calls.
 * That whole remote-debug feature was removed at explicit user request,
 * after a long, confirmed-live chain of dbgeng/COM-specific failures - see
 * `backend/app/dynamic/debug_bridge/win32_debug.py`'s module docstring for
 * the full story. Local-launch (`Win32DebugBridge`, the plain Win32 debug
 * API) is the only way to start a debug session now.
 *
 * Flow:
 *   1. Mandatory general warning (safety constraint #6) - shown once per
 *      page session.
 *   2. Local-launch-specific warning - shown EVERY time this modal opens,
 *      not once-per-session like step 1, because this executes an
 *      arbitrary path directly with no isolation of any kind - plus a
 *      required confirmation checkbox.
 *   3. Command-line input (or the one-click "run the file just uploaded"
 *      shortcut). See
 *      `backend/app/dynamic/debug_bridge/win32_debug.py`'s
 *      `create_and_attach_local` docstring for the full rationale.
 *
 * No step is skippable or auto-advanced.
 */

import { useEffect, useState } from 'react';

import { ConfirmDialog } from '@/components/ConfirmDialog';
import { debugApi } from '@/services/debugApi';
import type { RiskCheckResponse } from '@/types/debug';

interface DebugConnectModalProps {
  open: boolean;
  analysisId: string;
  /** True once the user has confirmed the general warning step earlier in
   *  this page session (in-memory only in App.tsx - never persisted to disk). */
  warningAcknowledged: boolean;
  onAcknowledgeWarning: () => void;
  connecting: boolean;
  connectError: string | null;
  onClose: () => void;
  /** Local-launch: makes the app itself execute `commandLine` on this
   *  machine. See module docstring above. */
  onLaunchLocal: (commandLine: string) => void;
  /** The exact file still held in memory from the original upload, if any -
   *  offered as a one-click local-launch option (see `local-form` step
   *  below). `null` before any file has been uploaded this page session. */
  uploadedFile: File | null;
  /** Local-launch from `uploadedFile` - see `debugApi.launchLocalFromUpload`'s
   *  docstring for the full rationale (this is the one path that turns
   *  "upload a sample" directly into "the app can execute it"). */
  onLaunchLocalFromUpload: () => void;
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

type Mode = 'local-warning' | 'local-form';

const RISK_BUCKET_LABEL: Record<string, string> = {
  none: 'Không phát hiện tín hiệu rủi ro nào từ phân tích tĩnh',
  low: 'Rủi ro thấp theo heuristic tĩnh',
  medium: 'Rủi ro trung bình theo heuristic tĩnh',
  high: 'Rủi ro CAO — heuristic tĩnh cho thấy khả năng cao là mã độc thật',
};

export function DebugConnectModal({
  open,
  analysisId,
  warningAcknowledged,
  onAcknowledgeWarning,
  connecting,
  connectError,
  onClose,
  onLaunchLocal,
  uploadedFile,
  onLaunchLocalFromUpload,
}: DebugConnectModalProps): JSX.Element | null {
  const [risk, setRisk] = useState<RiskCheckResponse | null>(null);
  const [mode, setMode] = useState<Mode>('local-warning');

  // `localWarningAcknowledged` intentionally resets every time the modal
  // opens (unlike `warningAcknowledged`, which is owned by App.tsx and
  // persists for the page session) - this warning is deliberately more
  // insistent given the higher stakes (direct, unsandboxed execution).
  const [localWarningAcknowledged, setLocalWarningAcknowledged] = useState(false);
  const [commandLine, setCommandLine] = useState('');

  useEffect(() => {
    if (!open) return;
    setRisk(null);
    setMode('local-warning');
    setLocalWarningAcknowledged(false);
    setCommandLine('');
    void debugApi
      .riskCheck(analysisId)
      .then(setRisk)
      // Best-effort only - the warning text still shows without a risk
      // bucket, and this must never block the modal from opening.
      .catch(() => setRisk(null));
  }, [open, analysisId]);

  if (!open) return null;

  if (!warningAcknowledged) {
    return (
      <ConfirmDialog
        open
        title="Debug thật — sample sẽ được thực thi"
        confirmLabel="Tôi đã hiểu, tiếp tục"
        onConfirm={onAcknowledgeWarning}
        onCancel={onClose}
      >
        <p>
          Tiếp tục sẽ mở một phiên debug <strong>thật</strong>: app tự thực thi trực tiếp file bạn
          chỉ định, ngay trên máy đang chạy app — <strong>không qua VM, không qua bất kỳ cách ly
          nào</strong>.
        </p>
        {risk && (
          <p className={`risk-callout risk-${risk.riskBucket}`}>
            {RISK_BUCKET_LABEL[risk.riskBucket] ?? risk.riskBucket} (điểm {risk.riskScore})
            {risk.likelyPacked ? ' — sample có thể bị pack' : ''}.
          </p>
        )}
        <ul>
          <li>Chỉ dùng cho phần mềm <strong>bạn hoàn toàn tin cậy</strong>.</li>
          <li>
            Với mẫu chưa xác định/nghi ngờ mã độc: chạy trong một VM cách ly riêng (host-only,
            không NAT ra Internet, đã snapshot ở trạng thái sạch) — trách nhiệm chuẩn bị VM đó là
            của bạn, app không tự làm việc này.
          </li>
        </ul>
      </ConfirmDialog>
    );
  }

  if (mode === 'local-warning') {
    return (
      <ConfirmDialog
        open
        title="⚠️ App sẽ thực thi trực tiếp — không qua cách ly nào"
        confirmLabel="Tôi xác nhận file này an toàn, tiếp tục"
        confirmDisabled={!localWarningAcknowledged}
        cancelLabel="Hủy"
        onConfirm={() => setMode('local-form')}
        onCancel={onClose}
      >
        <p>
          App <strong>tự thực thi trực tiếp</strong> file bạn chỉ định ngay trên máy đang chạy app
          — <strong>không qua VM, không qua bất kỳ cách ly nào</strong>.
        </p>
        <ul>
          <li>Chỉ dùng cho phần mềm <strong>bạn hoàn toàn tin cậy</strong> (vd. chính app bạn đang phát triển, hoặc sample benign trong <code className="mono">samples/</code>).</li>
          <li><strong>Không dùng</strong> cho mẫu chưa xác định, nghi ngờ, hoặc bất kỳ sample nào bạn không hoàn toàn chắc chắn — chạy những trường hợp đó trong một VM cách ly riêng.</li>
          <li>Bạn tự chịu trách nhiệm về hậu quả nếu file được thực thi gây hại cho máy này.</li>
        </ul>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 10, fontSize: 12.5 }}>
          <input
            type="checkbox"
            checked={localWarningAcknowledged}
            onChange={(event) => setLocalWarningAcknowledged(event.target.checked)}
          />
          <span>Tôi xác nhận file này an toàn và tôi chịu trách nhiệm.</span>
        </label>
      </ConfirmDialog>
    );
  }

  // mode === 'local-form'
  const canLaunch = commandLine.trim().length > 0;
  return (
    <ConfirmDialog
      open
      title="Chạy trực tiếp trên máy này"
      confirmLabel={connecting ? 'Đang chạy...' : 'Chạy'}
      confirmDisabled={!canLaunch || connecting}
      cancelLabel="Quay lại"
      onConfirm={() => onLaunchLocal(commandLine.trim())}
      onCancel={() => setMode('local-warning')}
    >
      {uploadedFile && (
        <div className="chip-row" style={{ marginBottom: 12 }}>
          <button type="button" disabled={connecting} onClick={onLaunchLocalFromUpload}>
            {connecting
              ? 'Đang chạy...'
              : `Chạy file vừa upload: ${uploadedFile.name} (${formatFileSize(uploadedFile.size)})`}
          </button>
        </div>
      )}
      <p>
        Hoặc nhập đường dẫn (và tham số nếu có) tới một file khác muốn chạy. App sẽ thực thi trực
        tiếp trên máy này ngay khi bạn bấm "Chạy".
      </p>
      <label className="field">
        <span>Command line</span>
        <input
          type="text"
          className="mono"
          value={commandLine}
          onChange={(event) => setCommandLine(event.target.value)}
          placeholder={String.raw`C:\path\to\app.exe --flag`}
        />
      </label>
      {connectError && <p className="disclaimer error-text">{connectError}</p>}
    </ConfirmDialog>
  );
}
