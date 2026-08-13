/**
 * Debug modal, now a multi-step flow:
 *   1. Mandatory general warning (safety constraint #6) - real execution
 *      somewhere, VM/network/snapshot responsibility disclaimer - shown once
 *      per page session. Unchanged from the original two-step version.
 *   2. Mode choice: remote (connect to a `dbgsrv` the user runs themselves,
 *      anywhere - a VM, another machine, or even this one via 127.0.0.1) vs.
 *      local-launch (the app itself executes a path directly on this
 *      machine).
 *   3a. Remote: the original host/port/processId/processName form, unchanged.
 *   3b. Local-launch: its OWN distinctly-worded warning - shown EVERY time
 *      this path is taken, not once-per-session like step 1, because this
 *      is qualitatively more dangerous (the app executes an arbitrary path,
 *      no isolation of any kind) - plus a required confirmation checkbox,
 *      then the command-line input. See
 *      `backend/app/dynamic/debug_bridge/client.py`'s
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
  onConnect: (
    host: string,
    port: number,
    processId: number | null,
    processName: string | null,
  ) => void;
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

type Mode = 'choose' | 'remote' | 'local-warning' | 'local-form';

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
  onConnect,
  onLaunchLocal,
  uploadedFile,
  onLaunchLocalFromUpload,
}: DebugConnectModalProps): JSX.Element | null {
  const [risk, setRisk] = useState<RiskCheckResponse | null>(null);
  const [mode, setMode] = useState<Mode>('choose');

  // Remote form fields.
  const [host, setHost] = useState('');
  const [port, setPort] = useState('');
  const [processId, setProcessId] = useState('');
  const [processName, setProcessName] = useState('');

  // Local-launch fields. `localWarningAcknowledged` intentionally resets
  // every time the modal opens (unlike `warningAcknowledged`, which is
  // owned by App.tsx and persists for the page session) - this warning is
  // deliberately more insistent given the higher stakes.
  const [localWarningAcknowledged, setLocalWarningAcknowledged] = useState(false);
  const [commandLine, setCommandLine] = useState('');

  useEffect(() => {
    if (!open) return;
    setRisk(null);
    setMode('choose');
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
          Tiếp tục sẽ mở một phiên debug <strong>thật</strong>: sample được thực thi bên trong một
          máy ảo (VM) mà <strong>bạn tự chuẩn bị</strong>, hoặc trực tiếp trên máy này nếu bạn chọn
          chế độ "chạy trực tiếp" ở bước sau. App chỉ kết nối tới{' '}
          <code className="mono">host:port</code> của <code className="mono">dbgsrv</code> bạn đã
          tự chạy sẵn (chế độ remote) — không tự khởi động VM, không tự copy sample vào, và không
          kiểm soát được cấu hình mạng của VM.
        </p>
        {risk && (
          <p className={`risk-callout risk-${risk.riskBucket}`}>
            {RISK_BUCKET_LABEL[risk.riskBucket] ?? risk.riskBucket} (điểm {risk.riskScore})
            {risk.likelyPacked ? ' — sample có thể bị pack' : ''}.
          </p>
        )}
        <ul>
          <li>Chế độ remote: đảm bảo VM đã cách ly mạng (host-only, không NAT ra Internet) — trách nhiệm của bạn.</li>
          <li>Chế độ remote: nên đã snapshot VM ở trạng thái sạch trước khi debug, để tự revert lại sau.</li>
          <li>Chế độ "chạy trực tiếp": app sẽ thực thi thẳng file bạn chỉ định, ngay trên máy này — chỉ dùng cho phần mềm bạn hoàn toàn tin cậy.</li>
        </ul>
        <p className="disclaimer">
          Xem <code className="mono">docs/dynamic-analysis-vm-setup.md</code> để biết cách chuẩn bị
          VM + dbgsrv.
        </p>
      </ConfirmDialog>
    );
  }

  if (mode === 'choose') {
    return (
      <ConfirmDialog
        open
        title="Chọn cách debug"
        confirmLabel="Remote (VM/máy khác)"
        cancelLabel="Hủy"
        onConfirm={() => setMode('remote')}
        onCancel={onClose}
      >
        <p>
          <strong>Remote</strong>: kết nối tới <code className="mono">dbgsrv</code> đang chạy ở một
          nơi khác (VM cách ly là lựa chọn đúng cho mẫu chưa xác định/nghi ngờ).
        </p>
        <p>
          <strong>Chạy trực tiếp trên máy này</strong>: app tự thực thi file bạn chỉ định, ngay trên
          máy đang chạy app — chỉ dùng cho phần mềm bạn tự tin cậy, không phải sample lạ.
        </p>
        <div className="chip-row" style={{ marginTop: 10 }}>
          <button type="button" onClick={() => setMode('local-warning')}>
            Chạy trực tiếp trên máy này
          </button>
        </div>
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
        cancelLabel="Quay lại"
        onConfirm={() => setMode('local-form')}
        onCancel={() => setMode('choose')}
      >
        <p>
          Ở chế độ này, app <strong>tự thực thi trực tiếp</strong> file bạn chỉ định ngay trên máy
          đang chạy app — <strong>không qua VM, không qua bất kỳ cách ly nào</strong>. Đây khác hẳn
          chế độ remote (app chỉ kết nối tới dbgsrv người dùng tự chạy).
        </p>
        <ul>
          <li>Chỉ dùng cho phần mềm <strong>bạn hoàn toàn tin cậy</strong> (vd. chính app bạn đang phát triển).</li>
          <li><strong>Không dùng</strong> cho mẫu chưa xác định, nghi ngờ, hoặc bất kỳ sample nào bạn không hoàn toàn chắc chắn — hãy dùng chế độ remote + VM cách ly cho những trường hợp đó.</li>
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

  if (mode === 'local-form') {
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

  // mode === 'remote'
  const parsedPort = Number.parseInt(port, 10);
  const canConnect =
    host.trim().length > 0 && Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort <= 65535;

  return (
    <ConfirmDialog
      open
      title="Kết nối tới dbgsrv"
      confirmLabel={connecting ? 'Đang kết nối...' : 'Kết nối'}
      confirmDisabled={!canConnect || connecting}
      cancelLabel="Quay lại"
      onConfirm={() =>
        onConnect(
          host.trim(),
          parsedPort,
          processId.trim() ? Number.parseInt(processId, 10) : null,
          processName.trim() || null,
        )
      }
      onCancel={() => setMode('choose')}
    >
      <p>
        Nhập <code className="mono">host:port</code> của <code className="mono">dbgsrv</code> đang
        chạy (trong VM bạn đã tự chuẩn bị, hoặc <code className="mono">127.0.0.1</code> nếu bạn tự
        chạy dbgsrv ngay trên máy này).
      </p>
      <label className="field">
        <span>Host</span>
        <input
          type="text"
          value={host}
          onChange={(event) => setHost(event.target.value)}
          placeholder="192.168.56.10"
        />
      </label>
      <label className="field">
        <span>Port</span>
        <input
          type="number"
          value={port}
          onChange={(event) => setPort(event.target.value)}
          placeholder="5005"
          min={1}
          max={65535}
        />
      </label>
      <label className="field">
        <span>Process ID (tùy chọn)</span>
        <input
          type="number"
          value={processId}
          onChange={(event) => setProcessId(event.target.value)}
          placeholder="để trống nếu dbgsrv đã attach sẵn"
        />
      </label>
      <label className="field">
        <span>Process name (tùy chọn)</span>
        <input
          type="text"
          value={processName}
          onChange={(event) => setProcessName(event.target.value)}
          placeholder="sample.exe"
        />
      </label>
      {connectError && <p className="disclaimer error-text">{connectError}</p>}
    </ConfirmDialog>
  );
}
