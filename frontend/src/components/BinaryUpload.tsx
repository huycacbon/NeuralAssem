/**
 * File picker + progress indicator.
 *
 * The file is never read or executed here - it is handed straight to the
 * backend, which analyses it statically.
 */

import { useRef } from 'react';

import type { AnalysisStage } from '@/types/graph';

const STAGE_LABELS: Record<AnalysisStage, string> = {
  idle: '',
  uploading: 'Đang upload...',
  validating: 'Đang kiểm tra file...',
  loading_binary: 'Đang nạp binary...',
  building_cfg: 'Đang dựng CFG...',
  extracting_functions: 'Đang trích xuất function...',
  building_graph: 'Đang dựng graph...',
  completed: 'Hoàn tất',
  failed: 'Thất bại',
};

interface BinaryUploadProps {
  stage: AnalysisStage;
  uploadPercent: number;
  disabled: boolean;
  onFileSelected: (file: File) => void;
}

export function BinaryUpload({
  stage,
  uploadPercent,
  disabled,
  onFileSelected,
}: BinaryUploadProps): JSX.Element {
  const inputRef = useRef<HTMLInputElement>(null);

  const busy = stage !== 'idle' && stage !== 'completed' && stage !== 'failed';

  return (
    <div className="toolbar-group">
      <label className="upload-label">
        <input
          ref={inputRef}
          type="file"
          accept=".exe,.dll"
          disabled={disabled || busy}
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) onFileSelected(file);
            // Reset so re-picking the same file fires onChange again.
            event.target.value = '';
          }}
        />
        <button
          type="button"
          className="primary"
          disabled={disabled || busy}
          onClick={() => inputRef.current?.click()}
        >
          {busy ? 'Đang phân tích...' : 'Upload .exe / .dll'}
        </button>
      </label>

      {stage === 'uploading' && (
        <div className="progress-track" title={`${uploadPercent}%`}>
          <div className="progress-fill" style={{ width: `${uploadPercent}%` }} />
        </div>
      )}

      {stage !== 'idle' && (
        <span
          className={`stage-text ${stage === 'failed' ? 'failed' : ''} ${
            stage === 'completed' ? 'completed' : ''
          }`}
        >
          {STAGE_LABELS[stage]}
        </span>
      )}
    </div>
  );
}
