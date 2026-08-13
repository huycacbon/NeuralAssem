/** Top bar: graph type, layout, search, view controls. */

import { BinaryUpload } from '@/components/BinaryUpload';
import type { AnalysisStage, GraphType, LayoutName } from '@/types/graph';

interface GraphToolbarProps {
  stage: AnalysisStage;
  uploadPercent: number;
  analysisReady: boolean;
  graphType: GraphType;
  layout: LayoutName;
  search: string;
  showLabels: boolean;
  cfgAvailable: boolean;
  onFileSelected: (file: File) => void;
  onGraphTypeChange: (type: GraphType) => void;
  onLayoutChange: (layout: LayoutName) => void;
  onSearchChange: (value: string) => void;
  onToggleLabels: () => void;
  onFit: () => void;
  onResetView: () => void;
  onExport: () => void;
  /** True once a debug session is already open - relabels the button so the
   *  user knows clicking it reopens the live panel rather than starting over. */
  debugSessionActive: boolean;
  onDebugClick: () => void;
  /** Which view fills the centre column while debugging - only meaningful
   *  (and only rendered) once `debugSessionActive` is true; the graph is
   *  always shown outside a debug session. */
  debugViewMode: 'graph' | 'assembly';
  onDebugViewModeChange: (mode: 'graph' | 'assembly') => void;
}

export function GraphToolbar({
  stage,
  uploadPercent,
  analysisReady,
  graphType,
  layout,
  search,
  showLabels,
  cfgAvailable,
  onFileSelected,
  onGraphTypeChange,
  onLayoutChange,
  onSearchChange,
  onToggleLabels,
  onFit,
  onResetView,
  onExport,
  debugSessionActive,
  onDebugClick,
  debugViewMode,
  onDebugViewModeChange,
}: GraphToolbarProps): JSX.Element {
  return (
    <header className="toolbar">
      <span className="toolbar-brand">Binary Graph Analyzer</span>

      <BinaryUpload
        stage={stage}
        uploadPercent={uploadPercent}
        disabled={false}
        onFileSelected={onFileSelected}
      />

      <div className="toolbar-group">
        <label id="graph-type-label">Graph</label>
        <div className="segmented" role="group" aria-labelledby="graph-type-label">
          <button
            type="button"
            aria-pressed={graphType === 'call'}
            disabled={!analysisReady}
            onClick={() => onGraphTypeChange('call')}
          >
            Call Graph
          </button>
          <button
            type="button"
            aria-pressed={graphType === 'cfg'}
            // CFG has no meaning until a function has been opened.
            disabled={!analysisReady || !cfgAvailable}
            title={cfgAvailable ? undefined : 'Double-click một function để mở CFG'}
            onClick={() => onGraphTypeChange('cfg')}
          >
            Function CFG
          </button>
          <button
            type="button"
            aria-pressed={graphType === 'api'}
            disabled={!analysisReady}
            onClick={() => onGraphTypeChange('api')}
          >
            API Graph
          </button>
        </div>
      </div>

      <div className="toolbar-group">
        <label id="layout-label">Layout</label>
        <div className="segmented" role="group" aria-labelledby="layout-label">
          <button
            type="button"
            aria-pressed={layout === 'neural'}
            disabled={!analysisReady}
            onClick={() => onLayoutChange('neural')}
          >
            Neural Network
          </button>
          <button
            type="button"
            aria-pressed={layout === 'hierarchical'}
            disabled={!analysisReady}
            onClick={() => onLayoutChange('hierarchical')}
          >
            Hierarchical Flow
          </button>
        </div>
      </div>

      {debugSessionActive && (
        <div className="toolbar-group">
          <label id="debug-view-label">Xem</label>
          <div className="segmented" role="group" aria-labelledby="debug-view-label">
            <button
              type="button"
              aria-pressed={debugViewMode === 'assembly'}
              onClick={() => onDebugViewModeChange('assembly')}
              title="Assembly của function đang chạy, tự highlight dòng đang đứng"
            >
              Assembly
            </button>
            <button
              type="button"
              aria-pressed={debugViewMode === 'graph'}
              onClick={() => onDebugViewModeChange('graph')}
            >
              Đồ thị
            </button>
          </div>
        </div>
      )}

      <div className="toolbar-spacer" />

      <div className="toolbar-group">
        <input
          className="search-input"
          type="search"
          placeholder="Tìm function / API / địa chỉ..."
          value={search}
          disabled={!analysisReady}
          onChange={(event) => onSearchChange(event.target.value)}
          aria-label="Tìm kiếm trong graph"
        />
      </div>

      <div className="toolbar-group">
        <button type="button" disabled={!analysisReady} onClick={onFit}>
          Fit
        </button>
        <button type="button" disabled={!analysisReady} onClick={onResetView}>
          Reset view
        </button>
        <button
          type="button"
          className={showLabels ? 'toggled' : ''}
          aria-pressed={showLabels}
          disabled={!analysisReady}
          onClick={onToggleLabels}
        >
          {showLabels ? 'Ẩn label' : 'Hiện label'}
        </button>
        <button
          type="button"
          disabled={!analysisReady}
          onClick={onExport}
          title="Xuất báo cáo Markdown gọn — phù hợp dán vào AI hoặc gửi cho đồng nghiệp"
        >
          Xuất Markdown
        </button>
        <button
          type="button"
          className={debugSessionActive ? 'toggled' : ''}
          disabled={!analysisReady || debugSessionActive}
          onClick={onDebugClick}
          title="Mở phiên debug thật, kết nối tới dbgsrv trong một VM cách ly bạn tự chuẩn bị"
        >
          {debugSessionActive ? 'Debug (đang chạy)' : 'Debug'}
        </button>
      </div>
    </header>
  );
}
