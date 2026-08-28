/**
 * Summary + filter controls, rendered at the top of the left panel.
 *
 * Filters change what is *displayed*; the loaded graph data is never mutated.
 */

import { useCopyMenu } from '@/components/CopyContextMenu';
import type { AnalysisResponse, GraphNode, GraphType } from '@/types/graph';
import type { GraphFilters } from '@/hooks/useGraphFilters';
import { toX64dbgExpression } from '@/utils/x64dbgExpression';

interface AnalysisSummaryProps {
  analysis: AnalysisResponse | null;
  graphType: GraphType;
  filters: GraphFilters;
  availableApis: GraphNode[];
  isFiltered: boolean;
  hiddenCount: number;
  depth: number;
  maxNodes: number;
  onFilterChange: <K extends keyof GraphFilters>(key: K, value: GraphFilters[K]) => void;
  onResetFilters: () => void;
  onUnhideAll: () => void;
  onDepthChange: (depth: number) => void;
  onMaxNodesChange: (maxNodes: number) => void;
}

function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(2)} MB`;
}

export function AnalysisSummary({
  analysis,
  graphType,
  filters,
  availableApis,
  isFiltered,
  hiddenCount,
  depth,
  maxNodes,
  onFilterChange,
  onResetFilters,
  onUnhideAll,
  onDepthChange,
  onMaxNodesChange,
}: AnalysisSummaryProps): JSX.Element | null {
  const { openCopyMenu } = useCopyMenu();

  if (!analysis) return null;

  const { file, summary } = analysis;
  const isCallGraph = graphType === 'call';

  return (
    <>
      <div className="panel-section">
        <h4>File</h4>
        <dl className="kv">
          <dt>Tên</dt>
          <dd>{file.name}</dd>
          <dt>Kích thước</dt>
          <dd>{formatBytes(file.size)}</dd>
          <dt>Kiến trúc</dt>
          <dd>
            {file.architecture} ({file.bits}-bit)
          </dd>
          <dt>Entry point</dt>
          <dd
            onContextMenu={(event) => {
              const items = [{ label: 'entry point', value: file.entryPoint }];
              const x64dbgExpr = toX64dbgExpression(file.entryPoint, file.imageBase, file.name);
              if (x64dbgExpr) items.push({ label: 'dạng x64dbg (module+offset)', value: x64dbgExpr });
              openCopyMenu(event, items);
            }}
          >
            {file.entryPoint}
          </dd>
          <dt>Image base</dt>
          <dd
            title="Base mặc định (preferred ImageBase) trong PE header - mọi địa chỉ 'static' trong app đều tính theo base này, không đổi giữa các lần chạy (khác với ASLR runtime base). Trừ địa chỉ static cho giá trị này để ra offset dùng được với x64dbg (module+offset)."
            onContextMenu={(event) =>
              openCopyMenu(event, [{ label: 'image base', value: file.imageBase }])
            }
          >
            {file.imageBase}
          </dd>
          <dt>SHA-256</dt>
          <dd style={{ fontSize: 10.5 }}>{file.sha256}</dd>
        </dl>
        <p className="disclaimer" style={{ marginTop: 6 }}>
          Địa chỉ hiển thị trong app (Function List, đồ thị, CFG) là <strong>static</strong>, tính
          theo Image base ở trên — không đổi giữa các lần chạy. x64dbg (chạy độc lập) sẽ có base
          ngẫu nhiên khác (ASLR) mỗi lần launch, nên đừng so trực tiếp địa chỉ tuyệt đối. Chuột phải
          vào một địa chỉ để copy dạng <code>module+offset</code> — dán thẳng vào ô "Go to
          Expression" (Ctrl+G) của x64dbg.
        </p>
      </div>

      <div className="panel-section">
        <h4>Tổng quan</h4>
        <div className="summary-grid">
          <div className="summary-cell">
            <span className="n">{summary.functionCount}</span>
            <span className="k">Functions</span>
          </div>
          <div className="summary-cell">
            <span className="n">{summary.basicBlockCount}</span>
            <span className="k">Basic blocks</span>
          </div>
          <div className="summary-cell">
            <span className="n">{summary.importCount}</span>
            <span className="k">Imports</span>
          </div>
          <div className="summary-cell">
            <span className="n">{summary.stringCount}</span>
            <span className="k">Strings</span>
          </div>
        </div>
        <p style={{ margin: '6px 0 0', fontSize: 11.5, color: 'var(--text-faint)' }}>
          Phân tích trong {summary.analysisDurationSeconds.toFixed(1)}s
        </p>
      </div>

      <div className="panel-section">
        <h4>Bộ lọc</h4>

        <div className="filter-row">
          <label htmlFor="filter-risk">Risk score tối thiểu</label>
          <input
            id="filter-risk"
            type="number"
            min={0}
            max={100}
            step={1}
            value={filters.minRiskScore}
            onChange={(event) =>
              onFilterChange('minRiskScore', Math.max(0, Number(event.target.value) || 0))
            }
          />
        </div>

        {isCallGraph && (
          <>
            <div className="filter-row">
              <label htmlFor="filter-depth">Độ sâu từ entry (server)</label>
              <select
                id="filter-depth"
                value={depth}
                onChange={(event) => onDepthChange(Number(event.target.value))}
              >
                {[1, 2, 3, 4, 5].map((value) => (
                  <option key={value} value={value}>
                    {value} hop
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-row">
              <label htmlFor="filter-hops">Giới hạn hop (client)</label>
              <select
                id="filter-hops"
                value={filters.maxHops}
                onChange={(event) => onFilterChange('maxHops', Number(event.target.value))}
              >
                {[1, 2, 3, 4, 5].map((value) => (
                  <option key={value} value={value}>
                    {value === 5 ? 'không giới hạn' : `${value} hop`}
                  </option>
                ))}
              </select>
            </div>

            <div className="filter-row">
              <label htmlFor="filter-maxnodes">Số node tối đa</label>
              <select
                id="filter-maxnodes"
                value={maxNodes}
                onChange={(event) => onMaxNodesChange(Number(event.target.value))}
              >
                {[100, 250, 500, 1000, 2000].map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </div>
          </>
        )}

        <div className="filter-row">
          <label>
            <input
              type="checkbox"
              checked={filters.hideApis}
              onChange={(event) => onFilterChange('hideApis', event.target.checked)}
            />
            Ẩn imported API
          </label>
        </div>

        <div className="filter-row">
          <label>
            <input
              type="checkbox"
              checked={filters.hideUnnamed}
              onChange={(event) => onFilterChange('hideUnnamed', event.target.checked)}
            />
            Ẩn function không có tên
          </label>
        </div>

        <div className="filter-row">
          <label>
            <input
              type="checkbox"
              checked={filters.onlyWithStrings}
              onChange={(event) => onFilterChange('onlyWithStrings', event.target.checked)}
            />
            Chỉ function có string
          </label>
        </div>

        {availableApis.length > 0 && (
          <div className="filter-row">
            <label htmlFor="filter-api">Chỉ function gọi API</label>
            <select
              id="filter-api"
              value={filters.apiFilter ?? ''}
              onChange={(event) =>
                onFilterChange('apiFilter', event.target.value === '' ? null : event.target.value)
              }
            >
              <option value="">— tất cả —</option>
              {availableApis.map((api) => (
                <option key={api.id} value={api.id}>
                  {api.label}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="chip-row" style={{ marginTop: 8 }}>
          <button type="button" disabled={!isFiltered} onClick={onResetFilters}>
            Xóa bộ lọc
          </button>
          <button type="button" disabled={hiddenCount === 0} onClick={onUnhideAll}>
            Hiện lại node đã ẩn
          </button>
        </div>
      </div>

      {summary.highestRiskFunctions.length > 0 && (
        <div className="panel-section">
          <h4>Risk score cao nhất</h4>
          <ul className="plain-list">
            {summary.highestRiskFunctions.slice(0, 5).map((fn) => (
              <li key={fn.address}>
                <span className="mono">{fn.name}</span> — {fn.riskScore}
              </li>
            ))}
          </ul>
          <p className="disclaimer" style={{ marginTop: 6 }}>
            Risk score là điểm heuristic để ưu tiên phân tích, không phải kết luận phát hiện
            mã độc.
          </p>
        </div>
      )}
    </>
  );
}
