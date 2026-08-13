/**
 * Bottom bar: shape/colour legend plus analysis status.
 *
 * The legend spells out shapes as well as colours because the graph encodes
 * node kind with both - colour alone is never load-bearing.
 */

import type { GraphType } from '@/types/graph';

interface GraphLegendProps {
  graphType: GraphType;
  statusText: string;
  visibleNodes: number;
  totalNodes: number;
  hiddenNodes: number;
}

export function GraphLegend({
  graphType,
  statusText,
  visibleNodes,
  totalNodes,
  hiddenNodes,
}: GraphLegendProps): JSX.Element {
  const isCfg = graphType === 'cfg';

  return (
    <footer className="statusbar">
      <div className="legend" aria-label="Chú giải">
        {isCfg ? (
          <>
            <span className="legend-item" style={{ color: 'var(--node-block)' }}>
              <span className="legend-swatch rect" /> Basic block (chữ nhật)
            </span>
            <span className="legend-item" style={{ color: 'var(--edge-true)' }}>
              <span className="legend-line" /> TRUE
            </span>
            <span className="legend-item" style={{ color: 'var(--edge-false)' }}>
              <span className="legend-line" /> FALSE
            </span>
            <span className="legend-item" style={{ color: 'var(--edge)' }}>
              <span className="legend-line" /> JUMP / FALLTHROUGH
            </span>
          </>
        ) : (
          <>
            <span className="legend-item" style={{ color: 'var(--node-function)' }}>
              <span className="legend-swatch circle" /> Function (tròn)
            </span>
            <span className="legend-item" style={{ color: 'var(--node-api)' }}>
              <span className="legend-swatch round-rect" /> API (chữ nhật bo góc)
            </span>
            <span className="legend-item" style={{ color: 'var(--node-function-entry)' }}>
              <span className="legend-swatch circle double" /> Entry point (viền kép)
            </span>
            <span className="legend-item" style={{ color: 'var(--risk-high)' }}>
              <span className="legend-swatch circle thick" /> Risk cao (viền dày)
            </span>
            <span className="legend-item" style={{ color: 'var(--edge-call)' }}>
              <span className="legend-line" /> CALL
            </span>
          </>
        )}
      </div>

      <div className="toolbar-spacer" />

      <span>
        {visibleNodes}/{totalNodes} node hiển thị
        {hiddenNodes > 0 ? ` · ${hiddenNodes} bị ẩn` : ''}
      </span>
      <span>{statusText}</span>
    </footer>
  );
}
