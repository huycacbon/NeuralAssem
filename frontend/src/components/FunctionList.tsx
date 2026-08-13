/**
 * Left panel: searchable function list.
 *
 * Click focuses the matching graph node; double-click opens the function's CFG.
 */

import { useMemo, useState } from 'react';

import type { FunctionSummary, RiskLevel } from '@/types/graph';
import { displayAddress } from '@/utils/addressDisplay';

function riskLevelOf(score: number): RiskLevel {
  if (score >= 20) return 'high';
  if (score >= 10) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

interface FunctionListProps {
  functions: FunctionSummary[];
  selectedAddress: string | null;
  loading: boolean;
  /** `moduleLoadBase - preferredImageBase` from the active debug session,
   *  or `null` when there is none - see `utils/addressDisplay.ts`. Display
   *  only: `fn.address` itself (used for selection/keys/API calls) stays a
   *  static address throughout. */
  rebaseDelta: number | null;
  onSelect: (fn: FunctionSummary) => void;
  onOpenCfg: (fn: FunctionSummary) => void;
}

export function FunctionList({
  functions,
  selectedAddress,
  loading,
  rebaseDelta,
  onSelect,
  onOpenCfg,
}: FunctionListProps): JSX.Element {
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return functions;
    const bare = needle.replace(/^0x/, '');
    return functions.filter(
      (fn) =>
        fn.name.toLowerCase().includes(needle) ||
        fn.address.toLowerCase().includes(needle) ||
        (bare.length >= 3 && fn.address.toLowerCase().includes(bare)) ||
        fn.importedApis.some((api) => api.toLowerCase().includes(needle)),
    );
  }, [functions, query]);

  return (
    <section className="panel fn-panel">
      <div className="panel-header">
        <span>Functions</span>
        <span className="count">
          {filtered.length}
          {filtered.length !== functions.length ? ` / ${functions.length}` : ''}
        </span>
      </div>

      <div className="fn-search">
        <input
          type="search"
          placeholder="Lọc theo tên, địa chỉ, API..."
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          aria-label="Lọc danh sách function"
        />
      </div>

      <div className="panel-body" role="listbox" aria-label="Danh sách function">
        {loading && <p className="empty-hint">Đang tải...</p>}

        {!loading && functions.length === 0 && (
          <p className="empty-hint">Chưa có dữ liệu. Upload một file PE để bắt đầu.</p>
        )}

        {!loading && functions.length > 0 && filtered.length === 0 && (
          <p className="empty-hint">Không có function nào khớp.</p>
        )}

        {filtered.map((fn) => (
          <button
            key={fn.address}
            type="button"
            className="fn-item"
            role="option"
            aria-selected={fn.address === selectedAddress}
            onClick={() => onSelect(fn)}
            onDoubleClick={() => onOpenCfg(fn)}
            title="Click: focus node · Double-click: mở CFG"
          >
            <div className="fn-item-top">
              <span className="fn-name">{fn.name}</span>
              <span className={`risk-badge risk-${riskLevelOf(fn.riskScore)}`}>
                {fn.riskScore}
              </span>
            </div>
            <div className="fn-meta">
              <span>{displayAddress(fn.address, rebaseDelta)}</span>
              <span>
                ↓{fn.callerCount} ↑{fn.calleeCount}
              </span>
              <span>{fn.blockCount} bb</span>
              {fn.isEntryPoint && <span className="entry-tag">ENTRY</span>}
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}
