/**
 * Right panel. Renders one of three views depending on the selected node kind:
 * function, basic block, or API.
 */

import { useEffect, useMemo, useRef, useState } from 'react';

import { useCopyMenu } from '@/components/CopyContextMenu';
import { DebugPanel } from '@/components/DebugPanel';
import { MemoryDumpPanel } from '@/components/MemoryDumpPanel';
import type { DebugSessionState, StepMode } from '@/types/debug';
import type {
  FunctionDetail,
  Graph,
  GraphNode,
  ImportedApi,
  Instruction,
  RiskLevel,
} from '@/types/graph';
import { displayAddress } from '@/utils/addressDisplay';

const RISK_DISCLAIMER =
  'Risk score là điểm heuristic để ưu tiên phân tích, không phải kết luận phát hiện mã độc.';

function riskLevelOf(score: number): RiskLevel {
  if (score >= 20) return 'high';
  if (score >= 10) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

/** CFG block addresses are hex strings ("0x401000"); sort blocks by value, not text. */
function parseHexAddress(address: string | null): number {
  if (!address) return 0;
  const parsed = Number.parseInt(address.replace(/^0x/i, ''), 16);
  return Number.isNaN(parsed) ? 0 : parsed;
}

interface NodeDetailsProps {
  node: GraphNode | null;
  /** `moduleLoadBase - preferredImageBase` from the active debug session, or
   *  `null` when there is none - see `utils/addressDisplay.ts`. Display
   *  only, applied everywhere an address is *shown* in this panel; every
   *  address used for lookups/API calls (onFocusAddress, onOpenCfg, ...)
   *  keeps using the original static value. */
  rebaseDelta: number | null;
  functionDetail: FunctionDetail | null;
  loadingDetail: boolean;
  /** Full CFG of the selected function (fetched via the CFG endpoint), used
   *  to render its disassembly inline without switching the active graph. */
  functionDisassembly: Graph | null;
  loadingDisassembly: boolean;
  imports: ImportedApi[];
  /** address -> name, so API callers can be shown by name. */
  functionNames: Map<string, string>;
  /** True while a decompile-on-demand request for the *selected* function is in flight. */
  isDecompiling: boolean;
  onOpenCfg: (address: string) => void;
  onExpand: (address: string) => void;
  onFocusAddress: (address: string) => void;
  onFilterByApi: (nodeId: string) => void;
  onDecompile: (address: string) => void;
  /** Live debug session, if one is open - rendered as its own section,
   *  independent of the selected node's kind (see DebugPanel.tsx). */
  debugSession: DebugSessionState | null;
  debugLoading: boolean;
  debugError: string | null;
  onDebugStep: (mode: StepMode) => void;
  onDebugContinue: () => void;
  onDebugDisconnect: () => void;
  onDebugSetBreakpoint: (staticAddress: string) => void;
  onDebugRemoveBreakpoint: (breakpointId: number) => void;
  onDebugSetRegister: (name: string, value: string) => void;
}

function FunctionView({
  node,
  rebaseDelta,
  detail,
  loading,
  disassembly,
  loadingDisassembly,
  isDecompiling,
  onOpenCfg,
  onExpand,
  onFocusAddress,
  onDecompile,
}: {
  node: GraphNode;
  rebaseDelta: number | null;
  detail: FunctionDetail | null;
  loading: boolean;
  disassembly: Graph | null;
  loadingDisassembly: boolean;
  isDecompiling: boolean;
  onOpenCfg: (address: string) => void;
  onExpand: (address: string) => void;
  onFocusAddress: (address: string) => void;
  onDecompile: (address: string) => void;
}): JSX.Element {
  const { openCopyMenu } = useCopyMenu();
  // -- Disassembly <-> Pseudocode sync (IDA-style dual pane: both boxes are
  // always visible, never a toggle between the two - hovering a row/line in
  // one instantly highlights its counterpart in the other, no click needed)
  // - built on `detail.pseudocodeAddressLines` (address -> pseudocode line
  // number, from angr's own decompiler internals - see
  // `angr_analyzer._pseudocode_address_lines`).
  const addressToLine = detail?.pseudocodeAddressLines ?? null;
  // Reverse of `addressToLine` - one pseudocode line can decompile from
  // several instructions (e.g. a multi-instruction comparison folded into one
  // `if`), so this is address*es* plural.
  const lineToAddresses = useMemo(() => {
    const map = new Map<number, string[]>();
    if (!addressToLine) return map;
    for (const [address, line] of Object.entries(addressToLine)) {
      const list = map.get(line) ?? [];
      list.push(address);
      map.set(line, list);
    }
    for (const list of map.values()) list.sort();
    return map;
  }, [addressToLine]);
  const pseudoLineRefs = useRef<Map<number, HTMLDivElement>>(new Map());
  const disasmRowRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  // Exactly one of these is non-null at a time in practice (the mouse is
  // only ever over one box), but they're independent state so each box only
  // ever has to know about its own hover, not the other's.
  const [hoveredAddress, setHoveredAddress] = useState<string | null>(null); // hovering a disasm row
  const [hoveredLine, setHoveredLine] = useState<number | null>(null); // hovering a pseudo line

  const highlightedPseudoLine =
    hoveredAddress !== null ? (addressToLine?.[hoveredAddress] ?? null) : null;
  const highlightedDisasmAddresses =
    hoveredLine !== null ? (lineToAddresses.get(hoveredLine) ?? []) : [];

  // Keeps the synced spot in the *other* box visible while hovering, without
  // fighting the user's own scroll position - `block: 'nearest'` only moves
  // it if it's not already on screen (unlike Ctrl+G's jump-to-center in
  // AssemblyView, which is a deliberate one-shot action; a continuous hover
  // effect re-centering on every mouse move would be disorienting).
  useEffect(() => {
    if (highlightedPseudoLine !== null) {
      pseudoLineRefs.current.get(highlightedPseudoLine)?.scrollIntoView({ block: 'nearest' });
    }
  }, [highlightedPseudoLine]);
  const firstHighlightedDisasmAddress = highlightedDisasmAddresses[0] ?? null;
  useEffect(() => {
    if (firstHighlightedDisasmAddress !== null) {
      disasmRowRefs.current.get(firstHighlightedDisasmAddress)?.scrollIntoView({ block: 'nearest' });
    }
  }, [firstHighlightedDisasmAddress]);

  const score = detail?.riskScore ?? node.metadata.riskScore ?? 0;
  const reasons = detail?.riskReasons ?? [];
  const apis = detail?.importedApis ?? [];
  const strings = detail?.strings ?? [];
  const blocks = detail?.blockAddresses ?? [];

  const disasmBlocks = [...(disassembly?.nodes ?? [])].sort(
    (a, b) => parseHexAddress(a.address) - parseHexAddress(b.address),
  );
  const disasmTruncated = disassembly?.metadata.truncated ?? false;
  const disasmInstructionCount = disassembly?.metadata.instructionCount ?? 0;

  const pseudocode = detail?.pseudocode ?? null;
  const pseudoStatus = detail?.pseudocodeStatus ?? 'not_attempted';
  const pseudoNote = detail?.pseudocodeNote ?? null;
  const pseudoAvailable = pseudoStatus === 'available' && Boolean(pseudocode);
  const pseudoWaiting = loading && !detail;
  const pseudocodeLines = pseudocode ? pseudocode.split('\n') : [];

  // Repopulated fresh by each row/line's own ref callback below on every
  // render - stale entries from a previous function must not linger
  // (mirrors AssemblyView.tsx's `rowRefs` for the same reason).
  disasmRowRefs.current.clear();
  pseudoLineRefs.current.clear();

  return (
    <>
      <div className="panel-section">
        <div
          className="detail-title"
          onContextMenu={(event) =>
            openCopyMenu(event, [{ label: 'tên hàm', value: detail?.name ?? node.label }])
          }
        >
          {detail?.name ?? node.label}
        </div>
        <dl className="kv" style={{ marginTop: 6 }}>
          <dt>Address</dt>
          <dd
            onContextMenu={(event) =>
              node.address &&
              openCopyMenu(event, [
                { label: 'địa chỉ', value: displayAddress(node.address, rebaseDelta) },
              ])
            }
          >
            {node.address ? displayAddress(node.address, rebaseDelta) : '-'}
          </dd>
          <dt>Size</dt>
          <dd>{detail?.size != null ? `${detail.size} bytes` : '-'}</dd>
          <dt>Basic blocks</dt>
          <dd>{detail?.blockCount ?? node.metadata.blockCount ?? 0}</dd>
          <dt>Callers</dt>
          <dd>{detail?.callerCount ?? node.metadata.callerCount ?? 0}</dd>
          <dt>Callees</dt>
          <dd>{detail?.calleeCount ?? node.metadata.calleeCount ?? 0}</dd>
          <dt>Entry point</dt>
          <dd>{node.metadata.isEntryPoint ? 'có' : 'không'}</dd>
        </dl>

        <div className="chip-row" style={{ marginTop: 8 }}>
          {node.address && (
            <button type="button" onClick={() => onOpenCfg(node.address as string)}>
              Mở CFG
            </button>
          )}
          {node.address && (
            <button type="button" onClick={() => onExpand(node.address as string)}>
              Expand 1 hop
            </button>
          )}
        </div>
      </div>

      {/* Disassembly and Pseudocode are two separate, always-visible boxes -
          not a toggle between them - so hovering a row/line in one can
          highlight its counterpart in the other at the same time (see the
          hover state/effects above). */}
      <div className="panel-section">
        <div className="code-view-header">
          <h4 style={{ margin: 0 }}>
            Disassembly
            {disassembly && disasmBlocks.length > 0
              ? ` (${disasmInstructionCount} instruction, ${disasmBlocks.length} block)`
              : ''}
          </h4>
        </div>

        {loadingDisassembly && (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>Đang tải...</p>
        )}

        {!loadingDisassembly && disasmBlocks.length > 0 && (
          <pre className="disasm disasm-split">
            {disasmBlocks.map((block) => {
              const instructions: Instruction[] = block.metadata.instructions ?? [];
              return (
                <div key={block.id}>
                  <div
                    className="disasm-block-header"
                    onContextMenu={(event) =>
                      openCopyMenu(event, [
                        { label: 'địa chỉ block', value: displayAddress(block.address, rebaseDelta) },
                      ])
                    }
                  >
                    {displayAddress(block.address, rebaseDelta)}
                    {block.metadata.isFunctionStart ? ' · entry' : ''}
                  </div>
                  {instructions.length > 0 ? (
                    instructions.map((insn) => {
                      const pseudoLine = addressToLine?.[insn.address] ?? null;
                      const isSynced = pseudoLine !== null;
                      const isHighlighted = highlightedDisasmAddresses.includes(insn.address);
                      const shownAddress = displayAddress(insn.address, rebaseDelta);
                      return (
                        <div
                          key={insn.address}
                          ref={(el) => {
                            if (el) disasmRowRefs.current.set(insn.address, el);
                          }}
                          className={`disasm-row${isSynced ? ' sync-available' : ''}${isHighlighted ? ' sync-hover' : ''}`}
                          title={
                            isSynced
                              ? 'Có dòng pseudocode tương ứng · Chuột phải để copy'
                              : 'Chuột phải để copy'
                          }
                          onMouseEnter={isSynced ? () => setHoveredAddress(insn.address) : undefined}
                          onMouseLeave={isSynced ? () => setHoveredAddress(null) : undefined}
                          onContextMenu={(event) =>
                            openCopyMenu(event, [
                              { label: 'địa chỉ', value: shownAddress },
                              {
                                label: 'dòng lệnh',
                                value: `${shownAddress}  ${insn.mnemonic} ${insn.operands}`.trim(),
                              },
                            ])
                          }
                        >
                          <span className="a">{shownAddress}</span>
                          <span className="m">{insn.mnemonic}</span>
                          <span>{insn.operands}</span>
                        </div>
                      );
                    })
                  ) : (
                    <div className="disasm-row">
                      <span className="a" />
                      <span style={{ color: 'var(--text-faint)' }}>
                        (angr không disassemble được block này)
                      </span>
                      <span />
                    </div>
                  )}
                </div>
              );
            })}
          </pre>
        )}

        {!loadingDisassembly && disassembly && disasmBlocks.length === 0 && (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>
            Function này không có basic block nào (thường là import thunk hoặc stub).
          </p>
        )}

        {disasmTruncated && (
          <p className="disclaimer" style={{ marginTop: 6 }}>
            Danh sách block/instruction đã bị cắt bớt vì function quá lớn. Mở CFG để xem toàn bộ
            dưới dạng đồ thị.
          </p>
        )}
      </div>

      <div className="panel-section">
        <div className="code-view-header">
          <h4 style={{ margin: 0 }}>Pseudocode (C)</h4>
        </div>

        {(pseudoWaiting || isDecompiling) && (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>
            {isDecompiling
              ? 'Đang decompile... (lần đầu cho function lớn có thể mất vài giây)'
              : 'Đang tải...'}
          </p>
        )}

        {!pseudoWaiting && !isDecompiling && pseudoAvailable && (
          <pre className="disasm disasm-split pseudocode">
            {pseudocodeLines.map((text, index) => {
              const lineNumber = index + 1;
              const addresses = lineToAddresses.get(lineNumber);
              const isSynced = Boolean(addresses && addresses.length > 0);
              const isHighlighted = highlightedPseudoLine === lineNumber;
              return (
                <div
                  key={lineNumber}
                  ref={(el) => {
                    if (el) pseudoLineRefs.current.set(lineNumber, el);
                  }}
                  className={`pseudo-line${isSynced ? ' sync-available' : ''}${isHighlighted ? ' sync-hover' : ''}`}
                  title={
                    isSynced
                      ? 'Có dòng disassembly tương ứng · Chuột phải để copy'
                      : 'Chuột phải để copy'
                  }
                  onMouseEnter={isSynced ? () => setHoveredLine(lineNumber) : undefined}
                  onMouseLeave={isSynced ? () => setHoveredLine(null) : undefined}
                  onContextMenu={(event) =>
                    openCopyMenu(event, [{ label: 'dòng pseudocode', value: text }])
                  }
                >
                  {text || ' '}
                </div>
              );
            })}
          </pre>
        )}

        {!pseudoWaiting && !isDecompiling && !pseudoAvailable && (
          <>
            <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>
              {pseudoNote ?? 'Function này chưa được decompile.'}
            </p>
            {pseudoStatus !== 'not_applicable' && node.address && (
              <button
                type="button"
                style={{ marginTop: 8 }}
                onClick={() => onDecompile(node.address as string)}
              >
                Decompile hàm này
              </button>
            )}
          </>
        )}

        <p className="disclaimer" style={{ marginTop: 8 }}>
          Pseudocode do angr Decompiler (heuristic) tự sinh ra - có thể khác với source thật, chỉ
          mang tính tham khảo khi đọc code, không phải kết quả decompile chính xác 100%.
        </p>
      </div>

      <div className="panel-section">
        <h4>Risk score</h4>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
          <span className={`risk-badge risk-${riskLevelOf(score)}`} style={{ fontSize: 14 }}>
            {score}
          </span>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            mức {riskLevelOf(score)}
          </span>
        </div>
        {reasons.length > 0 ? (
          <ul className="reason-list">
            {reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        ) : (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>
            Không có tín hiệu heuristic nào.
          </p>
        )}
        <p className="disclaimer" style={{ marginTop: 8 }}>
          {RISK_DISCLAIMER}
        </p>
      </div>

      <div className="panel-section">
        <h4>API được gọi ({apis.length})</h4>
        {apis.length > 0 ? (
          <div className="chip-row">
            {apis.map((api) => (
              <span key={api} className="chip api">
                {api}
              </span>
            ))}
          </div>
        ) : (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>
            {loading ? 'Đang tải...' : 'Không gọi imported API nào.'}
          </p>
        )}
      </div>

      <div className="panel-section">
        <h4>Strings tham chiếu ({strings.length})</h4>
        {strings.length > 0 ? (
          <ul className="string-list">
            {strings.map((item) => (
              <li key={`${item.address}-${item.value}`}>
                <span className="addr">{item.address || '-'}</span>
                <span className="val">{item.value}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>
            Không xác định được string nào.
          </p>
        )}
      </div>

      <div className="panel-section">
        <h4>Basic blocks ({blocks.length})</h4>
        {blocks.length > 0 ? (
          <div className="address-links">
            {blocks.slice(0, 200).map((address) => (
              <button key={address} type="button" onClick={() => onFocusAddress(address)}>
                {displayAddress(address, rebaseDelta)}
              </button>
            ))}
          </div>
        ) : (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>
            Chưa có dữ liệu block.
          </p>
        )}
      </div>
    </>
  );
}

function BlockView({
  node,
  rebaseDelta,
}: {
  node: GraphNode;
  rebaseDelta: number | null;
}): JSX.Element {
  const instructions: Instruction[] = node.metadata.instructions ?? [];
  const callTargets = node.metadata.callTargets ?? [];

  return (
    <>
      <div className="panel-section">
        <div className="detail-title">
          Basic block {displayAddress(node.address, rebaseDelta)}
        </div>
        <dl className="kv" style={{ marginTop: 6 }}>
          <dt>Address</dt>
          <dd>{node.address ? displayAddress(node.address, rebaseDelta) : '-'}</dd>
          <dt>Size</dt>
          <dd>{node.metadata.size ?? 0} bytes</dd>
          <dt>Instructions</dt>
          <dd>{node.metadata.instructionCount ?? instructions.length}</dd>
          <dt>Successors</dt>
          <dd>{node.metadata.successorCount ?? 0}</dd>
          <dt>Predecessors</dt>
          <dd>{node.metadata.predecessorCount ?? 0}</dd>
          <dt>Function start</dt>
          <dd>{node.metadata.isFunctionStart ? 'có' : 'không'}</dd>
        </dl>
      </div>

      {callTargets.length > 0 && (
        <div className="panel-section">
          <h4>Call targets</h4>
          <div className="chip-row">
            {callTargets.map((target) => (
              <span key={target} className="chip api">
                {target.replace(/^api_/, '')}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="panel-section">
        <h4>Disassembly</h4>
        {instructions.length > 0 ? (
          <pre className="disasm">
            {instructions.map((insn) => (
              <div className="disasm-row" key={insn.address}>
                <span className="a">{displayAddress(insn.address, rebaseDelta)}</span>
                <span className="m">{insn.mnemonic}</span>
                <span>{insn.operands}</span>
              </div>
            ))}
          </pre>
        ) : (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>
            angr không disassemble được block này.
          </p>
        )}
        {node.metadata.truncated && (
          <p className="disclaimer" style={{ marginTop: 6 }}>
            Danh sách instruction đã bị cắt bớt vì block quá dài.
          </p>
        )}
      </div>
    </>
  );
}

function ApiView({
  node,
  rebaseDelta,
  imports,
  functionNames,
  onFocusAddress,
  onFilterByApi,
}: {
  node: GraphNode;
  rebaseDelta: number | null;
  imports: ImportedApi[];
  functionNames: Map<string, string>;
  onFocusAddress: (address: string) => void;
  onFilterByApi: (nodeId: string) => void;
}): JSX.Element {
  const entry = imports.find((item) => item.nodeId === node.id);
  const callers = entry?.callers ?? [];

  return (
    <>
      <div className="panel-section">
        <div className="detail-title">{entry?.name ?? node.label}</div>
        <dl className="kv" style={{ marginTop: 6 }}>
          <dt>DLL</dt>
          <dd>{entry?.module ?? node.metadata.module ?? '-'}</dd>
          <dt>IAT address</dt>
          <dd>{displayAddress(entry?.address ?? node.address, rebaseDelta) || '-'}</dd>
          <dt>References</dt>
          <dd>{entry?.referenceCount ?? node.metadata.referenceCount ?? 0}</dd>
          <dt>Capability</dt>
          <dd>{entry?.capability ?? node.metadata.capability ?? 'other'}</dd>
          <dt>Risk weight</dt>
          <dd>{node.metadata.riskScore ?? 0}</dd>
        </dl>
        <div className="chip-row" style={{ marginTop: 8 }}>
          <button type="button" onClick={() => onFilterByApi(node.id)}>
            Chỉ hiện function gọi API này
          </button>
        </div>
        <p className="disclaimer" style={{ marginTop: 8 }}>
          {RISK_DISCLAIMER}
        </p>
      </div>

      <div className="panel-section">
        <h4>Function gọi đến ({callers.length})</h4>
        {callers.length > 0 ? (
          <div className="address-links">
            {callers.map((address) => (
              <button key={address} type="button" onClick={() => onFocusAddress(address)}>
                {functionNames.get(address) ?? displayAddress(address, rebaseDelta)}
              </button>
            ))}
          </div>
        ) : (
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>
            Không xác định được function nào gọi API này (có thể là indirect call).
          </p>
        )}
      </div>
    </>
  );
}

export function NodeDetails({
  node,
  rebaseDelta,
  functionDetail,
  loadingDetail,
  functionDisassembly,
  loadingDisassembly,
  imports,
  functionNames,
  isDecompiling,
  onOpenCfg,
  onExpand,
  onFocusAddress,
  onFilterByApi,
  onDecompile,
  debugSession,
  debugLoading,
  debugError,
  onDebugStep,
  onDebugContinue,
  onDebugDisconnect,
  onDebugSetBreakpoint,
  onDebugRemoveBreakpoint,
  onDebugSetRegister,
}: NodeDetailsProps): JSX.Element {
  return (
    <aside className="panel panel-right">
      <div className="panel-header">
        <span>Chi tiết</span>
        {node && <span className="count">{node.kind}</span>}
      </div>

      <div className="panel-body">
        {debugSession && (
          <DebugPanel
            session={debugSession}
            loading={debugLoading}
            error={debugError}
            selectedNodeAddress={node?.address ?? null}
            onStepInto={() => onDebugStep('into')}
            onStepOver={() => onDebugStep('over')}
            onContinue={onDebugContinue}
            onDisconnect={onDebugDisconnect}
            onSetBreakpoint={onDebugSetBreakpoint}
            onRemoveBreakpoint={onDebugRemoveBreakpoint}
            onSetRegister={onDebugSetRegister}
            onFocusStaticAddress={onFocusAddress}
          />
        )}

        {debugSession && (
          <MemoryDumpPanel
            sessionId={debugSession.sessionId}
            disabled={debugLoading}
            defaultAddress={debugSession.runtimeAddress}
          />
        )}

        {!node && (
          <p className="empty-hint">
            Chọn một node trên graph hoặc một function ở panel trái để xem chi tiết.
          </p>
        )}

        {node?.kind === 'function' && (
          <FunctionView
            node={node}
            rebaseDelta={rebaseDelta}
            detail={functionDetail}
            loading={loadingDetail}
            disassembly={functionDisassembly}
            loadingDisassembly={loadingDisassembly}
            isDecompiling={isDecompiling}
            onOpenCfg={onOpenCfg}
            onExpand={onExpand}
            onFocusAddress={onFocusAddress}
            onDecompile={onDecompile}
          />
        )}

        {node?.kind === 'basic_block' && <BlockView node={node} rebaseDelta={rebaseDelta} />}

        {node?.kind === 'api' && (
          <ApiView
            node={node}
            rebaseDelta={rebaseDelta}
            imports={imports}
            functionNames={functionNames}
            onFocusAddress={onFocusAddress}
            onFilterByApi={onFilterByApi}
          />
        )}
      </div>
    </aside>
  );
}
