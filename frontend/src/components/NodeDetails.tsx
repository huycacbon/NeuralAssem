/**
 * Right panel. Renders one of three views depending on the selected node kind:
 * function, basic block, or API.
 */

import { useState } from 'react';

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
  const [codeView, setCodeView] = useState<'disasm' | 'pseudo'>('disasm');

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

  return (
    <>
      <div className="panel-section">
        <div className="detail-title">{detail?.name ?? node.label}</div>
        <dl className="kv" style={{ marginTop: 6 }}>
          <dt>Address</dt>
          <dd>{node.address ? displayAddress(node.address, rebaseDelta) : '-'}</dd>
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

      <div className="panel-section">
        <div className="code-view-header">
          <h4 style={{ margin: 0 }}>
            {codeView === 'disasm'
              ? `Disassembly${
                  disassembly && disasmBlocks.length > 0
                    ? ` (${disasmInstructionCount} instruction, ${disasmBlocks.length} block)`
                    : ''
                }`
              : 'Pseudocode (C)'}
          </h4>
          <div className="segmented small" role="group" aria-label="Kiểu hiển thị code">
            <button
              type="button"
              aria-pressed={codeView === 'disasm'}
              onClick={() => setCodeView('disasm')}
            >
              Disassembly
            </button>
            <button
              type="button"
              aria-pressed={codeView === 'pseudo'}
              onClick={() => setCodeView('pseudo')}
              title={!pseudoAvailable ? (pseudoNote ?? undefined) : undefined}
            >
              Pseudocode
            </button>
          </div>
        </div>

        {codeView === 'disasm' && (
          <>
            {loadingDisassembly && (
              <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>Đang tải...</p>
            )}

            {!loadingDisassembly && disasmBlocks.length > 0 && (
              <pre className="disasm disasm-full">
                {disasmBlocks.map((block) => {
                  const instructions: Instruction[] = block.metadata.instructions ?? [];
                  return (
                    <div key={block.id}>
                      <div className="disasm-block-header">
                        {displayAddress(block.address, rebaseDelta)}
                        {block.metadata.isFunctionStart ? ' · entry' : ''}
                      </div>
                      {instructions.length > 0 ? (
                        instructions.map((insn) => (
                          <div className="disasm-row" key={insn.address}>
                            <span className="a">{displayAddress(insn.address, rebaseDelta)}</span>
                            <span className="m">{insn.mnemonic}</span>
                            <span>{insn.operands}</span>
                          </div>
                        ))
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
                Danh sách block/instruction đã bị cắt bớt vì function quá lớn. Mở CFG để xem toàn
                bộ dưới dạng đồ thị.
              </p>
            )}
          </>
        )}

        {codeView === 'pseudo' && (
          <>
            {(pseudoWaiting || isDecompiling) && (
              <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>
                {isDecompiling
                  ? 'Đang decompile... (lần đầu cho function lớn có thể mất vài giây)'
                  : 'Đang tải...'}
              </p>
            )}

            {!pseudoWaiting && !isDecompiling && pseudoAvailable && (
              <pre className="disasm disasm-full pseudocode">{pseudocode}</pre>
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
              Pseudocode do angr Decompiler (heuristic) tự sinh ra - có thể khác với source thật,
              chỉ mang tính tham khảo khi đọc code, không phải kết quả decompile chính xác 100%.
            </p>
          </>
        )}
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
