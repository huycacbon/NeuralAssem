/**
 * Full-size assembly listing shown in place of the graph while a debug
 * session is active - flattens the enclosing function's CFG blocks (already
 * fetched with `instructions`, see `analysisApi.getFunctionCfg`) into one
 * linear, address-sorted listing, highlights the row the debugger is
 * currently stopped at, and auto-scrolls it into view on every step.
 *
 * Deliberately a sibling of `GraphViewer`, not a mode inside it - Cytoscape
 * has no notion of a linear instruction list, so reusing that component
 * would mean smuggling a second rendering model through its props. `App.tsx`
 * swaps between the two at the `graph-column` level instead.
 *
 * Two data sources, never both at once:
 * - `graph` (static): the CFG of whatever function contains the debugger's
 *   PC, when the PC is inside the one module the static analyzer covers.
 *   Rows can toggle breakpoints (a *static* address the backend rebases).
 * - `liveDisassembly` (fallback): when the PC is somewhere the static graph
 *   never covered (system DLLs, most commonly - see
 *   `backend/app/dynamic/session.py`'s `disassemble_current` docstring),
 *   disassembled live from the process's own bytes instead. Read-only - a
 *   *runtime* address is not something the existing breakpoint API can
 *   accept (it always rebases via the static coordinate space), so these
 *   rows never show the breakpoint gutter.
 */

import { useEffect, useMemo, useRef } from 'react';

import type { DebugBreakpoint, DebugSessionStatus, LiveDisassemblyResponse } from '@/types/debug';
import type { Graph, Instruction } from '@/types/graph';
import { displayAddress } from '@/utils/addressDisplay';

interface FlatInstruction {
  address: string;
  mnemonic: string;
  operands: string;
  numericAddress: number | null;
  isBlockStart: boolean;
  isFunctionStart: boolean;
  blockLabel: string;
}

function parseHexAddress(address: string | null | undefined): number | null {
  if (!address) return null;
  const parsed = Number.parseInt(address.replace(/^0x/i, ''), 16);
  return Number.isNaN(parsed) ? null : parsed;
}

interface AssemblyViewProps {
  /** CFG of the function currently containing the debugger's PC - `null`
   *  while it is still loading or no such function could be resolved. */
  graph: Graph | null;
  loadingGraph: boolean;
  /** Live-disassembled fallback around the current runtime address, used
   *  only once `graph` has settled and come up empty. */
  liveDisassembly: LiveDisassemblyResponse | null;
  loadingLive: boolean;
  status: DebugSessionStatus;
  /** Static-space PC, matched against `graph`'s instruction addresses. */
  executingAddress: number | null;
  /** Runtime-space PC, matched against `liveDisassembly`'s addresses. */
  executingRuntimeAddress: number | null;
  /** `moduleLoadBase - preferredImageBase` from the active debug session, or
   *  `null` when there is none - see `utils/addressDisplay.ts`. Applied to
   *  the static (`graph`) branch's displayed addresses only - the live
   *  branch's addresses are already runtime, nothing to rebase there.
   *  Breakpoint calls always use the original static address regardless. */
  rebaseDelta: number | null;
  breakpoints: DebugBreakpoint[];
  breakpointsDisabled: boolean;
  onToggleBreakpoint: (staticAddress: string) => void;
}

export function AssemblyView({
  graph,
  loadingGraph,
  liveDisassembly,
  loadingLive,
  status,
  executingAddress,
  executingRuntimeAddress,
  rebaseDelta,
  breakpoints,
  breakpointsDisabled,
  onToggleBreakpoint,
}: AssemblyViewProps): JSX.Element {
  const activeRowRef = useRef<HTMLDivElement | null>(null);

  const staticInstructions = useMemo<FlatInstruction[]>(() => {
    if (!graph) return [];
    const blocks = [...graph.nodes]
      .filter((node) => node.kind === 'basic_block')
      .sort((a, b) => (parseHexAddress(a.address) ?? 0) - (parseHexAddress(b.address) ?? 0));

    const flat: FlatInstruction[] = [];
    for (const block of blocks) {
      const blockInstructions: Instruction[] = block.metadata.instructions ?? [];
      blockInstructions.forEach((insn, index) => {
        flat.push({
          address: insn.address,
          mnemonic: insn.mnemonic,
          operands: insn.operands,
          numericAddress: parseHexAddress(insn.address),
          isBlockStart: index === 0,
          isFunctionStart: index === 0 && Boolean(block.metadata.isFunctionStart),
          blockLabel: block.address ?? '',
        });
      });
    }
    return flat;
  }, [graph]);

  const liveInstructions = useMemo<FlatInstruction[]>(() => {
    if (!liveDisassembly) return [];
    return liveDisassembly.instructions.map((insn, index) => ({
      address: insn.address,
      mnemonic: insn.mnemonic,
      operands: insn.operands,
      numericAddress: parseHexAddress(insn.address),
      isBlockStart: index === 0,
      isFunctionStart: false,
      blockLabel: liveDisassembly.moduleLabel ?? insn.address,
    }));
  }, [liveDisassembly]);

  // Static always wins when it has something to show - it is the richer,
  // click-to-breakpoint-capable view; live disassembly only fills in when
  // the PC genuinely has no static function to fall back to.
  const usingLive = staticInstructions.length === 0 && liveInstructions.length > 0;
  const instructions = usingLive ? liveInstructions : staticInstructions;
  const currentAddress = usingLive ? executingRuntimeAddress : executingAddress;
  const loading = usingLive ? false : loadingGraph;

  const breakpointAddresses = useMemo(
    () => new Set(breakpoints.map((bp) => bp.staticAddress)),
    [breakpoints],
  );

  // Auto-scroll the current instruction into view every time the debugger
  // stops somewhere new (connect, step, breakpoint hit) - the whole point of
  // this view is "don't make the user hunt for where execution is".
  useEffect(() => {
    activeRowRef.current?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }, [currentAddress, graph, liveDisassembly]);

  const functionName = graph?.metadata.functionName as string | undefined;
  const functionAddress = graph?.metadata.functionAddress as string | undefined;
  const headerLabel = usingLive
    ? liveDisassembly?.moduleLabel ?? liveDisassembly?.runtimeAddress ?? 'Assembly (live)'
    : functionName
      ? `${functionName} (${displayAddress(functionAddress, rebaseDelta)})`
      : 'Assembly';

  return (
    <div className="assembly-view-wrap">
      <div className="assembly-view-header">
        <span>
          {headerLabel}
          {usingLive ? ' · module hệ thống, chỉ đọc' : ''}
        </span>
        <span className={`debug-status-badge debug-status-${status}`}>{status}</span>
      </div>

      <div className="assembly-view-body">
        {loading && <p className="assembly-view-empty">Đang tải assembly...</p>}

        {!loading && instructions.length === 0 && loadingLive && (
          <p className="assembly-view-empty">
            Không có function tĩnh chứa địa chỉ hiện tại - đang thử disassemble trực tiếp từ tiến
            trình (module hệ thống)...
          </p>
        )}

        {!loading && instructions.length === 0 && !loadingLive && (
          <p className="assembly-view-empty">
            {executingAddress === null && executingRuntimeAddress === null
              ? 'Chưa dừng ở đâu (đang chạy hoặc chưa attach).'
              : 'Không đọc được code tại địa chỉ hiện tại (cả static graph lẫn disassemble trực tiếp đều không có dữ liệu).'}
          </p>
        )}

        {!loading && instructions.length > 0 && (
          <pre className="disasm assembly-listing">
            {instructions.map((insn, index) => {
              const isCurrent = currentAddress !== null && insn.numericAddress === currentAddress;
              const hasBreakpoint = !usingLive && breakpointAddresses.has(insn.address);
              // Live-branch addresses are already runtime - only the static
              // (graph) branch needs rebasing for display.
              const shownAddress = usingLive ? insn.address : displayAddress(insn.address, rebaseDelta);
              const shownBlockLabel = usingLive
                ? insn.blockLabel
                : displayAddress(insn.blockLabel, rebaseDelta);
              return (
                <div key={`${insn.address}-${index}`}>
                  {insn.isBlockStart && (
                    <div className="disasm-block-header">
                      {shownBlockLabel}
                      {insn.isFunctionStart ? ' · entry' : ''}
                    </div>
                  )}
                  <div
                    ref={isCurrent ? activeRowRef : undefined}
                    className={`disasm-row assembly-row${isCurrent ? ' assembly-row-current' : ''}`}
                  >
                    {usingLive ? (
                      <span />
                    ) : (
                      <button
                        type="button"
                        className={`assembly-bp-toggle${hasBreakpoint ? ' assembly-bp-set' : ''}`}
                        disabled={breakpointsDisabled}
                        title={hasBreakpoint ? 'Xóa breakpoint' : 'Đặt breakpoint tại đây'}
                        aria-label={
                          hasBreakpoint
                            ? `Xóa breakpoint tại ${shownAddress}`
                            : `Đặt breakpoint tại ${shownAddress}`
                        }
                        onClick={() => onToggleBreakpoint(insn.address)}
                      >
                        ●
                      </button>
                    )}
                    <span className="a">{shownAddress}</span>
                    <span className="m">{insn.mnemonic}</span>
                    <span>{insn.operands}</span>
                  </div>
                </div>
              );
            })}
          </pre>
        )}
      </div>
    </div>
  );
}
