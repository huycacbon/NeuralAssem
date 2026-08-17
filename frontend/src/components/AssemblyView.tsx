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
 *   Rows toggle breakpoints via a *static* address the backend rebases
 *   (`onToggleBreakpoint`/`debugApi.setBreakpoint`).
 * - `liveDisassembly` (fallback): when the PC is somewhere the static graph
 *   never covered (system DLLs, most commonly - see
 *   `backend/app/dynamic/session.py`'s `disassemble_current` docstring),
 *   disassembled live from the process's own bytes instead. Its addresses
 *   are already *runtime* addresses - rows toggle breakpoints via
 *   `onToggleRuntimeBreakpoint`/`debugApi.setRuntimeBreakpoint`, which sets
 *   the address as-is, no static rebase (the sample's rebase delta is only
 *   valid for the sample's own module - applying it to an unrelated
 *   module's address, e.g. ntdll, produces a bogus address that isn't
 *   actually mapped there; that was a real, live failure once).
 *
 * Every row toggles its breakpoint two ways: the gutter "●" button, or a
 * double-click anywhere on the row (a common debugger convention - x64dbg,
 * OllyDbg, WinDbg's own listing).
 *
 * Ctrl+G ("go to address", the same shortcut x64dbg uses) jumps to and
 * briefly highlights a matching row. Two tiers:
 * 1. Already present in the *currently rendered* listing - scrolls to it
 *    immediately, no round trip. Accepts either the raw address (static: the
 *    un-rebased value; live: the runtime value) or, on the static branch, the
 *    rebased address as actually displayed - whichever the user copied from
 *    the UI should work. Also accepts a `sub_<hex>` name (angr's naming
 *    convention for an unnamed function *is* its address), stripping the
 *    prefix before parsing.
 * 2. Not currently rendered - delegates to `onJumpToAddress`, which
 *    `App.tsx` uses to look up whichever *static* function's address *range*
 *    actually contains the target, fetch its CFG (cached, same cache the
 *    graph view uses), and swap the listing to it via `externalJumpTarget`/an
 *    updated `graph` prop; this component then scrolls to the (now-rendered)
 *    target itself once it appears. Tried unconditionally, even while
 *    currently on the `liveDisassembly` branch (PC sitting in a system DLL) -
 *    that is precisely when jumping to a `sub_...` static function by name is
 *    most useful, and a static function's address means the same thing
 *    regardless of which branch happens to be on screen right now. A target
 *    no static function covers at all (a bare runtime address with nothing
 *    resembling it in the static graph) surfaces as an error banner.
 */

import { useEffect, useMemo, useRef, useState } from 'react';

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

/** Same as `parseHexAddress`, plus accepts a `sub_<hex>` function name (with
 *  or without a `0x` after the prefix) - the Ctrl+G box takes either, since
 *  that name literally *is* the address for anything angr couldn't name. */
function parseGoToInput(value: string | null | undefined): number | null {
  if (!value) return null;
  return parseHexAddress(value.trim().replace(/^sub_/i, ''));
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
  /** For a `liveDisassembly` row - the address is already a runtime one, so
   *  this must not go through the same static rebase as `onToggleBreakpoint`
   *  (see module docstring). */
  onToggleRuntimeBreakpoint: (runtimeAddress: string) => void;
  /** Ctrl+G, tier 2 (see module docstring): called with a *static* address
   *  that wasn't found in the currently rendered listing, so `App.tsx` can
   *  look up and fetch whichever function actually contains it. No-op on the
   *  live branch (never called there). */
  onJumpToAddress: (staticAddress: number) => void;
  /** Set by `App.tsx` once the function requested via `onJumpToAddress` has
   *  been fetched and `graph` updated to show it - this component scrolls to
   *  and flashes the row for this (raw, un-rebased) address, then reports
   *  back via `onExternalJumpConsumed` so the parent clears it (otherwise a
   *  later coincidental re-render could re-trigger the same scroll). `null`
   *  when there is nothing pending. */
  externalJumpTarget: number | null;
  onExternalJumpConsumed: () => void;
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
  onToggleRuntimeBreakpoint,
  onJumpToAddress,
  externalJumpTarget,
  onExternalJumpConsumed,
}: AssemblyViewProps): JSX.Element {
  const activeRowRef = useRef<HTMLDivElement | null>(null);
  // Keyed by each row's raw numeric address (`insn.numericAddress`, never
  // the rebased display value) - populated via each row's own ref callback
  // below, read back by the Ctrl+G handler to scroll a match into view.
  const rowRefs = useRef<Map<number, HTMLDivElement>>(new Map());
  const goToInputRef = useRef<HTMLInputElement | null>(null);

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

  const staticBreakpointAddresses = useMemo(
    () => new Set(breakpoints.map((bp) => bp.staticAddress).filter((address) => address !== null)),
    [breakpoints],
  );
  // Runtime breakpoints (`staticAddress === null`, see `DebugBreakpoint`'s
  // docstring) match live-disassembly rows by their own runtime address.
  const runtimeBreakpointAddresses = useMemo(
    () =>
      new Set(
        breakpoints.filter((bp) => bp.staticAddress === null).map((bp) => bp.runtimeAddress),
      ),
    [breakpoints],
  );

  // -- Ctrl+G "go to address" (same shortcut x64dbg uses) - see module
  // docstring for the two-tier lookup (current listing, then re-fetch). -----
  const [goToOpen, setGoToOpen] = useState(false);
  const [goToValue, setGoToValue] = useState('');
  const [goToNotFound, setGoToNotFound] = useState(false);
  const [jumpTargetAddress, setJumpTargetAddress] = useState<number | null>(null);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent): void => {
      if (event.ctrlKey && event.key.toLowerCase() === 'g') {
        event.preventDefault(); // browsers default Ctrl+G to "find next" - not wanted here
        setGoToNotFound(false);
        setGoToValue('');
        setGoToOpen(true);
      } else if (event.key === 'Escape' && goToOpen) {
        setGoToOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [goToOpen]);

  useEffect(() => {
    if (goToOpen) goToInputRef.current?.focus();
  }, [goToOpen]);

  const handleGoToSubmit = (): void => {
    const parsed = parseGoToInput(goToValue);
    if (parsed === null) {
      setGoToNotFound(true);
      return;
    }
    // Tier 1: accept either the raw address or, on the static branch, the
    // rebased address as actually shown on screen - whichever the user
    // copied.
    const rawMatch = rowRefs.current.get(parsed);
    const rebasedMatch =
      !usingLive && rebaseDelta ? rowRefs.current.get(parsed - rebaseDelta) : undefined;
    const target = rawMatch ?? rebasedMatch;
    const targetAddress = rawMatch ? parsed : rebaseDelta ? parsed - rebaseDelta : null;
    if (target && targetAddress !== null) {
      setGoToNotFound(false);
      setGoToOpen(false);
      target.scrollIntoView({ block: 'center', behavior: 'smooth' });
      setJumpTargetAddress(targetAddress);
      window.setTimeout(() => setJumpTargetAddress(null), 1500);
      return;
    }
    // Tier 2 - not on screen, ask App.tsx to fetch whatever *static* function
    // contains it. Always attempted, even while currently viewing the live
    // branch (PC sitting in a system DLL, most commonly, exactly the case
    // that makes typing a `sub_...` name useful in the first place) - a
    // static function's address is meaningful independent of what happens to
    // be on screen right now. Close the overlay optimistically; a failure (no
    // such function anywhere in the static graph) surfaces as a banner, the
    // app's usual error-reporting path, same as every other API call here.
    setGoToNotFound(false);
    setGoToOpen(false);
    onJumpToAddress(parsed);
  };

  // Tier 2 continued: once App.tsx has fetched the target function and this
  // component re-rendered with the new `graph`, its rows exist in `rowRefs` -
  // scroll to and flash the one that was actually asked for, then tell the
  // parent to clear `externalJumpTarget` so an unrelated later re-render
  // (e.g. the next debugger step) can't replay this scroll.
  useEffect(() => {
    if (externalJumpTarget === null) return;
    const target = rowRefs.current.get(externalJumpTarget);
    if (!target) return; // the requested function's rows haven't landed yet
    target.scrollIntoView({ block: 'center', behavior: 'smooth' });
    setJumpTargetAddress(externalJumpTarget);
    window.setTimeout(() => setJumpTargetAddress(null), 1500);
    onExternalJumpConsumed();
  }, [externalJumpTarget, instructions, onExternalJumpConsumed]);

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

  // Repopulated fresh by each row's own ref callback below on every render -
  // stale entries from a previous listing (e.g. switching static <-> live,
  // or a different function loading in) must not linger for Ctrl+G to match
  // against a row that no longer exists.
  rowRefs.current.clear();

  return (
    <div className="assembly-view-wrap">
      <div className="assembly-view-header">
        <span>
          {headerLabel}
          {usingLive ? ' · module hệ thống, chỉ đọc' : ''}
        </span>
        <span className={`debug-status-badge debug-status-${status}`}>{status}</span>
      </div>

      {goToOpen && (
        <div className="assembly-goto-overlay">
          <input
            ref={goToInputRef}
            type="text"
            className="mono"
            value={goToValue}
            placeholder="0x401000 hoặc sub_140012345"
            onChange={(event) => {
              setGoToValue(event.target.value);
              setGoToNotFound(false);
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter') handleGoToSubmit();
              if (event.key === 'Escape') setGoToOpen(false);
            }}
          />
          <button type="button" onClick={handleGoToSubmit}>
            Đi tới
          </button>
          <button type="button" onClick={() => setGoToOpen(false)}>
            ✕
          </button>
          {goToNotFound && (
            <span className="assembly-goto-error">Không tìm thấy trong danh sách đang hiển thị</span>
          )}
        </div>
      )}

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
              const isJumpTarget =
                jumpTargetAddress !== null && insn.numericAddress === jumpTargetAddress;
              // `insn.address` is a *static* address on the graph branch, a
              // *runtime* one on the live branch - matched against the
              // correspondingly-split breakpoint sets above, and each
              // branch's own toggle callback below never mixes the two.
              const hasBreakpoint = usingLive
                ? runtimeBreakpointAddresses.has(insn.address)
                : staticBreakpointAddresses.has(insn.address);
              const toggleBreakpoint = usingLive
                ? () => onToggleRuntimeBreakpoint(insn.address)
                : () => onToggleBreakpoint(insn.address);
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
                    ref={(el) => {
                      if (isCurrent) activeRowRef.current = el;
                      if (el && insn.numericAddress !== null) {
                        rowRefs.current.set(insn.numericAddress, el);
                      }
                    }}
                    className={`disasm-row assembly-row${isCurrent ? ' assembly-row-current' : ''}${isJumpTarget ? ' assembly-row-jumped' : ''}`}
                    title="Double-click để đặt/xóa breakpoint tại dòng này"
                    onDoubleClick={breakpointsDisabled ? undefined : toggleBreakpoint}
                  >
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
                      onClick={(event) => {
                        event.stopPropagation(); // the row's own onDoubleClick would double-toggle
                        toggleBreakpoint();
                      }}
                      onDoubleClick={(event) => event.stopPropagation()}
                    >
                      ●
                    </button>
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
