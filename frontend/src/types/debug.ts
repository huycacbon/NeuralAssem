/**
 * Wire types for the dynamic analysis (Debug) API - mirrors
 * `backend/app/dynamic/models.py`, following the same hand-maintained
 * camelCase convention as `types/graph.ts`.
 */

import type { RiskLevel } from '@/types/graph';

export type DebugSessionStatus =
  | 'connecting'
  | 'attached'
  | 'running'
  | 'break'
  /** The debuggee process itself has terminated (ran to completion, or
   *  crashed) - a terminal state, not an error in this app. Nothing further
   *  can step/continue/read live state since there is no live process left
   *  - see `backend/app/dynamic/session.py`'s `SessionStatus.EXITED`
   *  docstring for the real bug this distinction fixes (every stop used to
   *  collapse to `'break'`, making a process exit look identical to the
   *  debugger legitimately, permanently frozen at one address). */
  | 'exited'
  | 'disconnected'
  | 'error';

export interface DebugRegister {
  name: string;
  value: string;
}

export interface DebugStackFrame {
  index: number;
  runtimeReturnAddress: string;
  /** null when the return address falls outside the analysed module. */
  staticReturnAddress: string | null;
}

export interface DebugBreakpoint {
  id: number;
  /** null for a breakpoint set via `setRuntimeBreakpoint` - outside the
   *  sample's own module (e.g. a system DLL like ntdll), where no
   *  meaningful static address exists. See
   *  `backend/app/dynamic/session.py`'s `set_runtime_breakpoint` docstring. */
  staticAddress: string | null;
  runtimeAddress: string;
  /** Whether the physical `0xCC` is currently written into the debuggee -
   *  `false` most commonly means the module this address is inside hasn't
   *  loaded yet (a DLL loaded later via `LoadLibrary`). Not an error state:
   *  a pending breakpoint keeps retrying automatically on every subsequent
   *  Continue until the module loads and it plants successfully. See
   *  `backend/app/dynamic/models.py`'s `BreakpointModel.planted` docstring. */
  planted: boolean;
}

/** One row of the debuggee's module list (x64dbg-style: main EXE + every
 *  DLL currently mapped, including ones loaded well after attach) - fetched
 *  on demand via `debugApi.listModules`, not part of `DebugSessionState`
 *  itself (same convention as live disassembly). */
export interface DebugModule {
  loadBase: string;
  moduleName: string;
  /** `0` when the module's own `SizeOfImage` could not be read - not an
   *  error, just "size unknown". */
  size: number;
}

export interface DebugSessionState {
  sessionId: string;
  analysisId: string;
  status: DebugSessionStatus;
  runtimeAddress: string | null;
  /** Address_map-translated equivalent in the static graph's coordinate
   *  space - this is what gets matched against `GraphNode.address`. */
  staticAddress: string | null;
  moduleLoadBase: string | null;
  /** The analysed module's *preferred* ImageBase (what every static address
   *  in the app - function list, graph nodes, CFG - is already computed
   *  against). Paired with `moduleLoadBase`, used to derive
   *  `rebaseDelta = moduleLoadBase - preferredImageBase` once per session -
   *  see `utils/addressDisplay.ts`. */
  preferredImageBase: string | null;
  registers: DebugRegister[];
  stack: DebugStackFrame[];
  breakpoints: DebugBreakpoint[];
  lastError: string | null;
}

export interface RiskCheckResponse {
  /** Same bucket as `RiskLevel` - kept as a distinct name because it feeds
   *  the warning modal's copy, not node styling. */
  riskBucket: RiskLevel;
  riskScore: number;
  sampleName: string;
  likelyPacked: boolean;
}

export type StepMode = 'into' | 'over';

/** One line from a live `IDebugControl::Disassemble` call - distinct from
 *  `Instruction` (types/graph.ts), which is the static, angr-derived kind
 *  used everywhere else. See `LiveDisassemblyResponse`. */
export interface LiveInstruction {
  address: string;
  mnemonic: string;
  operands: string;
}

/** Fallback for the assembly view when the debugger's PC is outside the one
 *  module the static analyzer covers (system DLLs, most commonly) - fetched
 *  on demand via `debugApi.getLiveDisassembly`, not part of
 *  `DebugSessionState` itself. */
export interface LiveDisassemblyResponse {
  runtimeAddress: string;
  moduleLabel: string | null;
  instructions: LiveInstruction[];
}

/** Response of `debugApi.dumpMemory` - `address` is a *runtime* address, no
 *  address_map translation involved (same as `LiveDisassemblyResponse`).
 *  `bytesHex` is raw bytes as a plain hex string, formatted into the
 *  classic address/hex/ASCII rows by `MemoryDumpPanel`. */
export interface MemoryDumpResponse {
  address: string;
  size: number;
  bytesHex: string;
}
