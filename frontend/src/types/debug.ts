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
