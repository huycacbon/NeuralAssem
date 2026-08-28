/**
 * Wire types mirroring the backend's Pydantic models.
 *
 * These are hand-maintained rather than generated; if a backend model changes,
 * change it here too. `any` is not used anywhere - unknown metadata is typed as
 * `unknown` and narrowed at the point of use.
 */

export type NodeKind =
  | 'function'
  | 'basic_block'
  | 'api'
  | 'string'
  | 'module'
  | 'behavior';

export type EdgeKind =
  | 'CALL'
  | 'JUMP'
  | 'TRUE'
  | 'FALSE'
  | 'FALLTHROUGH'
  | 'RETURN'
  | 'REFERENCE'
  | 'READ'
  | 'WRITE'
  | 'DATA_FLOW';

export type RiskLevel = 'none' | 'low' | 'medium' | 'high';

export interface Instruction {
  address: string;
  mnemonic: string;
  operands: string;
}

/** Metadata attached to a function or API node in the call/API graph. */
export interface NodeMetadata {
  size?: number | null;
  blockCount?: number;
  callerCount?: number;
  calleeCount?: number;
  riskScore?: number;
  riskLevel?: RiskLevel;
  isImported?: boolean;
  isEntryPoint?: boolean;
  isPlt?: boolean;
  isNamed?: boolean;
  hasStrings?: boolean;
  apiCount?: number;
  degree?: number;
  sizeHint?: number;
  module?: string;
  capability?: string;
  referenceCount?: number;
  /** basic_block nodes only */
  instructionCount?: number;
  instructions?: Instruction[];
  truncated?: boolean;
  isFunctionStart?: boolean;
  callTargets?: string[];
  successorCount?: number;
  predecessorCount?: number;
}

export interface GraphNode {
  id: string;
  label: string;
  kind: NodeKind;
  address: string | null;
  metadata: NodeMetadata;
}

export interface EdgeMetadata {
  callCount?: number;
  callSite?: string | null;
  fromBlock?: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: EdgeKind;
  metadata: EdgeMetadata;
}

export interface GraphMetadata {
  graphType?: 'call_graph' | 'cfg' | 'api_graph' | 'expansion';
  depth?: number;
  maxNodes?: number;
  /** Nodes were dropped because the node cap was hit. */
  truncated?: boolean;
  /** Nodes were dropped because they lie beyond the hop limit. */
  depthLimited?: boolean;
  /** Either of the above. */
  limited?: boolean;
  totalFunctions?: number;
  displayedFunctions?: number;
  omittedFunctions?: number;
  entryPoint?: string;
  functionAddress?: string;
  functionName?: string;
  blockCount?: number;
  displayedBlocks?: number;
  instructionCount?: number;
  riskScore?: number;
  riskReasons?: string[];
  hasUnresolvedCalls?: boolean;
  isEntryPoint?: boolean;
  totalImports?: number;
  displayedApis?: number;
  capability?: string | null;
  found?: boolean;
  root?: string;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  metadata: GraphMetadata;
}

export interface FileInfo {
  name: string;
  sha256: string;
  size: number;
  architecture: string;
  entryPoint: string;
  format: string;
  bits: number;
  /** The PE's own preferred `ImageBase` - every "static" address elsewhere
   *  in the app (function list, graphs, CFG, `entryPoint` above) is already
   *  expressed in this coordinate space. Subtract this from a static
   *  address to get its RVA, the portable form for a `module+RVA`
   *  expression x64dbg/WinDbg's own "go to" accepts - see
   *  `utils/x64dbgExpression.ts`. */
  imageBase: string;
}

export interface FunctionSummary {
  address: string;
  name: string;
  size: number | null;
  blockCount: number;
  callerCount: number;
  calleeCount: number;
  isImported: boolean;
  isPlt: boolean;
  isEntryPoint: boolean;
  isSyscall: boolean;
  hasUnresolvedCalls: boolean;
  riskScore: number;
  riskReasons: string[];
  importedApis: string[];
  stringCount: number;
  nodeId: string;
}

export interface ReferencedString {
  address: string;
  value: string;
  length: number;
}

export type PseudocodeStatus = 'available' | 'not_attempted' | 'failed' | 'not_applicable';

export interface FunctionDetail extends FunctionSummary {
  strings: ReferencedString[];
  blockAddresses: string[];
  /** C-like pseudocode from angr's Decompiler (heuristic, best-effort). */
  pseudocode: string | null;
  pseudocodeStatus: PseudocodeStatus;
  pseudocodeNote: string | null;
  /** Instruction address (e.g. "0x401000") -> 1-indexed line number in
   *  `pseudocode` - drives the Disassembly<->Pseudocode sync (see
   *  NodeDetails.tsx). `null` when pseudocode isn't available, or is but the
   *  map itself couldn't be built - both are expected, not errors: not every
   *  pseudocode line has a mapped instruction (declarations, braces, blank
   *  lines), and not every instruction survives into the decompiled output. */
  pseudocodeAddressLines: Record<string, number> | null;
}

export interface FunctionListResponse {
  total: number;
  limit: number;
  offset: number;
  items: FunctionSummary[];
}

export interface AnalysisSummary {
  functionCount: number;
  basicBlockCount: number;
  importCount: number;
  stringCount: number;
  highestRiskFunctions: FunctionSummary[];
  warnings: string[];
  analysisDurationSeconds: number;
  likelyPacked: boolean;
}

export interface AnalysisResponse {
  analysisId: string;
  file: FileInfo;
  summary: AnalysisSummary;
  callGraph: Graph;
}

export interface ImportedApi {
  module: string;
  name: string;
  address: string | null;
  nodeId: string;
  capability: string;
  referenceCount: number;
  callers: string[];
}

export interface ExtractedString {
  address: string;
  value: string;
  length: number;
}

export interface ApiErrorDetail {
  code: string;
  message: string;
  details: string | null;
}

/** The frontend's own view of where an analysis is in its lifecycle. */
export type AnalysisStage =
  | 'idle'
  | 'uploading'
  | 'validating'
  | 'loading_binary'
  | 'building_cfg'
  | 'extracting_functions'
  | 'building_graph'
  | 'completed'
  | 'failed';

export type GraphType = 'call' | 'cfg' | 'api';
export type LayoutName = 'neural' | 'hierarchical';
