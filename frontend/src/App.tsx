/**
 * Application shell.
 *
 * Responsibilities kept here deliberately: which graph is on screen, which node
 * is selected, and the analysis lifecycle. Rendering lives in `components/`,
 * filtering in `hooks/useGraphFilters`, and I/O in `services/analysisApi`.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import { AnalysisSummary } from '@/components/AnalysisSummary';
import { AssemblyView } from '@/components/AssemblyView';
import { DebugConnectModal } from '@/components/DebugConnectModal';
import { FunctionList } from '@/components/FunctionList';
import { GraphLegend } from '@/components/GraphLegend';
import { GraphToolbar } from '@/components/GraphToolbar';
import { GraphViewer, type GraphViewerHandle } from '@/components/GraphViewer';
import { NodeDetails } from '@/components/NodeDetails';
import { useDebugSession } from '@/hooks/useDebugSession';
import { useGraphFilters } from '@/hooks/useGraphFilters';
import { analysisApi, ApiError } from '@/services/analysisApi';
import { debugApi } from '@/services/debugApi';
import type { LiveDisassemblyResponse } from '@/types/debug';
import { computeRebaseDelta } from '@/utils/addressDisplay';
import type {
  AnalysisResponse,
  AnalysisStage,
  FunctionDetail,
  FunctionSummary,
  Graph,
  GraphNode,
  GraphType,
  ImportedApi,
  LayoutName,
} from '@/types/graph';

import '@/styles/index.css';
import '@/styles/app.css';

interface BannerMessage {
  id: string;
  text: string;
  severity: 'warn' | 'error';
}

/** Same "0x401000" -> number parsing NodeDetails.tsx keeps a private copy
 *  of - needed here too for range checks (is this address *inside* a
 *  function/block, not just an exact match on its start address). */
function parseHexAddress(address: string | null | undefined): number | null {
  if (!address) return null;
  const parsed = Number.parseInt(address.replace(/^0x/i, ''), 16);
  return Number.isNaN(parsed) ? null : parsed;
}

/** Shared by `handleExport`/`handleExportFull` - Blob + object URL works
 *  identically whether `content` came over HTTP or straight from the desktop
 *  bridge, no server-sent `Content-Disposition` needed either way. */
function downloadTextFile(filename: string, content: string): void {
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/** How many instructions `debugFunctionCfg` should carry before the debug
 *  assembly view (`AssemblyView`) is considered "full enough" - short
 *  functions (the common case for hand-written stubs, thunks, tiny
 *  wrappers) otherwise leave the view mostly blank below a handful of rows,
 *  since `AssemblyView` never fetches more on its own - it just flattens
 *  whatever `graph` it's given. ~45 rows comfortably fills a typical panel
 *  height without needing to scroll on first paint. */
const MIN_ASSEMBLY_INSTRUCTION_COUNT = 45;
/** Upper bound on how many *additional* functions get merged in to reach
 *  that target - caps the fetch burst for a binary made of many tiny
 *  functions in a row (each contributes only a few instructions) so this
 *  can't balloon into dozens of requests. */
const MAX_EXTRA_FUNCTIONS_TO_FILL = 6;

function countBasicBlockInstructions(graph: Graph): number {
  return graph.nodes
    .filter((node) => node.kind === 'basic_block')
    .reduce((sum, node) => sum + (node.metadata.instructions?.length ?? 0), 0);
}

/** Concatenates `extra`'s nodes/edges onto `base` - used purely to give
 *  `AssemblyView` more rows to flatten (see `MIN_ASSEMBLY_INSTRUCTION_COUNT`).
 *  `base`'s own `metadata` (function name/address the view's header reads)
 *  is kept as-is - the merged-in function is additional *content*, not a
 *  change of "which function is this view about". */
function appendGraphForFilling(base: Graph, extra: Graph): Graph {
  return {
    nodes: [...base.nodes, ...extra.nodes],
    edges: [...base.edges, ...extra.edges],
    metadata: base.metadata,
  };
}

export default function App(): JSX.Element {
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [stage, setStage] = useState<AnalysisStage>('idle');
  const [uploadPercent, setUploadPercent] = useState(0);
  const [banners, setBanners] = useState<BannerMessage[]>([]);

  const [graphType, setGraphType] = useState<GraphType>('call');
  const [layout, setLayout] = useState<LayoutName>('neural');
  const [depth, setDepth] = useState(2);
  const [maxNodes, setMaxNodes] = useState(500);

  const [callGraph, setCallGraph] = useState<Graph | null>(null);
  const [apiGraph, setApiGraph] = useState<Graph | null>(null);
  const [cfgGraph, setCfgGraph] = useState<Graph | null>(null);

  const [functions, setFunctions] = useState<FunctionSummary[]>([]);
  const [imports, setImports] = useState<ImportedApi[]>([]);
  const [loadingFunctions, setLoadingFunctions] = useState(false);

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [functionDetail, setFunctionDetail] = useState<FunctionDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [functionDisassembly, setFunctionDisassembly] = useState<Graph | null>(null);
  const [loadingDisassembly, setLoadingDisassembly] = useState(false);
  /** Address of the function currently being decompiled on demand, if any. */
  const [decompilingAddress, setDecompilingAddress] = useState<string | null>(null);

  /* ---------------- Debug (dynamic analysis) ---------------- */
  const debug = useDebugSession();
  const [debugModalOpen, setDebugModalOpen] = useState(false);
  // In-memory only, resets on reload - the mandatory warning modal (safety
  // constraint #6) shows once per page session, never persisted to disk.
  const [debugWarningAcknowledged, setDebugWarningAcknowledged] = useState(false);
  // Drives the "Xuất tất cả (decompile hết)" button's disabled/label state -
  // see `handleExportFull`, which can block for minutes on a large binary.
  const [exportingFull, setExportingFull] = useState(false);
  const [executingNodeId, setExecutingNodeId] = useState<string | null>(null);
  // Which view fills the centre column while a debug session is active - the
  // graph is replaced by a live-highlighted assembly listing by default (per
  // spec: "vào debugger thì không hiển thị đồ thị nữa, hiển thị assembly"),
  // but a manual toggle in the toolbar still lets the user peek at the graph
  // without disconnecting.
  const [debugViewMode, setDebugViewMode] = useState<'graph' | 'assembly'>('graph');
  const [debugFunctionCfg, setDebugFunctionCfg] = useState<Graph | null>(null);
  const [loadingDebugFunctionCfg, setLoadingDebugFunctionCfg] = useState(false);
  // Ctrl+G "jump to a function not currently shown" (AssemblyView's tier 2) -
  // when set, overrides `debugFunctionCfg` as what the assembly view
  // displays, independent of the debugger's actual PC. Cleared the moment the
  // PC itself moves (next step/continue/breakpoint), so a manual jump never
  // lingers past the debugger no longer being stopped where the user left it.
  const [pinnedAssemblyGraph, setPinnedAssemblyGraph] = useState<Graph | null>(null);
  const [pinnedAssemblyJumpTarget, setPinnedAssemblyJumpTarget] = useState<number | null>(null);
  const [loadingPinnedAssembly, setLoadingPinnedAssembly] = useState(false);
  // Fallback for when the PC has no static function to show at all (system
  // DLLs, most commonly) - see AssemblyView's module docstring.
  const [liveDisassembly, setLiveDisassembly] = useState<LiveDisassemblyResponse | null>(null);
  const [loadingLiveDisassembly, setLoadingLiveDisassembly] = useState(false);
  /** The exact `File` the user picked for the current analysis, kept in
   *  memory so local-launch can offer "run the file I just uploaded" as a
   *  one-click option - the backend's own copy is deleted right after
   *  static analysis finishes, so this is the only place it still exists. */
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);

  const viewerRef = useRef<GraphViewerHandle | null>(null);
  const onViewerReady = useCallback((handle: GraphViewerHandle) => {
    viewerRef.current = handle;
  }, []);

  // CFG responses are keyed by function address and reused between the
  // details-panel disassembly preview and the full CFG graph view, so
  // clicking a function never fetches the same function twice.
  const cfgCacheRef = useRef<Map<string, Graph>>(new Map());

  const activeGraph = useMemo<Graph | null>(() => {
    if (graphType === 'call') return callGraph;
    if (graphType === 'api') return apiGraph;
    return cfgGraph;
  }, [graphType, callGraph, apiGraph, cfgGraph]);

  const {
    filters,
    update: updateFilter,
    reset: resetFilters,
    hideNode,
    unhideAll,
    hiddenByUser,
    availableApis,
    isFiltered,
    visibleNodeIds,
    visibleEdgeIds,
    hiddenCount,
  } = useGraphFilters(activeGraph);

  const functionNames = useMemo(() => {
    const map = new Map<string, string>();
    for (const fn of functions) map.set(fn.address, fn.name);
    return map;
  }, [functions]);

  const addBanner = useCallback((text: string, severity: BannerMessage['severity']) => {
    setBanners((previous) => {
      if (previous.some((item) => item.text === text)) return previous;
      return [...previous, { id: `${Date.now()}-${previous.length}`, text, severity }];
    });
  }, []);

  /* ---------------- Analysis lifecycle ---------------- */

  const handleFileSelected = useCallback(
    async (file: File) => {
      setBanners([]);
      setAnalysis(null);
      setCallGraph(null);
      setApiGraph(null);
      setCfgGraph(null);
      setFunctions([]);
      setImports([]);
      setSelectedNode(null);
      setFunctionDetail(null);
      setFunctionDisassembly(null);
      setDecompilingAddress(null);
      setGraphType('call');
      cfgCacheRef.current.clear();
      resetFilters();

      // A new sample invalidates any open debug session - it belongs to the
      // previous analysisId's address space and static graph.
      setDebugModalOpen(false);
      setExecutingNodeId(null);
      setDebugViewMode('graph');
      setDebugFunctionCfg(null);
      setLiveDisassembly(null);
      if (debug.session) void debug.disconnect();
      setUploadedFile(file);

      setStage('validating');
      setUploadPercent(0);

      try {
        setStage('uploading');
        const response = await analysisApi.analyze(file, (percent) => {
          setUploadPercent(percent);
          // Once bytes are on the server the visible work shifts to angr; walk
          // the stage labels forward so the user sees progress, not a freeze.
          if (percent >= 100) setStage('loading_binary');
        });

        setStage('building_graph');
        setAnalysis(response);
        setCallGraph(response.callGraph);

        for (const warning of response.summary.warnings) {
          addBanner(warning, 'warn');
        }
        if (response.callGraph.metadata.truncated) {
          addBanner(
            `Graph đã bị giới hạn ở ${response.callGraph.metadata.maxNodes} node ` +
              `(${response.callGraph.metadata.omittedFunctions} function không hiển thị). ` +
              'Tăng "Số node tối đa" hoặc dùng Expand để xem thêm.',
            'warn',
          );
        } else if (response.callGraph.metadata.depthLimited) {
          addBanner(
            `${response.callGraph.metadata.omittedFunctions} function nằm ngoài ` +
              `${response.callGraph.metadata.depth} hop từ entry point. Tăng độ sâu để xem thêm.`,
            'warn',
          );
        }

        setStage('extracting_functions');
        setLoadingFunctions(true);
        try {
          const [functionList, importList] = await Promise.all([
            analysisApi.listFunctions(response.analysisId, { limit: 1000 }),
            analysisApi.getImports(response.analysisId),
          ]);
          setFunctions(functionList.items);
          setImports(importList);
        } finally {
          setLoadingFunctions(false);
        }

        setStage('completed');
      } catch (error) {
        setStage('failed');
        if (error instanceof ApiError) {
          addBanner(
            error.details ? `${error.message} (${error.code}: ${error.details})` : `${error.message} (${error.code})`,
            'error',
          );
        } else {
          addBanner('Lỗi không xác định khi phân tích file.', 'error');
        }
      }
    },
    [addBanner, resetFilters, debug],
  );

  /* ---------------- Graph loading on demand ---------------- */

  const openFunctionCfg = useCallback(
    async (address: string) => {
      if (!analysis) return;
      try {
        let graph = cfgCacheRef.current.get(address);
        if (!graph) {
          graph = await analysisApi.getFunctionCfg(analysis.analysisId, address);
          cfgCacheRef.current.set(address, graph);
        }
        setCfgGraph(graph);
        setGraphType('cfg');
        // A CFG reads top-to-bottom; switch layout unless the user is already there.
        setLayout('hierarchical');
        setSelectedNode(null);
        if (graph.metadata.truncated) {
          addBanner(
            `CFG của ${graph.metadata.functionName} bị cắt bớt ` +
              `(${graph.metadata.displayedBlocks}/${graph.metadata.blockCount} block).`,
            'warn',
          );
        }
      } catch (error) {
        if (error instanceof ApiError) addBanner(error.message, 'error');
      }
    },
    [analysis, addBanner],
  );

  const loadApiGraph = useCallback(async () => {
    if (!analysis || apiGraph) return;
    try {
      setApiGraph(await analysisApi.getApiGraph(analysis.analysisId, { maxNodes }));
    } catch (error) {
      if (error instanceof ApiError) addBanner(error.message, 'error');
    }
  }, [analysis, apiGraph, maxNodes, addBanner]);

  const handleGraphTypeChange = useCallback(
    (next: GraphType) => {
      setGraphType(next);
      setSelectedNode(null);
      if (next === 'api') void loadApiGraph();
      // Default layouts per the spec: CFG hierarchical, call graph force-directed.
      setLayout(next === 'cfg' ? 'hierarchical' : 'neural');
    },
    [loadApiGraph],
  );

  /* Reload the call graph when depth/maxNodes change. */
  useEffect(() => {
    if (!analysis) return;
    let cancelled = false;

    void (async () => {
      try {
        const graph = await analysisApi.getCallGraph(analysis.analysisId, {
          depth,
          maxNodes,
        });
        if (!cancelled) setCallGraph(graph);
      } catch (error) {
        if (!cancelled && error instanceof ApiError) addBanner(error.message, 'error');
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [analysis, depth, maxNodes, addBanner]);

  /* Fetch full detail (strings, block list) whenever a function node is picked. */
  useEffect(() => {
    if (!analysis || !selectedNode || selectedNode.kind !== 'function' || !selectedNode.address) {
      setFunctionDetail(null);
      return;
    }

    let cancelled = false;
    setLoadingDetail(true);

    void (async () => {
      try {
        const detail = await analysisApi.getFunction(
          analysis.analysisId,
          selectedNode.address as string,
        );
        if (!cancelled) setFunctionDetail(detail);
      } catch {
        if (!cancelled) setFunctionDetail(null);
      } finally {
        if (!cancelled) setLoadingDetail(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [analysis, selectedNode]);

  /*
   * Fetch the function's disassembly (via the CFG endpoint, which already
   * returns instructions per block) whenever a function node is selected, so
   * the details panel can show code immediately on click - without switching
   * the graph currently on screen to CFG view. Results are shared with
   * `openFunctionCfg` through `cfgCacheRef`, so opening the full CFG right
   * after previewing it here never re-fetches.
   */
  useEffect(() => {
    if (!analysis || !selectedNode || selectedNode.kind !== 'function' || !selectedNode.address) {
      setFunctionDisassembly(null);
      return;
    }

    const address = selectedNode.address;
    const cached = cfgCacheRef.current.get(address);
    if (cached) {
      setFunctionDisassembly(cached);
      return;
    }

    let cancelled = false;
    setLoadingDisassembly(true);
    setFunctionDisassembly(null);

    void (async () => {
      try {
        const graph = await analysisApi.getFunctionCfg(analysis.analysisId, address);
        cfgCacheRef.current.set(address, graph);
        if (!cancelled) setFunctionDisassembly(graph);
      } catch {
        if (!cancelled) setFunctionDisassembly(null);
      } finally {
        if (!cancelled) setLoadingDisassembly(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [analysis, selectedNode]);

  /* ---------------- Interactions ---------------- */

  const focusNodeByAddress = useCallback(
    (address: string) => {
      const graph = activeGraph;
      if (!graph) return;
      const node = graph.nodes.find((item) => item.address === address);
      if (!node) return;
      setSelectedNode(node);
      viewerRef.current?.focusNode(node.id);
    },
    [activeGraph],
  );

  /** Finds the function whose address *range* (not just start address)
   *  contains `address` - the debugger's PC is almost always somewhere
   *  inside a function, not exactly on its first instruction. Functions
   *  without a known `size` only match an exact-address stop (e.g. a
   *  breakpoint set right at the entry). */
  const findEnclosingFunction = useCallback(
    (address: number): FunctionSummary | null => {
      for (const fn of functions) {
        const start = parseHexAddress(fn.address);
        if (start === null) continue;
        if (fn.size && fn.size > 0) {
          if (address >= start && address < start + fn.size) return fn;
        } else if (address === start) {
          return fn;
        }
      }
      return null;
    },
    [functions],
  );

  // Address-sorted once per `functions` change - `nextFunctionAfter` below
  // (used only to fill out a too-short debug assembly listing, see
  // `MIN_ASSEMBLY_INSTRUCTION_COUNT`) walks this instead of re-sorting on
  // every call.
  const functionsSortedByAddress = useMemo(
    () =>
      [...functions].sort(
        (a, b) => (parseHexAddress(a.address) ?? 0) - (parseHexAddress(b.address) ?? 0),
      ),
    [functions],
  );

  const nextFunctionAfter = useCallback(
    (address: string): FunctionSummary | null => {
      const index = functionsSortedByAddress.findIndex((fn) => fn.address === address);
      if (index === -1) return null;
      return functionsSortedByAddress[index + 1] ?? null;
    },
    [functionsSortedByAddress],
  );

  /**
   * Two *independent* highlights, each always computed against the graph it
   * actually belongs to - not against `activeGraph` (whatever is currently
   * on screen). That distinction matters: `activeGraph` *is* the CFG while
   * viewing one, and a CFG has no function-kind nodes at all, so deriving
   * the function highlight from `activeGraph` would silently go blank the
   * moment a CFG was open - and stay wrong even after switching back to the
   * call graph, since nothing had recomputed it against the right data.
   * Searching `callGraph` specifically for the function id, and `cfgGraph`
   * specifically for the block id, means both stay correct independent of
   * which one is currently rendered - switching graph type just picks which
   * of the two already-correct ids to feed `GraphViewer`.
   */
  const executingAddressValue = useMemo(
    () => parseHexAddress(debug.session?.staticAddress ?? null),
    [debug.session?.staticAddress],
  );

  // A manual Ctrl+G jump (AssemblyView's tier 2, see its module docstring) is
  // a temporary detour from "follow the debugger's PC" - the moment the PC
  // itself moves again (step/continue/breakpoint), snap back to auto-follow
  // rather than leaving the user staring at a function execution has long
  // since left.
  useEffect(() => {
    setPinnedAssemblyGraph(null);
    setPinnedAssemblyJumpTarget(null);
  }, [executingAddressValue]);

  /** AssemblyView's Ctrl+G tier 2: `address` wasn't in the currently
   *  rendered listing, so look up whichever function's address *range*
   *  actually contains it, fetch its CFG (sharing the same cache as the
   *  graph view and the PC-follow effect below), and pin the assembly view
   *  to it. A miss (no function covers this address at all) surfaces as a
   *  banner, same as any other failed lookup in this app. */
  const handleJumpToStaticAddress = useCallback(
    (address: number) => {
      if (!analysis) return;
      const enclosingFunction = findEnclosingFunction(address);
      if (!enclosingFunction) {
        addBanner(
          `Không tìm thấy hàm nào chứa địa chỉ 0x${address.toString(16)} trong graph tĩnh.`,
          'error',
        );
        return;
      }
      setLoadingPinnedAssembly(true);
      void (async () => {
        try {
          let graph = cfgCacheRef.current.get(enclosingFunction.address);
          if (!graph) {
            graph = await analysisApi.getFunctionCfg(analysis.analysisId, enclosingFunction.address);
            cfgCacheRef.current.set(enclosingFunction.address, graph);
          }
          setPinnedAssemblyGraph(graph);
          setPinnedAssemblyJumpTarget(address);
        } catch (error) {
          if (error instanceof ApiError) addBanner(error.message, 'error');
        } finally {
          setLoadingPinnedAssembly(false);
        }
      })();
    },
    [analysis, findEnclosingFunction, addBanner],
  );

  const handlePinnedJumpConsumed = useCallback(() => setPinnedAssemblyJumpTarget(null), []);

  /** `moduleLoadBase - preferredImageBase` for the active session, `null`
   *  when there is none - the single source of truth every component below
   *  uses to rebase *displayed* static addresses into runtime coordinates
   *  (see `utils/addressDisplay.ts`). Underlying data (`fn.address`,
   *  `node.address`, breakpoint addresses, ...) is never touched - only
   *  what gets rendered as text. */
  const rebaseDelta = useMemo(
    () => computeRebaseDelta(debug.session?.moduleLoadBase, debug.session?.preferredImageBase),
    [debug.session?.moduleLoadBase, debug.session?.preferredImageBase],
  );

  const executingFunctionNodeId = useMemo(() => {
    if (executingAddressValue === null) return null;
    const enclosingFunction = findEnclosingFunction(executingAddressValue);
    if (!enclosingFunction) return null;
    const node = callGraph?.nodes.find(
      (item) => item.kind === 'function' && item.address === enclosingFunction.address,
    );
    return node?.id ?? null;
  }, [executingAddressValue, callGraph, findEnclosingFunction]);

  const executingBlockNodeId = useMemo(() => {
    if (executingAddressValue === null || !cfgGraph) return null;
    const block = cfgGraph.nodes.find((node) => {
      if (node.kind !== 'basic_block') return false;
      const start = parseHexAddress(node.address);
      if (start === null) return false;
      const size = node.metadata.size ?? 0;
      return size > 0
        ? executingAddressValue >= start && executingAddressValue < start + size
        : executingAddressValue === start;
    });
    return block?.id ?? null;
  }, [executingAddressValue, cfgGraph]);

  /** Mirrors focusNodeByAddress, but for the debugger's current address -
   *  kept separate because "selected" (user click) and "executing"
   *  (debugger PC) are two different, simultaneously-visible highlights.
   *  Picks whichever of the two independently-correct ids above matches the
   *  graph currently on screen (CFG shows the block, call/API graph shows
   *  the function) and pans to it. */
  const focusExecutingAddress = useCallback(() => {
    const id = graphType === 'cfg' ? executingBlockNodeId : executingFunctionNodeId;
    setExecutingNodeId(id);
    if (id) viewerRef.current?.focusNode(id);
  }, [graphType, executingBlockNodeId, executingFunctionNodeId]);

  // Re-apply whenever either independently-computed id changes (debug
  // stepped/connected/disconnected, or the relevant graph data arrived) or
  // the user switches which of the two graphs is on screen.
  // `focusExecutingAddress` only changes identity on one of those same
  // meaningful changes (not on every render), so no exhaustive-deps
  // workaround is needed here.
  useEffect(() => {
    focusExecutingAddress();
  }, [focusExecutingAddress]);

  // Debugging starting/ending flips the centre column's default view - into
  // assembly the moment a session attaches (that is the point of a
  // debugger: show code, not the static graph), back to the graph the
  // moment it ends. A manual toggle in the toolbar can still override this
  // while the session is live; that override does not need to survive past
  // disconnect, so this effect keying off `session !== null` (not e.g. an
  // extra "user overrode it" flag) is enough.
  const debugSessionActive = debug.session !== null;
  useEffect(() => {
    setDebugViewMode(debugSessionActive ? 'assembly' : 'graph');
  }, [debugSessionActive]);

  // Keep `debugFunctionCfg` pointed at whichever function currently contains
  // the debugger's PC, reusing the same CFG cache the graph view and the
  // details-panel preview already share - stepping within one function (by
  // far the common case) costs zero extra fetches, and stepping into a new
  // function fetches exactly once (plus whatever `MIN_ASSEMBLY_INSTRUCTION_COUNT`
  // needs merged in - each of those is itself cached the same way, so
  // re-entering an already-filled function later never re-fetches).
  useEffect(() => {
    if (!analysis || executingAddressValue === null) {
      setDebugFunctionCfg(null);
      return;
    }
    const enclosingFunction = findEnclosingFunction(executingAddressValue);
    if (!enclosingFunction) {
      setDebugFunctionCfg(null);
      return;
    }
    if (debugFunctionCfg?.metadata.functionAddress === enclosingFunction.address) return;

    let cancelled = false;

    const getCfg = async (address: string): Promise<Graph> => {
      const cached = cfgCacheRef.current.get(address);
      if (cached) return cached;
      const graph = await analysisApi.getFunctionCfg(analysis.analysisId, address);
      cfgCacheRef.current.set(address, graph);
      return graph;
    };

    setLoadingDebugFunctionCfg(true);
    void (async () => {
      try {
        let merged = await getCfg(enclosingFunction.address);
        // Short function (a stub/thunk/tiny wrapper, common) - merge in
        // however many of the *next* functions by address it takes to give
        // AssemblyView enough rows to actually fill the panel, capped so a
        // run of many tiny functions can't balloon into dozens of fetches.
        // See MIN_ASSEMBLY_INSTRUCTION_COUNT's docstring.
        let cursorAddress = enclosingFunction.address;
        let mergedCount = 0;
        while (
          countBasicBlockInstructions(merged) < MIN_ASSEMBLY_INSTRUCTION_COUNT &&
          mergedCount < MAX_EXTRA_FUNCTIONS_TO_FILL
        ) {
          const next = nextFunctionAfter(cursorAddress);
          if (!next) break;
          const nextGraph = await getCfg(next.address);
          merged = appendGraphForFilling(merged, nextGraph);
          cursorAddress = next.address;
          mergedCount += 1;
        }
        if (!cancelled) setDebugFunctionCfg(merged);
      } catch {
        if (!cancelled) setDebugFunctionCfg(null);
      } finally {
        if (!cancelled) setLoadingDebugFunctionCfg(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [analysis, executingAddressValue, findEnclosingFunction, debugFunctionCfg, nextFunctionAfter]);

  const debugRuntimeAddress = debug.session?.runtimeAddress ?? null;
  const debugSessionId = debug.session?.sessionId ?? null;

  // Fallback for when there is no static function to show at all (the PC is
  // in a system DLL, most commonly) - only kicks in once the static lookup
  // above has settled and genuinely come up empty, and re-fetches on every
  // new runtime address (i.e. every step) while that stays true.
  useEffect(() => {
    if (!debugSessionId || loadingDebugFunctionCfg || debugFunctionCfg || !debugRuntimeAddress) {
      setLiveDisassembly(null);
      return;
    }

    let cancelled = false;
    setLoadingLiveDisassembly(true);
    void (async () => {
      try {
        // 200 = the backend's own clamp ceiling (session.py's
        // disassemble_current) - fetching the max lets the listing actually
        // fill a tall viewport instead of leaving blank space below a short
        // 60-instruction window.
        const result = await debugApi.getLiveDisassembly(debugSessionId, 200);
        if (!cancelled) setLiveDisassembly(result);
      } catch {
        if (!cancelled) setLiveDisassembly(null);
      } finally {
        if (!cancelled) setLoadingLiveDisassembly(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [debugSessionId, debugRuntimeAddress, loadingDebugFunctionCfg, debugFunctionCfg]);

  /** Click-to-toggle-breakpoint from the assembly gutter: set one if the
   *  address is bare, remove the existing one otherwise - mirrors what
   *  x64dbg's own instruction-list gutter does, so it needs no separate
   *  address-entry step for the common case (breakpoint on a line you can
   *  already see). */
  const handleToggleBreakpointAtAddress = useCallback(
    (staticAddress: string) => {
      const existing = debug.session?.breakpoints.find((bp) => bp.staticAddress === staticAddress);
      if (existing) {
        void debug.removeBreakpoint(existing.id);
      } else {
        void debug.setBreakpoint(staticAddress);
      }
    },
    [debug],
  );

  /** Same as `handleToggleBreakpointAtAddress` above, for a live-disassembly
   *  row (a system DLL like ntdll, outside the sample's own module) - the
   *  address is already a *runtime* one, so this goes through
   *  `setRuntimeBreakpoint` instead of `setBreakpoint`, never the static
   *  rebase (see `AssemblyView`'s module docstring for why that distinction
   *  matters - the wrong one produced a real, live breakpoint failure). */
  const handleToggleRuntimeBreakpointAtAddress = useCallback(
    (runtimeAddress: string) => {
      const existing = debug.session?.breakpoints.find(
        (bp) => bp.staticAddress === null && bp.runtimeAddress === runtimeAddress,
      );
      if (existing) {
        void debug.removeBreakpoint(existing.id);
      } else {
        void debug.setRuntimeBreakpoint(runtimeAddress);
      }
    },
    [debug],
  );

  /* ---------------- Debug (dynamic analysis) handlers ---------------- */

  const handleDebugClick = useCallback(() => {
    setDebugModalOpen(true);
  }, []);

  const handleAcknowledgeDebugWarning = useCallback(() => {
    setDebugWarningAcknowledged(true);
  }, []);

  const handleCloseDebugModal = useCallback(() => {
    setDebugModalOpen(false);
  }, []);

  const handleLaunchLocalDebug = useCallback(
    (commandLine: string) => {
      if (!analysis) return;
      void debug.launchLocal(analysis.analysisId, commandLine).then((state) => {
        if (state) setDebugModalOpen(false);
      });
    },
    [analysis, debug],
  );

  const handleLaunchLocalFromUploadDebug = useCallback(() => {
    if (!analysis || !uploadedFile) return;
    void debug.launchLocalFromUpload(analysis.analysisId, uploadedFile).then((state) => {
      if (state) setDebugModalOpen(false);
    });
  }, [analysis, uploadedFile, debug]);

  const handleSelectFunction = useCallback(
    (fn: FunctionSummary) => {
      const node = activeGraph?.nodes.find((item) => item.address === fn.address);
      if (node) {
        setSelectedNode(node);
        viewerRef.current?.focusNode(node.id);
        return;
      }
      // The function exists but is filtered out or beyond the current depth;
      // synthesise a node so the details panel still works.
      setSelectedNode({
        id: fn.nodeId,
        label: fn.name,
        kind: 'function',
        address: fn.address,
        metadata: {
          riskScore: fn.riskScore,
          callerCount: fn.callerCount,
          calleeCount: fn.calleeCount,
          blockCount: fn.blockCount,
          isEntryPoint: fn.isEntryPoint,
        },
      });
    },
    [activeGraph],
  );

  const handleExpand = useCallback(
    async (address: string) => {
      if (!analysis || !callGraph) return;
      try {
        const expansion = await analysisApi.expand(analysis.analysisId, address);
        // Merge into the call graph rather than replacing it: expanding must
        // add context, not throw away what is already on screen.
        setCallGraph((previous) => {
          if (!previous) return previous;
          const nodeIds = new Set(previous.nodes.map((node) => node.id));
          const edgeIds = new Set(previous.edges.map((edge) => edge.id));
          return {
            nodes: [...previous.nodes, ...expansion.nodes.filter((n) => !nodeIds.has(n.id))],
            edges: [...previous.edges, ...expansion.edges.filter((e) => !edgeIds.has(e.id))],
            metadata: previous.metadata,
          };
        });
        setGraphType('call');
      } catch (error) {
        if (error instanceof ApiError) addBanner(error.message, 'error');
      }
    },
    [analysis, callGraph, addBanner],
  );

  const handleDecompile = useCallback(
    async (address: string) => {
      if (!analysis) return;
      setDecompilingAddress(address);
      try {
        const detail = await analysisApi.decompileFunction(analysis.analysisId, address);
        // Only replace functionDetail if the user hasn't since selected a
        // different node - an in-flight decompile must not clobber the panel.
        setFunctionDetail((previous) =>
          previous && previous.address === address ? detail : previous,
        );
        if (detail.pseudocodeStatus === 'failed') {
          addBanner(
            detail.pseudocodeNote ?? `Không decompile được function ${detail.name}.`,
            'warn',
          );
        }
      } catch (error) {
        if (error instanceof ApiError) addBanner(error.message, 'error');
      } finally {
        setDecompilingAddress((current) => (current === address ? null : current));
      }
    },
    [analysis, addBanner],
  );

  const handleResetView = useCallback(() => {
    resetFilters();
    setSelectedNode(null);
    viewerRef.current?.relayout();
  }, [resetFilters]);

  const handleExport = useCallback(async () => {
    if (!analysis) return;
    try {
      // Passes the active debug session's rebase delta (if any) so the
      // exported document's addresses reflect the real runtime address
      // rather than the static one - same rebase already applied to
      // on-screen addresses elsewhere (see `rebaseDelta`'s docstring above).
      const { filename, content } = await analysisApi.exportMarkdown(analysis.analysisId, rebaseDelta);
      downloadTextFile(filename, content);
    } catch (error) {
      if (error instanceof ApiError) addBanner(error.message, 'error');
    }
  }, [analysis, addBanner, rebaseDelta]);

  /** Same idea as `handleExport`, scoped to one function - not risk-filtered
   *  like the whole-analysis exports, since there is only one function to
   *  show either way. Does not decompile anything first (unlike
   *  `handleExportFull`) - a function without pseudocode yet just reports
   *  why in the exported file, same as the UI's own "Not decompiled" state. */
  const handleExportFunction = useCallback(
    async (address: string) => {
      if (!analysis) return;
      try {
        const { filename, content } = await analysisApi.exportFunctionMarkdown(
          analysis.analysisId,
          address,
          rebaseDelta,
        );
        downloadTextFile(filename, content);
      } catch (error) {
        if (error instanceof ApiError) addBanner(error.message, 'error');
      }
    },
    [analysis, addBanner, rebaseDelta],
  );

  const handleExportFull = useCallback(async () => {
    if (!analysis || exportingFull) return;
    setExportingFull(true);
    try {
      // Unlike `handleExport`, this first triggers decompiling every
      // function that still lacks pseudocode (no cap, can take from seconds
      // to several minutes on a large binary) so the export afterwards
      // covers as much of the binary as possible - see
      // `analysisApi.decompileAll`'s docstring.
      addBanner('Đang decompile toàn bộ hàm còn thiếu — có thể mất vài phút với binary lớn...', 'warn');
      const counts = await analysisApi.decompileAll(analysis.analysisId);
      addBanner(
        `Decompile xong: ${counts.decompiled} hàm mới, ${counts.alreadyAvailable} đã có sẵn, ` +
          `${counts.failed} thất bại, ${counts.skippedNotApplicable} không áp dụng được ` +
          `(import thunk/stub). Đang xuất file...`,
        'warn',
      );
      const { filename, content } = await analysisApi.exportMarkdownFull(
        analysis.analysisId,
        rebaseDelta,
      );
      downloadTextFile(filename, content);
    } catch (error) {
      if (error instanceof ApiError) addBanner(error.message, 'error');
    } finally {
      setExportingFull(false);
    }
  }, [analysis, addBanner, rebaseDelta, exportingFull]);

  const statusText = useMemo(() => {
    if (stage === 'failed') return 'Phân tích thất bại';
    if (stage === 'completed' && analysis) {
      return analysis.summary.likelyPacked
        ? 'Hoàn tất — cảnh báo: có thể bị pack'
        : 'Hoàn tất';
    }
    if (stage === 'idle') return 'Chưa có phân tích';
    return 'Đang xử lý...';
  }, [stage, analysis]);

  const emptyMessage =
    graphType === 'cfg'
      ? 'Double-click một function (trên graph hoặc panel trái) để mở CFG.'
      : analysis
        ? 'Không có dữ liệu graph.'
        : 'Upload một file PE (.exe / .dll) để bắt đầu phân tích tĩnh.';

  return (
    <div className="app">
      <GraphToolbar
        stage={stage}
        uploadPercent={uploadPercent}
        analysisReady={analysis !== null}
        graphType={graphType}
        layout={layout}
        search={filters.search}
        showLabels={filters.showLabels}
        cfgAvailable={cfgGraph !== null}
        onFileSelected={(file) => void handleFileSelected(file)}
        onGraphTypeChange={handleGraphTypeChange}
        onLayoutChange={setLayout}
        onSearchChange={(value) => updateFilter('search', value)}
        onToggleLabels={() => updateFilter('showLabels', !filters.showLabels)}
        onFit={() => viewerRef.current?.fit()}
        onResetView={handleResetView}
        onExport={handleExport}
        onExportFull={() => void handleExportFull()}
        exportingFull={exportingFull}
        debugSessionActive={debug.session !== null}
        onDebugClick={handleDebugClick}
        debugViewMode={debugViewMode}
        onDebugViewModeChange={setDebugViewMode}
      />

      {analysis && (
        <DebugConnectModal
          open={debugModalOpen}
          analysisId={analysis.analysisId}
          warningAcknowledged={debugWarningAcknowledged}
          onAcknowledgeWarning={handleAcknowledgeDebugWarning}
          connecting={debug.loading}
          connectError={debug.error}
          onClose={handleCloseDebugModal}
          onLaunchLocal={handleLaunchLocalDebug}
          uploadedFile={uploadedFile}
          onLaunchLocalFromUpload={handleLaunchLocalFromUploadDebug}
        />
      )}

      <div className="main">
        <div className="panel panel-left">
          <div className="left-summary">
            <AnalysisSummary
              analysis={analysis}
              graphType={graphType}
              filters={filters}
              availableApis={availableApis}
              isFiltered={isFiltered}
              hiddenCount={hiddenByUser.size}
              depth={depth}
              maxNodes={maxNodes}
              onFilterChange={updateFilter}
              onResetFilters={resetFilters}
              onUnhideAll={unhideAll}
              onDepthChange={setDepth}
              onMaxNodesChange={setMaxNodes}
            />
          </div>
          <FunctionList
            functions={functions}
            selectedAddress={selectedNode?.address ?? null}
            loading={loadingFunctions}
            rebaseDelta={rebaseDelta}
            onSelect={handleSelectFunction}
            onOpenCfg={(fn) => void openFunctionCfg(fn.address)}
          />
        </div>

        <div className="graph-column">
          {banners.length > 0 && (
            <div className="graph-banner">
              {banners.map((banner) => (
                <div
                  key={banner.id}
                  className={`banner ${banner.severity === 'error' ? 'error' : ''}`}
                  role={banner.severity === 'error' ? 'alert' : 'status'}
                  onClick={() =>
                    setBanners((previous) => previous.filter((item) => item.id !== banner.id))
                  }
                  title="Click để đóng"
                >
                  {banner.text}
                </div>
              ))}
            </div>
          )}

          {debug.session && debugViewMode === 'assembly' ? (
            <AssemblyView
              graph={pinnedAssemblyGraph ?? debugFunctionCfg}
              loadingGraph={pinnedAssemblyGraph ? loadingPinnedAssembly : loadingDebugFunctionCfg}
              liveDisassembly={liveDisassembly}
              loadingLive={loadingLiveDisassembly}
              status={debug.session.status}
              executingAddress={executingAddressValue}
              executingRuntimeAddress={parseHexAddress(debugRuntimeAddress)}
              rebaseDelta={rebaseDelta}
              breakpoints={debug.session.breakpoints}
              breakpointsDisabled={debug.loading}
              onToggleBreakpoint={handleToggleBreakpointAtAddress}
              onToggleRuntimeBreakpoint={handleToggleRuntimeBreakpointAtAddress}
              onJumpToAddress={handleJumpToStaticAddress}
              externalJumpTarget={pinnedAssemblyJumpTarget}
              onExternalJumpConsumed={handlePinnedJumpConsumed}
            />
          ) : (
            <GraphViewer
              graph={activeGraph}
              visibleNodeIds={visibleNodeIds}
              visibleEdgeIds={visibleEdgeIds}
              layout={layout}
              showLabels={filters.showLabels}
              selectedNodeId={selectedNode?.id ?? null}
              executingNodeId={executingNodeId}
              rebaseDelta={rebaseDelta}
              searchTerm={filters.search}
              onSelectNode={setSelectedNode}
              onOpenFunction={(address) => void openFunctionCfg(address)}
              onHideNode={hideNode}
              onExpandNode={(address) => void handleExpand(address)}
              onReady={onViewerReady}
              emptyMessage={emptyMessage}
            />
          )}
        </div>

        <NodeDetails
          node={selectedNode}
          rebaseDelta={rebaseDelta}
          functionDetail={functionDetail}
          loadingDetail={loadingDetail}
          functionDisassembly={functionDisassembly}
          loadingDisassembly={loadingDisassembly}
          imports={imports}
          functionNames={functionNames}
          isDecompiling={decompilingAddress !== null && decompilingAddress === selectedNode?.address}
          onOpenCfg={(address) => void openFunctionCfg(address)}
          onExpand={(address) => void handleExpand(address)}
          onFocusAddress={focusNodeByAddress}
          onFilterByApi={(nodeId) => updateFilter('apiFilter', nodeId)}
          onDecompile={(address) => void handleDecompile(address)}
          onExportFunction={(address) => void handleExportFunction(address)}
          debugSession={debug.session}
          debugLoading={debug.loading}
          debugError={debug.error}
          onDebugStep={(mode) => void debug.step(mode)}
          onDebugContinue={() => void debug.continueExecution()}
          onDebugDisconnect={() => void debug.disconnect()}
          onDebugSetBreakpoint={(address) => void debug.setBreakpoint(address)}
          onDebugRemoveBreakpoint={(id) => void debug.removeBreakpoint(id)}
          onDebugSetRegister={(name, value) => void debug.setRegister(name, value)}
        />
      </div>

      <GraphLegend
        graphType={graphType}
        statusText={statusText}
        visibleNodes={visibleNodeIds.size}
        totalNodes={activeGraph?.nodes.length ?? 0}
        hiddenNodes={hiddenCount}
      />
    </div>
  );
}
