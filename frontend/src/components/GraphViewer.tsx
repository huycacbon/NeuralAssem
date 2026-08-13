/**
 * Cytoscape canvas.
 *
 * The whole graph is always loaded into Cytoscape; filtering only toggles the
 * `.filtered-out` class. That is what makes "unfilter" instant and keeps the
 * source data intact, as the spec requires.
 */

import cytoscape from 'cytoscape';
import fcose from 'cytoscape-fcose';
import { useCallback, useEffect, useRef, useState } from 'react';

import { buildLayout, buildStylesheet } from '@/components/graphStyle';
import type { Graph, GraphNode, LayoutName } from '@/types/graph';
import { displayAddress } from '@/utils/addressDisplay';

cytoscape.use(fcose);

export interface GraphViewerHandle {
  fit: () => void;
  focusNode: (nodeId: string) => void;
  relayout: () => void;
}

interface GraphViewerProps {
  graph: Graph | null;
  visibleNodeIds: ReadonlySet<string>;
  visibleEdgeIds: ReadonlySet<string>;
  layout: LayoutName;
  showLabels: boolean;
  selectedNodeId: string | null;
  /** Node matching the debug session's current (static-mapped) address, if
   *  any - highlighted with its own CSS class, separate from click-selection
   *  so both can be visible at once (spec's address-sync requirement). */
  executingNodeId: string | null;
  /** `moduleLoadBase - preferredImageBase` from the active debug session, or
   *  `null` when there is none - see `utils/addressDisplay.ts`. Display
   *  only: basic-block node labels/tooltip text are rebased, but
   *  `node.address` itself (used for lookups/API calls) always stays a
   *  static address. */
  rebaseDelta: number | null;
  searchTerm: string;
  onSelectNode: (node: GraphNode | null) => void;
  onOpenFunction: (address: string) => void;
  onHideNode: (nodeId: string) => void;
  onExpandNode: (address: string) => void;
  /** Registers imperative controls with the parent (fit / focus / relayout). */
  onReady: (handle: GraphViewerHandle) => void;
  emptyMessage: string;
}

interface TooltipState {
  x: number;
  y: number;
  node: GraphNode;
}

function toElements(graph: Graph, rebaseDelta: number | null): cytoscape.ElementDefinition[] {
  const nodes: cytoscape.ElementDefinition[] = graph.nodes.map((node) => ({
    group: 'nodes',
    data: {
      id: node.id,
      // Only basic-block labels are addresses (server sets them to
      // `format_address(address)`); function/API/string labels are names,
      // nothing to rebase.
      label: node.kind === 'basic_block' ? displayAddress(node.address, rebaseDelta) : node.label,
      kind: node.kind,
      address: node.address ?? '',
      size: node.metadata.sizeHint ?? (node.kind === 'basic_block' ? 46 : 24),
      riskLevel: node.metadata.riskLevel ?? 'none',
      riskScore: node.metadata.riskScore ?? 0,
      isEntryPoint: node.metadata.isEntryPoint === true,
      raw: node,
    },
  }));

  const nodeIds = new Set(graph.nodes.map((node) => node.id));
  const edges: cytoscape.ElementDefinition[] = graph.edges
    // Defensive: never hand Cytoscape an edge with a missing endpoint - it
    // throws and takes the whole canvas down.
    .filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
    .map((edge) => ({
      group: 'edges',
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        kind: edge.kind,
        callCount: edge.metadata.callCount ?? 1,
        raw: edge,
      },
    }));

  return [...nodes, ...edges];
}

export function GraphViewer({
  graph,
  visibleNodeIds,
  visibleEdgeIds,
  layout,
  showLabels,
  selectedNodeId,
  executingNodeId,
  rebaseDelta,
  searchTerm,
  onSelectNode,
  onOpenFunction,
  onHideNode,
  onExpandNode,
  onReady,
  emptyMessage,
}: GraphViewerProps): JSX.Element {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);

  // Handlers change every render; keep them in refs so the Cytoscape instance
  // does not have to be rebuilt (which would lose pan/zoom).
  const handlers = useRef({ onSelectNode, onOpenFunction, onHideNode, onExpandNode });
  handlers.current = { onSelectNode, onOpenFunction, onHideNode, onExpandNode };

  const runLayout = useCallback(() => {
    const cy = cyRef.current;
    if (!cy || cy.nodes(':visible').length === 0) return;

    // The container is a flex/grid cell whose size changes with panel layout.
    // Cytoscape caches its dimensions, so refresh them before laying out or the
    // fit below is computed against a stale viewport.
    cy.resize();

    const isCfg = graph?.metadata.graphType === 'cfg';
    const running = cy.layout({
      ...buildLayout({ name: layout, isCfg, nodeCount: cy.nodes(':visible').length }),
      // Only lay out what is on screen; filtered-out nodes must not push the
      // visible ones apart. `eles` is a valid Cytoscape layout option but is
      // missing from the bundled typings, hence the cast.
      eles: cy.elements(':visible'),
    } as unknown as cytoscape.LayoutOptions);

    // A layout's own `fit` runs inside its animation frame and is skipped if the
    // tab is backgrounded or the container resized mid-run. Fitting explicitly
    // on layoutstop guarantees the graph ends up centred and fully in view.
    running.one('layoutstop', () => {
      const visible = cy.elements(':visible');
      if (visible.length > 0) cy.fit(visible, 40);
    });

    running.run();
  }, [layout, graph?.metadata.graphType]);

  /* --- Create the instance once --- */
  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: [],
      style: buildStylesheet(true),
      minZoom: 0.03,
      maxZoom: 4,
      wheelSensitivity: 0.25,
      boxSelectionEnabled: false,
    });
    cyRef.current = cy;

    const nodeOf = (target: cytoscape.NodeSingular): GraphNode =>
      target.data('raw') as GraphNode;

    cy.on('tap', 'node', (event) => {
      const node = event.target as cytoscape.NodeSingular;
      handlers.current.onSelectNode(nodeOf(node));
    });

    cy.on('dbltap', 'node', (event) => {
      const node = event.target as cytoscape.NodeSingular;
      const data = nodeOf(node);
      // Double-click opens the CFG - only meaningful for real functions.
      if (data.kind === 'function' && data.address) {
        handlers.current.onOpenFunction(data.address);
      }
    });

    cy.on('cxttap', 'node', (event) => {
      const node = event.target as cytoscape.NodeSingular;
      const data = nodeOf(node);
      if (event.originalEvent instanceof MouseEvent && event.originalEvent.shiftKey) {
        if (data.address) handlers.current.onExpandNode(data.address);
      } else {
        handlers.current.onHideNode(data.id);
      }
    });

    cy.on('tap', (event) => {
      if (event.target === cy) handlers.current.onSelectNode(null);
    });

    cy.on('mouseover', 'node', (event) => {
      const node = event.target as cytoscape.NodeSingular;
      const position = node.renderedPosition();
      setTooltip({ x: position.x, y: position.y, node: nodeOf(node) });
    });
    cy.on('mouseout', 'node', () => setTooltip(null));
    cy.on('pan zoom', () => setTooltip(null));

    // Keep Cytoscape's viewport in sync with the container. Without this the
    // canvas keeps its first measured size when the window or panels change.
    const observer = new ResizeObserver(() => {
      cy.resize();
    });
    observer.observe(containerRef.current);

    // A graph laid out while the tab was hidden can come back mis-fitted, since
    // the browser suspends the animation frames the layout relies on.
    const onVisible = (): void => {
      if (document.hidden) return;
      cy.resize();
      const visible = cy.elements(':visible');
      if (visible.length > 0) cy.fit(visible, 40);
    };
    document.addEventListener('visibilitychange', onVisible);

    return () => {
      document.removeEventListener('visibilitychange', onVisible);
      observer.disconnect();
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

  /* --- Publish imperative controls --- */
  useEffect(() => {
    onReady({
      fit: () => cyRef.current?.fit(cyRef.current.elements(':visible'), 40),
      focusNode: (nodeId: string) => {
        const cy = cyRef.current;
        if (!cy) return;
        const node = cy.getElementById(nodeId);
        if (node.empty()) return;
        cy.animate({ center: { eles: node }, zoom: Math.max(cy.zoom(), 1.1) }, { duration: 300 });
      },
      relayout: runLayout,
    });
  }, [onReady, runLayout]);

  /* --- Swap in a new graph --- */
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().remove();
    setTooltip(null);
    if (!graph || graph.nodes.length === 0) return;

    cy.add(toElements(graph, rebaseDelta));
    // Layout is deferred to the visibility effect so filtered nodes never
    // participate in the very first placement.
    //
    // Re-runs on `rebaseDelta` too (not just `graph`) - a full remove+re-add
    // and thus a relayout, but that only happens on the rare edges (a debug
    // session attaching/detaching), never mid-session/per-step, so the
    // one-time jump is an acceptable trade for correct addresses.
  }, [graph, rebaseDelta]);

  /* --- Apply filters, then lay out --- */
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !graph) return;

    cy.batch(() => {
      cy.nodes().forEach((node) => {
        node.toggleClass('filtered-out', !visibleNodeIds.has(node.id()));
      });
      cy.edges().forEach((edge) => {
        edge.toggleClass('filtered-out', !visibleEdgeIds.has(edge.id()));
      });
    });

    runLayout();
  }, [graph, visibleNodeIds, visibleEdgeIds, runLayout]);

  /* --- Label toggle rebuilds the stylesheet --- */
  useEffect(() => {
    cyRef.current?.style(buildStylesheet(showLabels));
  }, [showLabels]);

  /* --- Selection highlights the direct in/out neighbourhood --- */
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      cy.elements().removeClass('selected-node neighbour highlight-edge dimmed');

      if (!selectedNodeId) return;
      const node = cy.getElementById(selectedNodeId);
      if (node.empty()) return;

      const connectedEdges = node.connectedEdges(':visible');
      const neighbourhood = connectedEdges.connectedNodes();

      cy.elements(':visible').addClass('dimmed');
      node.removeClass('dimmed').addClass('selected-node');
      neighbourhood.removeClass('dimmed').addClass('neighbour');
      connectedEdges.removeClass('dimmed').addClass('highlight-edge');
    });
  }, [selectedNodeId, visibleNodeIds]);

  /* --- Debug session's current instruction, independent of click-selection --- */
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.batch(() => {
      cy.elements().removeClass('executing-node');
      if (!executingNodeId) return;
      const node = cy.getElementById(executingNodeId);
      if (node.empty()) return;
      node.addClass('executing-node');
    });
  }, [executingNodeId, visibleNodeIds]);

  /* --- Search marks matches without hiding anything --- */
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const needle = searchTerm.trim().toLowerCase();

    cy.batch(() => {
      cy.nodes().removeClass('search-hit');
      if (needle.length < 2) return;
      cy.nodes().forEach((node) => {
        const label = String(node.data('label') ?? '').toLowerCase();
        const address = String(node.data('address') ?? '').toLowerCase();
        if (label.includes(needle) || address.includes(needle)) {
          node.addClass('search-hit');
        }
      });
    });
  }, [searchTerm, graph]);

  const hasContent = graph !== null && graph.nodes.length > 0;
  const visibleCount = visibleNodeIds.size;

  return (
    <div className="graph-wrap">
      <div ref={containerRef} className="graph-canvas" />

      {!hasContent && (
        <div className="graph-overlay">
          <p>{emptyMessage}</p>
        </div>
      )}

      {hasContent && visibleCount === 0 && (
        <div className="graph-overlay">
          <p>Không có node nào khớp bộ lọc hiện tại.</p>
        </div>
      )}

      {tooltip && (
        <div
          className="graph-tooltip"
          style={{
            left: Math.min(tooltip.x + 14, (containerRef.current?.clientWidth ?? 800) - 310),
            top: tooltip.y + 14,
          }}
        >
          <div>
            <strong>
              {tooltip.node.kind === 'basic_block'
                ? displayAddress(tooltip.node.address, rebaseDelta)
                : tooltip.node.label}
            </strong>
          </div>
          {tooltip.node.address && (
            <div className="mono">{displayAddress(tooltip.node.address, rebaseDelta)}</div>
          )}
          <div className="mono">
            {tooltip.node.kind === 'basic_block'
              ? `${tooltip.node.metadata.instructionCount ?? 0} instruction`
              : `risk ${tooltip.node.metadata.riskScore ?? 0} · ` +
                `${tooltip.node.metadata.callerCount ?? 0} caller · ` +
                `${tooltip.node.metadata.calleeCount ?? 0} callee`}
          </div>
          {tooltip.node.metadata.module && (
            <div className="mono">{tooltip.node.metadata.module}</div>
          )}
        </div>
      )}
    </div>
  );
}
