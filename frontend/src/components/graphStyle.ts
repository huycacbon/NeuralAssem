/**
 * Cytoscape stylesheet and layout presets.
 *
 * Colours are read from the CSS custom properties defined in `styles/index.css`
 * at call time, so the graph follows the OS light/dark preference instead of
 * hard-coding values that would be unreadable in one of the two themes.
 *
 * Node *shape* encodes the same information as node colour (function = circle,
 * API = rounded rect, block = rect, string = diamond), so the graph is readable
 * without relying on colour perception.
 */

import type cytoscape from 'cytoscape';

import type { LayoutName } from '@/types/graph';

function cssVar(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value === '' ? fallback : value;
}

export function buildStylesheet(showLabels: boolean): cytoscape.StylesheetJson {
  const colors = {
    fn: cssVar('--node-function', '#4a7fd4'),
    entry: cssVar('--node-function-entry', '#14a06a'),
    api: cssVar('--node-api', '#a05fc4'),
    block: cssVar('--node-block', '#5b7186'),
    string: cssVar('--node-string', '#c08a2e'),
    text: cssVar('--text', '#1a1f29'),
    bg: cssVar('--bg', '#f6f7f9'),
    panel: cssVar('--bg-panel', '#ffffff'),
    edge: cssVar('--edge', '#97a3b3'),
    edgeTrue: cssVar('--edge-true', '#3f8f5f'),
    edgeFalse: cssVar('--edge-false', '#cc4444'),
    edgeCall: cssVar('--edge-call', '#4a7fd4'),
    riskMedium: cssVar('--risk-medium', '#c08a2e'),
    riskHigh: cssVar('--risk-high', '#cc4444'),
    accent: cssVar('--accent', '#2f6fd0'),
    executing: cssVar('--node-executing', '#1fb6c9'),
  };

  const labelBase: cytoscape.Css.Node = {
    label: showLabels ? 'data(label)' : '',
    color: colors.text,
    'font-size': 9,
    'font-family': 'ui-monospace, Consolas, monospace',
    'text-outline-width': 2,
    'text-outline-color': colors.bg,
    'text-outline-opacity': 0.85,
    'min-zoomed-font-size': 6,
  };

  return [
    {
      selector: 'node',
      style: {
        ...labelBase,
        'background-color': colors.fn,
        'border-color': colors.panel,
        'border-width': 1.5,
        width: 'data(size)',
        height: 'data(size)',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 3,
        'overlay-opacity': 0,
      },
    },

    /* --- Node kinds: shape + colour together --- */
    {
      selector: 'node[kind = "function"]',
      style: { shape: 'ellipse', 'background-color': colors.fn },
    },
    {
      selector: 'node[kind = "api"]',
      style: {
        shape: 'round-rectangle',
        'background-color': colors.api,
        // APIs are labels, not code: give them a wider, shorter footprint.
        width: 'data(size)',
        height: (node: cytoscape.NodeSingular) => Number(node.data('size')) * 0.62,
      },
    },
    {
      selector: 'node[kind = "basic_block"]',
      style: {
        shape: 'rectangle',
        'background-color': colors.block,
        'text-valign': 'center',
        'text-margin-y': 0,
        'font-size': 10,
        width: 'data(size)',
        height: (node: cytoscape.NodeSingular) => Number(node.data('size')) * 0.5,
      },
    },
    {
      selector: 'node[kind = "string"]',
      style: { shape: 'diamond', 'background-color': colors.string },
    },

    /* --- Entry point: double border + larger, per the spec --- */
    {
      selector: 'node[?isEntryPoint]',
      style: {
        'background-color': colors.entry,
        'border-color': colors.entry,
        'border-width': 3,
        'border-style': 'double',
        'font-size': 11,
        'font-weight': 'bold',
        'z-index': 30,
      },
    },

    /* --- Risk: border weight, not just colour --- */
    {
      selector: 'node[riskLevel = "medium"]',
      style: { 'border-width': 3, 'border-color': colors.riskMedium },
    },
    {
      selector: 'node[riskLevel = "high"]',
      style: { 'border-width': 5, 'border-color': colors.riskHigh, 'z-index': 25 },
    },

    /* --- Edges --- */
    {
      selector: 'edge',
      style: {
        width: 1.2,
        'line-color': colors.edge,
        'target-arrow-color': colors.edge,
        'target-arrow-shape': 'triangle',
        'arrow-scale': 0.85,
        'curve-style': 'bezier',
        opacity: 0.65,
        'font-size': 8,
        color: colors.text,
        'text-outline-width': 2,
        'text-outline-color': colors.bg,
      },
    },
    {
      selector: 'edge[kind = "CALL"]',
      style: { 'line-color': colors.edgeCall, 'target-arrow-color': colors.edgeCall },
    },
    {
      selector: 'edge[kind = "TRUE"]',
      style: {
        'line-color': colors.edgeTrue,
        'target-arrow-color': colors.edgeTrue,
        label: 'true',
        opacity: 0.9,
        width: 1.8,
      },
    },
    {
      selector: 'edge[kind = "FALSE"]',
      style: {
        'line-color': colors.edgeFalse,
        'target-arrow-color': colors.edgeFalse,
        label: 'false',
        opacity: 0.9,
        width: 1.8,
      },
    },
    {
      selector: 'edge[kind = "FALLTHROUGH"]',
      style: { 'line-style': 'dashed' },
    },
    {
      selector: 'edge[kind = "RETURN"]',
      style: { 'line-style': 'dotted', 'target-arrow-shape': 'vee' },
    },
    {
      // Repeated calls read as a heavier connector.
      selector: 'edge[callCount > 1]',
      style: { width: 2.4 },
    },

    /* --- Interaction states --- */
    {
      selector: '.selected-node',
      style: {
        'border-width': 5,
        'border-color': colors.accent,
        'border-style': 'solid',
        'z-index': 50,
      },
    },
    {
      selector: '.neighbour',
      style: { 'border-width': 3, 'border-color': colors.accent, 'z-index': 40 },
    },
    {
      selector: '.highlight-edge',
      style: { opacity: 1, width: 3, 'line-color': colors.accent, 'target-arrow-color': colors.accent, 'z-index': 40 },
    },
    {
      // Everything not in the highlighted neighbourhood fades but stays visible,
      // so context is preserved rather than destroyed.
      selector: '.dimmed',
      style: { opacity: 0.12 },
    },
    {
      // Debug session's current instruction - a distinct pulsing-style ring
      // (via z-index + colour, no actual animation) so it reads separately
      // from `.selected-node` even when both apply to the same node.
      selector: '.executing-node',
      style: {
        'border-width': 5,
        'border-color': colors.executing,
        'border-style': 'dashed',
        'z-index': 60,
      },
    },
    {
      selector: '.search-hit',
      style: { 'border-width': 4, 'border-color': colors.riskMedium, 'border-style': 'dashed' },
    },
    {
      selector: '.filtered-out',
      style: { display: 'none' },
    },
  ];
}

export interface LayoutOptionsInput {
  name: LayoutName;
  /** CFGs read top-to-bottom; call graphs get the force-directed "neural" look. */
  isCfg: boolean;
  nodeCount: number;
}

/**
 * Layout animation is driven by requestAnimationFrame, which browsers suspend in
 * a backgrounded tab - an animated layout started there never emits `layoutstop`
 * and therefore never fits. Animate only when the page is actually visible and
 * the graph is small enough for the animation to be pleasant rather than slow.
 */
function shouldAnimate(nodeCount: number): boolean {
  const visible = typeof document === 'undefined' || !document.hidden;
  return visible && nodeCount <= 300;
}

export function buildLayout({
  name,
  isCfg,
  nodeCount,
}: LayoutOptionsInput): cytoscape.LayoutOptions {
  if (name === 'hierarchical') {
    return {
      name: 'breadthfirst',
      directed: true,
      // Top-to-bottom by default for CFGs, which is how a disassembler shows them.
      spacingFactor: isCfg ? 1.35 : 1.1,
      padding: 30,
      avoidOverlap: true,
      grid: false,
      animate: shouldAnimate(nodeCount),
      animationDuration: 350,
      fit: true,
    } as cytoscape.LayoutOptions;
  }

  // "Neural network" look: force-directed, so hubs pull to the centre and
  // clusters separate on their own.
  return {
    name: 'fcose',
    quality: nodeCount > 400 ? 'draft' : 'default',
    randomize: true,
    animate: shouldAnimate(nodeCount),
    animationDuration: 500,
    fit: true,
    padding: 40,
    nodeSeparation: 90,
    idealEdgeLength: () => (nodeCount > 200 ? 60 : 95),
    nodeRepulsion: () => 8000,
    edgeElasticity: () => 0.42,
    gravity: 0.28,
    gravityRange: 3.2,
    numIter: nodeCount > 400 ? 1200 : 2500,
    tile: true,
    uniformNodeDimensions: false,
  } as unknown as cytoscape.LayoutOptions;
}
