/**
 * Graph filtering state and the pure predicate that applies it.
 *
 * Key rule from the spec: filtering NEVER mutates the source graph. The full
 * graph stays in state; this hook only computes the set of ids that should be
 * *visible*, and GraphViewer toggles Cytoscape display accordingly. That keeps
 * "unhide" free and lets edge filtering stay consistent with node filtering.
 */

import { useCallback, useMemo, useState } from 'react';

import type { Graph, GraphEdge, GraphNode } from '@/types/graph';

export interface GraphFilters {
  /** Free-text search over name, address, module and capability. */
  search: string;
  minRiskScore: number;
  hideApis: boolean;
  /** Hide functions angr could not name (`sub_401000`). */
  hideUnnamed: boolean;
  /** Show only functions that reference at least one string. */
  onlyWithStrings: boolean;
  /** Show only functions calling this specific API node id. */
  apiFilter: string | null;
  /** Show only nodes within N hops of the entry point (call graph only). */
  maxHops: number;
  showLabels: boolean;
}

export const DEFAULT_FILTERS: GraphFilters = {
  search: '',
  minRiskScore: 0,
  hideApis: false,
  hideUnnamed: false,
  onlyWithStrings: false,
  apiFilter: null,
  maxHops: 5,
  showLabels: true,
};

/** BFS hop distance from the entry-point node over the undirected graph. */
function computeHopDistances(graph: Graph): Map<string, number> {
  const distances = new Map<string, number>();
  const entry = graph.nodes.find((node) => node.metadata.isEntryPoint);
  if (!entry) return distances;

  const adjacency = new Map<string, string[]>();
  const link = (from: string, to: string): void => {
    const existing = adjacency.get(from);
    if (existing) existing.push(to);
    else adjacency.set(from, [to]);
  };
  for (const edge of graph.edges) {
    link(edge.source, edge.target);
    link(edge.target, edge.source);
  }

  distances.set(entry.id, 0);
  const queue: string[] = [entry.id];
  // Iterative BFS with a visited map - a cyclic call graph must terminate.
  while (queue.length > 0) {
    const current = queue.shift() as string;
    const distance = distances.get(current) ?? 0;
    for (const neighbour of adjacency.get(current) ?? []) {
      if (!distances.has(neighbour)) {
        distances.set(neighbour, distance + 1);
        queue.push(neighbour);
      }
    }
  }

  return distances;
}

function matchesSearch(node: GraphNode, needle: string): boolean {
  if (!needle) return true;
  const haystack = [
    node.label,
    node.address ?? '',
    node.metadata.module ?? '',
    node.metadata.capability ?? '',
  ]
    .join(' ')
    .toLowerCase();

  if (haystack.includes(needle)) return true;

  // Let "401000" match "0x401000" so users can paste bare addresses.
  const bare = needle.replace(/^0x/, '');
  return bare.length >= 3 && (node.address ?? '').toLowerCase().includes(bare);
}

export interface FilterResult {
  visibleNodeIds: Set<string>;
  visibleEdgeIds: Set<string>;
  hiddenCount: number;
}

export function applyFilters(
  graph: Graph,
  filters: GraphFilters,
  hiddenByUser: ReadonlySet<string>,
): FilterResult {
  const needle = filters.search.trim().toLowerCase();
  const distances = filters.maxHops < 5 ? computeHopDistances(graph) : null;

  // Which functions call the API selected in the "only callers of" filter.
  const callersOfApi = new Set<string>();
  if (filters.apiFilter) {
    for (const edge of graph.edges) {
      if (edge.target === filters.apiFilter) callersOfApi.add(edge.source);
    }
  }

  const visibleNodeIds = new Set<string>();
  for (const node of graph.nodes) {
    if (hiddenByUser.has(node.id)) continue;

    const isApi = node.kind === 'api';
    if (filters.hideApis && isApi) continue;
    if (filters.hideUnnamed && !isApi && node.metadata.isNamed === false) continue;
    if ((node.metadata.riskScore ?? 0) < filters.minRiskScore) continue;
    if (filters.onlyWithStrings && !isApi && !node.metadata.hasStrings) continue;
    if (!matchesSearch(node, needle)) continue;

    if (distances) {
      const distance = distances.get(node.id);
      if (distance === undefined || distance > filters.maxHops) continue;
    }

    if (filters.apiFilter) {
      const keep = node.id === filters.apiFilter || callersOfApi.has(node.id);
      if (!keep) continue;
    }

    visibleNodeIds.add(node.id);
  }

  // An edge survives only if both endpoints do - otherwise Cytoscape would
  // render a dangling connector.
  const visibleEdgeIds = new Set<string>();
  for (const edge of graph.edges) {
    if (visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target)) {
      visibleEdgeIds.add(edge.id);
    }
  }

  return {
    visibleNodeIds,
    visibleEdgeIds,
    hiddenCount: graph.nodes.length - visibleNodeIds.size,
  };
}

export function useGraphFilters(graph: Graph | null) {
  const [filters, setFilters] = useState<GraphFilters>(DEFAULT_FILTERS);
  const [hiddenByUser, setHiddenByUser] = useState<ReadonlySet<string>>(new Set());

  const update = useCallback(<K extends keyof GraphFilters>(key: K, value: GraphFilters[K]) => {
    setFilters((previous) => ({ ...previous, [key]: value }));
  }, []);

  const reset = useCallback(() => {
    setFilters(DEFAULT_FILTERS);
    setHiddenByUser(new Set());
  }, []);

  const hideNode = useCallback((nodeId: string) => {
    setHiddenByUser((previous) => new Set(previous).add(nodeId));
  }, []);

  const unhideAll = useCallback(() => setHiddenByUser(new Set()), []);

  const result = useMemo<FilterResult>(() => {
    if (!graph) {
      return { visibleNodeIds: new Set(), visibleEdgeIds: new Set(), hiddenCount: 0 };
    }
    return applyFilters(graph, filters, hiddenByUser);
  }, [graph, filters, hiddenByUser]);

  /** APIs present in the graph, for the "only callers of" dropdown. */
  const availableApis = useMemo(() => {
    if (!graph) return [] as GraphNode[];
    return graph.nodes
      .filter((node) => node.kind === 'api')
      .sort((a, b) => a.label.localeCompare(b.label));
  }, [graph]);

  const isFiltered = useMemo(() => {
    return (
      filters.search !== '' ||
      filters.minRiskScore > 0 ||
      filters.hideApis ||
      filters.hideUnnamed ||
      filters.onlyWithStrings ||
      filters.apiFilter !== null ||
      filters.maxHops < 5 ||
      hiddenByUser.size > 0
    );
  }, [filters, hiddenByUser]);

  return {
    filters,
    update,
    reset,
    hideNode,
    unhideAll,
    hiddenByUser,
    availableApis,
    isFiltered,
    ...result,
  };
}

export type { GraphEdge };
