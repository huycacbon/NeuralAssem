/**
 * Client for the analysis backend - two transports behind one interface.
 *
 * - **Web** (`npm run dev` / a hosted build): REST over `fetch`/`XMLHttpRequest`
 *   against the FastAPI backend, same-origin (Vite's dev proxy in dev, the
 *   backend's own static-file mount in a combined build).
 * - **Desktop** (the packaged pywebview app): every call below goes through
 *   `window.pywebview.api.*` instead - an in-process Python call, no HTTP,
 *   no socket, no server. See `app.desktop_bridge` on the Python side.
 *
 * Which transport is used is decided per call by `isDesktop()`, so the rest
 * of the app (`App.tsx`, components) never has to know which build it is
 * running in - it just calls `analysisApi.xxx(...)` either way.
 */

import type {
  AnalysisResponse,
  ApiErrorDetail,
  ExtractedString,
  FunctionDetail,
  FunctionListResponse,
  Graph,
  ImportedApi,
} from '@/types/graph';
import { formatHexAddress, parseHexAddress } from '@/utils/addressDisplay';

const API_BASE_URL: string = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '';

/** Error carrying the backend's structured `{error: {...}}` envelope. */
export class ApiError extends Error {
  readonly code: string;
  readonly details: string | null;
  readonly status: number;

  constructor(detail: ApiErrorDetail, status: number) {
    super(detail.message);
    this.name = 'ApiError';
    this.code = detail.code;
    this.details = detail.details;
    this.status = status;
  }
}

/** Result of `analysisApi.decompileAll` - see its docstring. */
export interface DecompileAllResult {
  total: number;
  alreadyAvailable: number;
  decompiled: number;
  failed: number;
  skippedNotApplicable: number;
}

function isErrorEnvelope(value: unknown): value is { error: ApiErrorDetail } {
  if (typeof value !== 'object' || value === null || !('error' in value)) {
    return false;
  }
  const candidate = (value as { error: unknown }).error;
  return (
    typeof candidate === 'object' &&
    candidate !== null &&
    'code' in candidate &&
    'message' in candidate
  );
}

// -- desktop (pywebview) transport ------------------------------------------

/** Shape of `window.pywebview.api` - one method per `DesktopApi` method in
 * `backend/app/desktop_bridge.py`. Args are positional, matching pywebview's
 * JS-call-to-Python-method mapping. */
interface DesktopBridge {
  health(): Promise<unknown>;
  analyze(fileBase64: string, filename: string | null): Promise<unknown>;
  get_analysis(analysisId: string): Promise<unknown>;
  list_functions(
    analysisId: string,
    search: string | null,
    limit: number,
    offset: number,
    minRiskScore: number,
  ): Promise<unknown>;
  get_function(analysisId: string, address: string): Promise<unknown>;
  decompile_function(analysisId: string, address: string): Promise<unknown>;
  get_function_cfg(analysisId: string, address: string): Promise<unknown>;
  export_function_markdown(analysisId: string, address: string): Promise<unknown>;
  get_call_graph(
    analysisId: string,
    depth: number,
    maxNodes: number,
    includeApis: boolean,
  ): Promise<unknown>;
  get_api_graph(analysisId: string, maxNodes: number, capability: string | null): Promise<unknown>;
  get_imports(analysisId: string): Promise<unknown>;
  get_strings(analysisId: string, limit: number, search: string | null): Promise<unknown>;
  expand(analysisId: string, address: string, maxNodes: number): Promise<unknown>;
  export_markdown(analysisId: string): Promise<unknown>;
  decompile_all_functions(analysisId: string): Promise<unknown>;
  export_markdown_full(analysisId: string): Promise<unknown>;
  delete_analysis(analysisId: string): Promise<unknown>;
}

declare global {
  interface Window {
    pywebview?: { api?: DesktopBridge };
  }
}

function isDesktop(): boolean {
  return typeof window !== 'undefined' && 'pywebview' in window;
}

let bridgeReady: Promise<DesktopBridge> | null = null;

/** Resolves once `window.pywebview.api` exists. pywebview injects it
 * asynchronously and fires `pywebviewready` right after - see
 * https://pywebview.flowrl.com/guide/interdomain.html. */
function getBridge(): Promise<DesktopBridge> {
  if (window.pywebview?.api) {
    return Promise.resolve(window.pywebview.api);
  }
  if (!bridgeReady) {
    bridgeReady = new Promise((resolve) => {
      window.addEventListener(
        'pywebviewready',
        () => resolve(window.pywebview!.api as DesktopBridge),
        { once: true },
      );
    });
  }
  return bridgeReady;
}

/** Reads a `File` as base64 without ever writing it to disk on the JS side -
 * `window.pywebview.api.analyze` decodes it straight back to bytes. */
function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error('Không đọc được file'));
    reader.onload = () => {
      const result = reader.result as string; // "data:<mime>;base64,<payload>"
      const comma = result.indexOf(',');
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    reader.readAsDataURL(file);
  });
}

/** Runs a bridge call and applies the same error-envelope handling as the
 * HTTP path's `handle()`, so callers get an `ApiError` either way. */
async function callBridge<T>(call: () => Promise<unknown>): Promise<T> {
  let payload: unknown;
  try {
    payload = await call();
  } catch (error) {
    throw new ApiError(
      {
        code: 'BRIDGE_ERROR',
        message: 'Lỗi giao tiếp nội bộ với backend',
        details: error instanceof Error ? error.message : String(error),
      },
      0,
    );
  }

  if (isErrorEnvelope(payload)) {
    throw new ApiError(payload.error, 0);
  }
  return payload as T;
}

// -- web (HTTP) transport -----------------------------------------------------

async function handle<T>(response: Response): Promise<T> {
  if (response.ok) {
    return (await response.json()) as T;
  }

  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    // Body was not JSON (proxy error page, connection reset mid-response).
  }

  if (isErrorEnvelope(payload)) {
    throw new ApiError(payload.error, response.status);
  }

  throw new ApiError(
    {
      code: `HTTP_${response.status}`,
      message: `Backend trả về lỗi ${response.status}`,
      details: null,
    },
    response.status,
  );
}

async function get<T>(path: string, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
  // The base argument makes this work whether API_BASE_URL is relative
  // (same-origin, the normal case) or a full origin override - `new URL`
  // ignores the base whenever the first argument is already absolute.
  const url = new URL(`${API_BASE_URL}${path}`, window.location.origin);
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== '') {
        url.searchParams.set(key, String(value));
      }
    }
  }

  try {
    return await handle<T>(await fetch(url.toString()));
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      {
        code: 'NETWORK_ERROR',
        message: 'Không kết nối được tới backend',
        details: `Kiểm tra backend đang chạy tại ${API_BASE_URL || window.location.origin}`,
      },
      0,
    );
  }
}

/**
 * The Markdown export is built server-side from the static `AnalysisRecord`,
 * so every address in it (`export_service.py`'s `` `{fn.address}` `` /
 * `` `{file.entry_point}` `` fields) is a *static* address - same coordinate
 * space as the graph/function list before any debug session exists (see
 * `utils/addressDisplay.ts`'s module docstring for the full static-vs-runtime
 * picture). When the export happens while a debug session is attached, that
 * static address is no longer "where the code actually is" if the module got
 * rebased (ASLR) - the caller passes the session's `rebaseDelta` so the
 * exported document reflects the real, running address instead of the
 * theoretical preferred-base one.
 *
 * Every address the exporter emits is wrapped in backticks as a `0x...` hex
 * literal (entry point, risk-table rows, function-detail headers) - nothing
 * else in the document matches that shape (the SHA-256 is backtick-wrapped
 * too, but has no `0x` prefix), so a scoped regex replace is safe without
 * having to reparse the whole document server-side.
 */
function rebaseExportedAddresses(content: string, rebaseDelta: number | null | undefined): string {
  if (!rebaseDelta) return content;
  return content.replace(/`(0x[0-9a-fA-F]+)`/g, (match, hex: string) => {
    const parsed = parseHexAddress(hex);
    if (parsed === null) return match;
    return `\`${formatHexAddress(parsed + rebaseDelta)}\``;
  });
}

export const analysisApi = {
  baseUrl: API_BASE_URL,

  async health(): Promise<{ status: string; angrAvailable: boolean; maxUploadMb: number }> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).health());
    }
    return get('/api/health');
  },

  /**
   * Upload and analyse a PE file.
   *
   * Web: uses XMLHttpRequest rather than fetch for real upload progress,
   * which matters for a 100 MB cap. Desktop: the file never leaves the
   * machine or even crosses a socket - it is base64-encoded in the renderer
   * and decoded straight back to bytes on the Python side of the bridge, so
   * there is no meaningful "upload" step to report progress for; the
   * progress callback just jumps to 100% once the local read finishes.
   */
  async analyze(
    file: File,
    onUploadProgress?: (percent: number) => void,
  ): Promise<AnalysisResponse> {
    if (isDesktop()) {
      onUploadProgress?.(0);
      const base64 = await fileToBase64(file);
      onUploadProgress?.(100);
      return callBridge(async () => (await getBridge()).analyze(base64, file.name));
    }

    const form = new FormData();
    form.append('file', file);

    return new Promise<AnalysisResponse>((resolve, reject) => {
      const request = new XMLHttpRequest();
      request.open('POST', `${API_BASE_URL}/api/analysis`);
      request.responseType = 'text';

      request.upload.onprogress = (event) => {
        if (event.lengthComputable && onUploadProgress) {
          onUploadProgress(Math.round((event.loaded / event.total) * 100));
        }
      };

      request.onload = () => {
        let payload: unknown = null;
        try {
          payload = JSON.parse(request.responseText) as unknown;
        } catch {
          payload = null;
        }

        if (request.status >= 200 && request.status < 300 && payload !== null) {
          resolve(payload as AnalysisResponse);
          return;
        }

        if (isErrorEnvelope(payload)) {
          reject(new ApiError(payload.error, request.status));
          return;
        }

        reject(
          new ApiError(
            {
              code: 'ANALYSIS_FAILED',
              message: 'Phân tích thất bại',
              details: `HTTP ${request.status}`,
            },
            request.status,
          ),
        );
      };

      request.onerror = () =>
        reject(
          new ApiError(
            {
              code: 'NETWORK_ERROR',
              message: 'Không kết nối được tới backend',
              details: `Kiểm tra backend đang chạy tại ${API_BASE_URL || window.location.origin}`,
            },
            0,
          ),
        );

      request.onabort = () =>
        reject(
          new ApiError(
            { code: 'UPLOAD_ABORTED', message: 'Upload bị hủy', details: null },
            0,
          ),
        );

      request.send(form);
    });
  },

  async listFunctions(
    analysisId: string,
    options: { search?: string; limit?: number; offset?: number; minRiskScore?: number } = {},
  ): Promise<FunctionListResponse> {
    const limit = options.limit ?? 500;
    const offset = options.offset ?? 0;
    const minRiskScore = options.minRiskScore ?? 0;

    if (isDesktop()) {
      return callBridge(async () =>
        (await getBridge()).list_functions(analysisId, options.search ?? null, limit, offset, minRiskScore),
      );
    }
    return get(`/api/analysis/${analysisId}/functions`, {
      search: options.search,
      limit,
      offset,
      minRiskScore,
    });
  },

  async getFunction(analysisId: string, address: string): Promise<FunctionDetail> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).get_function(analysisId, address));
    }
    return get(`/api/analysis/${analysisId}/functions/${address}`);
  },

  async getFunctionCfg(analysisId: string, address: string): Promise<Graph> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).get_function_cfg(analysisId, address));
    }
    return get(`/api/analysis/${analysisId}/functions/${address}/cfg`);
  },

  /**
   * Decompile one function on demand (angr's decompiler, best-effort).
   * A no-op on the backend if pseudocode is already available - safe to call
   * again without worrying about re-triggering work.
   */
  async decompileFunction(analysisId: string, address: string): Promise<FunctionDetail> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).decompile_function(analysisId, address));
    }
    const response = await fetch(
      `${API_BASE_URL}/api/analysis/${analysisId}/functions/${address}/decompile`,
      { method: 'POST' },
    );
    return handle<FunctionDetail>(response);
  },

  /**
   * Compact Markdown for exactly one function - full disassembly and
   * pseudocode (if available), not risk-filtered like `exportMarkdown`/
   * `exportMarkdownFull`. Same `{filename, content}` + `rebaseDelta`
   * convention as those two - see `exportMarkdown`'s docstring.
   */
  async exportFunctionMarkdown(
    analysisId: string,
    address: string,
    rebaseDelta?: number | null,
  ): Promise<{ filename: string; content: string }> {
    if (isDesktop()) {
      const result = await callBridge<{ filename: string; content: string }>(async () =>
        (await getBridge()).export_function_markdown(analysisId, address),
      );
      return { ...result, content: rebaseExportedAddresses(result.content, rebaseDelta) };
    }
    let response: Response;
    try {
      response = await fetch(
        `${API_BASE_URL}/api/analysis/${analysisId}/functions/${address}/export.md`,
      );
    } catch (error) {
      throw new ApiError(
        {
          code: 'NETWORK_ERROR',
          message: 'Không kết nối được tới backend',
          details: `Kiểm tra backend đang chạy tại ${API_BASE_URL || window.location.origin}`,
        },
        0,
      );
    }
    if (!response.ok) {
      await handle(response); // throws the structured ApiError
    }
    const content = await response.text();
    return {
      filename: `function-${address.replace(/^0x/i, '')}.md`,
      content: rebaseExportedAddresses(content, rebaseDelta),
    };
  },

  async getCallGraph(
    analysisId: string,
    options: { depth?: number; maxNodes?: number; includeApis?: boolean } = {},
  ): Promise<Graph> {
    const depth = options.depth ?? 2;
    const maxNodes = options.maxNodes ?? 500;
    const includeApis = options.includeApis ?? true;

    if (isDesktop()) {
      return callBridge(async () =>
        (await getBridge()).get_call_graph(analysisId, depth, maxNodes, includeApis),
      );
    }
    return get(`/api/analysis/${analysisId}/call-graph`, {
      depth: options.depth,
      maxNodes: options.maxNodes,
      includeApis: options.includeApis,
    });
  },

  async getApiGraph(
    analysisId: string,
    options: { maxNodes?: number; capability?: string } = {},
  ): Promise<Graph> {
    const maxNodes = options.maxNodes ?? 500;

    if (isDesktop()) {
      return callBridge(async () =>
        (await getBridge()).get_api_graph(analysisId, maxNodes, options.capability ?? null),
      );
    }
    return get(`/api/analysis/${analysisId}/api-graph`, {
      maxNodes: options.maxNodes,
      capability: options.capability,
    });
  },

  async getImports(analysisId: string): Promise<ImportedApi[]> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).get_imports(analysisId));
    }
    return get(`/api/analysis/${analysisId}/imports`);
  },

  async getStrings(
    analysisId: string,
    options: { limit?: number; search?: string } = {},
  ): Promise<ExtractedString[]> {
    const limit = options.limit ?? 500;

    if (isDesktop()) {
      return callBridge(async () =>
        (await getBridge()).get_strings(analysisId, limit, options.search ?? null),
      );
    }
    return get(`/api/analysis/${analysisId}/strings`, {
      limit,
      search: options.search,
    });
  },

  async expand(analysisId: string, address: string, maxNodes = 60): Promise<Graph> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).expand(analysisId, address, maxNodes));
    }
    return get(`/api/analysis/${analysisId}/expand/${address}`, { maxNodes });
  },

  /**
   * Compact Markdown export (see root README - built for pasting into an LLM
   * chat or handing to a colleague, not a raw data dump). Returns the content
   * directly rather than a URL, so the caller builds a `Blob` + object URL to
   * trigger the download - that works the same whether the content came over
   * HTTP or straight from the bridge.
   *
   * `rebaseDelta` is the active debug session's `moduleLoadBase -
   * preferredImageBase` (from `utils/addressDisplay.ts`'s
   * `computeRebaseDelta`), or `null`/omitted with no session attached. When
   * set, every address in the exported document is rewritten to the real
   * runtime address instead of the static one the backend computed - see
   * `rebaseExportedAddresses` above.
   */
  async exportMarkdown(
    analysisId: string,
    rebaseDelta?: number | null,
  ): Promise<{ filename: string; content: string }> {
    if (isDesktop()) {
      const result = await callBridge<{ filename: string; content: string }>(async () =>
        (await getBridge()).export_markdown(analysisId),
      );
      return { ...result, content: rebaseExportedAddresses(result.content, rebaseDelta) };
    }
    // Unlike `get()`, this needs the raw Response (for `.text()`, not
    // `.json()`), so it can't reuse that helper directly - but it still needs
    // the same network-error wrapping `get()` gives every other endpoint.
    // Without this try/catch, a failed `fetch` (backend unreachable, CORS
    // block, offline) throws a plain TypeError instead of an `ApiError`, and
    // every caller in this app only shows a banner for `instanceof ApiError`
    // - so the export button would silently do nothing on any network hiccup.
    let response: Response;
    try {
      response = await fetch(`${API_BASE_URL}/api/analysis/${analysisId}/export.md`);
    } catch (error) {
      throw new ApiError(
        {
          code: 'NETWORK_ERROR',
          message: 'Không kết nối được tới backend',
          details: `Kiểm tra backend đang chạy tại ${API_BASE_URL || window.location.origin}`,
        },
        0,
      );
    }
    if (!response.ok) {
      await handle(response); // throws the structured ApiError
    }
    const content = await response.text();
    return {
      filename: `analysis-${analysisId.slice(0, 8)}.md`,
      content: rebaseExportedAddresses(content, rebaseDelta),
    };
  },

  /**
   * Decompile every function that still lacks pseudocode, best-effort, no
   * count/time budget - unlike the eager pass at analysis time, this exists
   * specifically to prepare for `exportMarkdownFull`. Can take from seconds
   * to several minutes depending on the binary; callers are expected to show
   * their own loading state around this (see `App.tsx`'s `handleExportFull`).
   */
  async decompileAll(analysisId: string): Promise<DecompileAllResult> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).decompile_all_functions(analysisId));
    }
    const response = await fetch(
      `${API_BASE_URL}/api/analysis/${analysisId}/decompile-all`,
      { method: 'POST' },
    );
    return handle<DecompileAllResult>(response);
  },

  /**
   * Same report as `exportMarkdown`, except the Function Detail section
   * covers every function that currently has pseudocode, not a risk-curated
   * top-25 - the "export everything" counterpart. Does not decompile
   * anything itself; call `decompileAll` first to fill in as much of the
   * binary as possible. Same `rebaseDelta` handling as `exportMarkdown`.
   */
  async exportMarkdownFull(
    analysisId: string,
    rebaseDelta?: number | null,
  ): Promise<{ filename: string; content: string }> {
    if (isDesktop()) {
      const result = await callBridge<{ filename: string; content: string }>(async () =>
        (await getBridge()).export_markdown_full(analysisId),
      );
      return { ...result, content: rebaseExportedAddresses(result.content, rebaseDelta) };
    }
    let response: Response;
    try {
      response = await fetch(`${API_BASE_URL}/api/analysis/${analysisId}/export-full.md`);
    } catch (error) {
      throw new ApiError(
        {
          code: 'NETWORK_ERROR',
          message: 'Không kết nối được tới backend',
          details: `Kiểm tra backend đang chạy tại ${API_BASE_URL || window.location.origin}`,
        },
        0,
      );
    }
    if (!response.ok) {
      await handle(response); // throws the structured ApiError
    }
    const content = await response.text();
    return {
      filename: `analysis-${analysisId.slice(0, 8)}-full.md`,
      content: rebaseExportedAddresses(content, rebaseDelta),
    };
  },
};
