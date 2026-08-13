/**
 * Client for the dynamic analysis (Debug) API.
 *
 * Same dual-transport shape as `services/analysisApi.ts` (web: REST over
 * `fetch` against `app.dynamic.api`; desktop: `window.pywebview.api.debug_*`
 * against the matching methods on `app.desktop_bridge.DesktopApi`) - but
 * kept as its own self-contained file rather than importing analysisApi's
 * private helpers, mirroring the backend's own `app/dynamic/api.py`, which
 * duplicates its `_error()` helper instead of importing `app/api/analysis.py`'s.
 * The dynamic module stays a separately-readable unit end to end.
 */

import { ApiError } from '@/services/analysisApi';
import type {
  DebugBreakpoint,
  DebugSessionState,
  LiveDisassemblyResponse,
  MemoryDumpResponse,
  RiskCheckResponse,
  StepMode,
} from '@/types/debug';
import type { ApiErrorDetail } from '@/types/graph';

const API_BASE_URL: string = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '';

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

/** Shape of `window.pywebview.api`'s `debug_*` methods - one per
 * `DesktopApi.debug_*` method in `backend/app/desktop_bridge.py`. */
interface DesktopDebugBridge {
  debug_risk_check(analysisId: string): Promise<unknown>;
  debug_connect(
    analysisId: string,
    host: string,
    port: number,
    processId: number | null,
    processName: string | null,
  ): Promise<unknown>;
  debug_launch_local(analysisId: string, commandLine: string): Promise<unknown>;
  debug_launch_local_upload(
    analysisId: string,
    fileBase64: string,
    filename: string | null,
  ): Promise<unknown>;
  debug_get_state(sessionId: string): Promise<unknown>;
  debug_set_register(sessionId: string, name: string, value: string): Promise<unknown>;
  debug_disassemble(sessionId: string, count: number): Promise<unknown>;
  debug_dump_memory(sessionId: string, address: string, size: number): Promise<unknown>;
  debug_set_breakpoint(sessionId: string, staticAddress: string): Promise<unknown>;
  debug_remove_breakpoint(sessionId: string, breakpointId: number): Promise<unknown>;
  debug_step(sessionId: string, mode: StepMode): Promise<unknown>;
  debug_continue(sessionId: string): Promise<unknown>;
  debug_disconnect(sessionId: string): Promise<unknown>;
}

// `analysisApi.ts` already augments `Window.pywebview` globally, typed for
// *its own* bridge methods - redeclaring the same global member here with a
// different inline type would conflict (TS requires identical merged
// declarations). Casting at the point of use instead keeps this file
// self-contained without fighting that merge.
function pywebviewWindow(): { pywebview?: { api?: DesktopDebugBridge } } {
  return window as unknown as { pywebview?: { api?: DesktopDebugBridge } };
}

function isDesktop(): boolean {
  return typeof window !== 'undefined' && 'pywebview' in window;
}

let bridgeReady: Promise<DesktopDebugBridge> | null = null;

/** Resolves once `window.pywebview.api` exists - see analysisApi.ts's
 * `getBridge` for the same pattern and the pywebview docs link. */
function getBridge(): Promise<DesktopDebugBridge> {
  const existing = pywebviewWindow().pywebview?.api;
  if (existing) {
    return Promise.resolve(existing);
  }
  if (!bridgeReady) {
    bridgeReady = new Promise((resolve) => {
      window.addEventListener(
        'pywebviewready',
        () => resolve(pywebviewWindow().pywebview!.api as DesktopDebugBridge),
        { once: true },
      );
    });
  }
  return bridgeReady;
}

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
    // 204/empty-body responses (delete endpoints) still parse fine as JSON
    // here because every dynamic endpoint returns a small JSON object, even
    // `{"deleted": true}` - never a true empty body.
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
    { code: `HTTP_${response.status}`, message: `Backend trả về lỗi ${response.status}`, details: null },
    response.status,
  );
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  try {
    return await handle<T>(
      await fetch(`${API_BASE_URL}${path}`, {
        headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
        ...init,
      }),
    );
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

/** Reads a `File` as base64 for the desktop transport - a small local copy
 * of `analysisApi.ts`'s own `fileToBase64` (not exported from there), kept
 * here to preserve this file's self-contained convention (see module
 * docstring). */
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

export const debugApi = {
  /** Feeds the mandatory warning modal's copy - never gates whether the
   * modal shows (it always does, once per page session). */
  async riskCheck(analysisId: string): Promise<RiskCheckResponse> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).debug_risk_check(analysisId));
    }
    return request(`/api/dynamic/risk-check/${analysisId}`);
  },

  /**
   * Connect to a `dbgsrv` the user already has running in their own VM and
   * attach. `host`/`port` come straight from the connect form; nothing here
   * is defaulted or guessed.
   */
  async connect(
    analysisId: string,
    host: string,
    port: number,
    processId: number | null = null,
    processName: string | null = null,
  ): Promise<DebugSessionState> {
    if (isDesktop()) {
      return callBridge(async () =>
        (await getBridge()).debug_connect(analysisId, host, port, processId, processName),
      );
    }
    return request('/api/dynamic/sessions', {
      method: 'POST',
      body: JSON.stringify({ analysisId, host, port, processId, processName }),
    });
  },

  /**
   * Local-launch: makes the app itself execute `commandLine` directly on
   * this machine and attach from the entry point - no `dbgsrv`, no VM. This
   * is the one call in this whole file that causes real process execution;
   * see `backend/app/dynamic/debug_bridge/client.py`'s
   * `create_and_attach_local` docstring for the full rationale. The caller
   * (`DebugConnectModal`) is responsible for having already shown its own
   * local-launch-specific warning - every time, not once-per-session -
   * before calling this.
   */
  async launchLocal(analysisId: string, commandLine: string): Promise<DebugSessionState> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).debug_launch_local(analysisId, commandLine));
    }
    return request('/api/dynamic/sessions/local', {
      method: 'POST',
      body: JSON.stringify({ analysisId, commandLine }),
    });
  },

  /**
   * Local-launch from the exact file the frontend still holds in memory
   * from the original upload (the static analyzer's own copy is already
   * deleted by the time Debug is clickable - see
   * `backend/app/dynamic/local_upload.py`'s module docstring). Re-sends
   * those same bytes fresh; the backend stages its own, separate temp copy
   * and executes that. Same execution caveat as `launchLocal` above, with a
   * larger consequence: this is the one call that turns "upload a sample"
   * directly into "the app can execute it" with no manual step left at all.
   */
  async launchLocalFromUpload(analysisId: string, file: File): Promise<DebugSessionState> {
    if (isDesktop()) {
      const base64 = await fileToBase64(file);
      return callBridge(async () =>
        (await getBridge()).debug_launch_local_upload(analysisId, base64, file.name),
      );
    }

    const form = new FormData();
    form.append('analysis_id', analysisId);
    form.append('file', file);

    try {
      const response = await fetch(`${API_BASE_URL}/api/dynamic/sessions/local/upload`, {
        method: 'POST',
        body: form,
      });
      return await handle<DebugSessionState>(response);
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
  },

  async getState(sessionId: string): Promise<DebugSessionState> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).debug_get_state(sessionId));
    }
    return request(`/api/dynamic/sessions/${sessionId}/state`);
  },

  /**
   * Live disassembly around the debugger's current runtime address - the
   * assembly view's fallback for when the PC is outside the one module the
   * static analyzer covers (see `backend/app/dynamic/session.py`'s
   * `disassemble_current` docstring). Fetched on demand, not part of
   * `DebugSessionState`/`getState`.
   */
  async getLiveDisassembly(sessionId: string, count = 40): Promise<LiveDisassemblyResponse> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).debug_disassemble(sessionId, count));
    }
    return request(`/api/dynamic/sessions/${sessionId}/disassembly?count=${count}`);
  },

  /**
   * Raw memory dump at a *runtime* address, the "Dump"/`db` capability
   * every other debugger has (x64dbg's Dump tab, WinDbg's `db`) - see
   * `backend/app/dynamic/session.py`'s `dump_memory` docstring. `size` is
   * clamped server-side (1-4096) regardless of what is passed here.
   */
  async dumpMemory(sessionId: string, address: string, size = 256): Promise<MemoryDumpResponse> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).debug_dump_memory(sessionId, address, size));
    }
    return request(
      `/api/dynamic/sessions/${sessionId}/memory?address=${encodeURIComponent(address)}&size=${size}`,
    );
  },

  /**
   * Write a register on the live engine context and return the updated
   * session state - a subsequent step/continue call naturally uses the
   * edited value (see `backend/app/dynamic/session.py`'s `set_register`
   * docstring), no separate "apply" step needed beyond this call itself.
   */
  async setRegister(sessionId: string, name: string, value: string): Promise<DebugSessionState> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).debug_set_register(sessionId, name, value));
    }
    return request(`/api/dynamic/sessions/${sessionId}/registers/${encodeURIComponent(name)}`, {
      method: 'POST',
      body: JSON.stringify({ value }),
    });
  },

  async setBreakpoint(sessionId: string, staticAddress: string): Promise<DebugBreakpoint> {
    if (isDesktop()) {
      return callBridge(async () =>
        (await getBridge()).debug_set_breakpoint(sessionId, staticAddress),
      );
    }
    return request(`/api/dynamic/sessions/${sessionId}/breakpoints`, {
      method: 'POST',
      body: JSON.stringify({ staticAddress }),
    });
  },

  async removeBreakpoint(sessionId: string, breakpointId: number): Promise<void> {
    if (isDesktop()) {
      await callBridge(async () =>
        (await getBridge()).debug_remove_breakpoint(sessionId, breakpointId),
      );
      return;
    }
    await request(`/api/dynamic/sessions/${sessionId}/breakpoints/${breakpointId}`, {
      method: 'DELETE',
    });
  },

  async step(sessionId: string, mode: StepMode): Promise<DebugSessionState> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).debug_step(sessionId, mode));
    }
    return request(`/api/dynamic/sessions/${sessionId}/step`, {
      method: 'POST',
      body: JSON.stringify({ mode }),
    });
  },

  /** Blocks (server-side) until a breakpoint hits, the process exits, or the
   * backend's own continue-timeout elapses - the caller just awaits it. */
  async continueExecution(sessionId: string): Promise<DebugSessionState> {
    if (isDesktop()) {
      return callBridge(async () => (await getBridge()).debug_continue(sessionId));
    }
    return request(`/api/dynamic/sessions/${sessionId}/continue`, { method: 'POST' });
  },

  async disconnect(sessionId: string): Promise<void> {
    if (isDesktop()) {
      await callBridge(async () => (await getBridge()).debug_disconnect(sessionId));
      return;
    }
    await request(`/api/dynamic/sessions/${sessionId}`, { method: 'DELETE' });
  },
};
