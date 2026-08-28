/**
 * Owns one debug session's client-side state: local-launch/breakpoint/step/
 * continue/disconnect, wrapping `services/debugApi`. Mirrors the rest of the
 * app's convention (plain `useState`, no context/store) - state lives here,
 * rendering lives in `DebugPanel`/`DebugConnectModal`, wiring lives in
 * `App.tsx`.
 */

import { useCallback, useState } from 'react';

import { ApiError } from '@/services/analysisApi';
import { debugApi } from '@/services/debugApi';
import type { DebugSessionState, StepMode } from '@/types/debug';

export interface UseDebugSessionResult {
  session: DebugSessionState | null;
  loading: boolean;
  error: string | null;
  /** Local-launch: the app itself executes `commandLine` on this machine -
   *  see `debugApi.launchLocal`'s docstring for the full rationale. Returns
   *  the attached session's state on success, or `null` on failure (the
   *  error is also captured in `.error` either way) - callers that need to
   *  know whether to e.g. close the connect modal check this return value
   *  rather than reading `.session` right after awaiting, which can still
   *  reflect the pre-update render's stale closure. */
  launchLocal: (analysisId: string, commandLine: string) => Promise<DebugSessionState | null>;
  /** Local-launch from the exact file still held in memory from the
   *  original upload - see `debugApi.launchLocalFromUpload`'s docstring.
   *  Same success/failure return convention as `launchLocal`. */
  launchLocalFromUpload: (analysisId: string, file: File) => Promise<DebugSessionState | null>;
  /** Write a register, then use the returned (already up to date) session
   *  state directly - unlike `setBreakpoint`/`removeBreakpoint`, the write
   *  endpoint itself returns the full snapshot, so no separate `getState`
   *  round trip is needed here. */
  setRegister: (name: string, value: string) => Promise<void>;
  setBreakpoint: (staticAddress: string) => Promise<void>;
  /** For an address outside the sample's own module (e.g. an ntdll row from
   *  the live-disassembly fallback) - see `debugApi.setRuntimeBreakpoint`'s
   *  docstring for why this must not go through `setBreakpoint`. */
  setRuntimeBreakpoint: (runtimeAddress: string) => Promise<void>;
  removeBreakpoint: (breakpointId: number) => Promise<void>;
  step: (mode: StepMode) => Promise<void>;
  continueExecution: () => Promise<void>;
  disconnect: () => Promise<void>;
  clearError: () => void;
}

export function useDebugSession(): UseDebugSessionResult {
  const [session, setSession] = useState<DebugSessionState | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleError = useCallback((err: unknown) => {
    if (err instanceof ApiError) {
      // The session's own idle timeout (30 min, server-side) shows up here as
      // a 404 the next time the user interacts - clear the now-meaningless
      // session rather than leaving a stale one on screen.
      if (err.code === 'DYNAMIC_SESSION_NOT_FOUND') {
        setSession(null);
      }
      setError(
        err.details ? `${err.message} (${err.code}: ${err.details})` : `${err.message} (${err.code})`,
      );
    } else {
      setError('Lỗi không xác định trong phiên debug.');
    }
  }, []);

  const launchLocal = useCallback(
    async (analysisId: string, commandLine: string) => {
      setLoading(true);
      setError(null);
      try {
        const state = await debugApi.launchLocal(analysisId, commandLine);
        setSession(state);
        return state;
      } catch (err) {
        handleError(err);
        return null;
      } finally {
        setLoading(false);
      }
    },
    [handleError],
  );

  const launchLocalFromUpload = useCallback(
    async (analysisId: string, file: File) => {
      setLoading(true);
      setError(null);
      try {
        const state = await debugApi.launchLocalFromUpload(analysisId, file);
        setSession(state);
        return state;
      } catch (err) {
        handleError(err);
        return null;
      } finally {
        setLoading(false);
      }
    },
    [handleError],
  );

  const setRegister = useCallback(
    async (name: string, value: string) => {
      if (!session) return;
      setLoading(true);
      try {
        setSession(await debugApi.setRegister(session.sessionId, name, value));
      } catch (err) {
        handleError(err);
      } finally {
        setLoading(false);
      }
    },
    [session, handleError],
  );

  const setBreakpoint = useCallback(
    async (staticAddress: string) => {
      if (!session) return;
      setLoading(true);
      try {
        await debugApi.setBreakpoint(session.sessionId, staticAddress);
        setSession(await debugApi.getState(session.sessionId));
      } catch (err) {
        handleError(err);
      } finally {
        setLoading(false);
      }
    },
    [session, handleError],
  );

  const setRuntimeBreakpoint = useCallback(
    async (runtimeAddress: string) => {
      if (!session) return;
      setLoading(true);
      try {
        await debugApi.setRuntimeBreakpoint(session.sessionId, runtimeAddress);
        setSession(await debugApi.getState(session.sessionId));
      } catch (err) {
        handleError(err);
      } finally {
        setLoading(false);
      }
    },
    [session, handleError],
  );

  const removeBreakpoint = useCallback(
    async (breakpointId: number) => {
      if (!session) return;
      setLoading(true);
      try {
        await debugApi.removeBreakpoint(session.sessionId, breakpointId);
        setSession(await debugApi.getState(session.sessionId));
      } catch (err) {
        handleError(err);
      } finally {
        setLoading(false);
      }
    },
    [session, handleError],
  );

  const step = useCallback(
    async (mode: StepMode) => {
      if (!session) return;
      setLoading(true);
      try {
        setSession(await debugApi.step(session.sessionId, mode));
      } catch (err) {
        handleError(err);
      } finally {
        setLoading(false);
      }
    },
    [session, handleError],
  );

  const continueExecution = useCallback(async () => {
    if (!session) return;
    setLoading(true);
    try {
      setSession(await debugApi.continueExecution(session.sessionId));
    } catch (err) {
      handleError(err);
    } finally {
      setLoading(false);
    }
  }, [session, handleError]);

  const disconnect = useCallback(async () => {
    if (!session) return;
    setLoading(true);
    try {
      await debugApi.disconnect(session.sessionId);
    } catch {
      // A session that is already gone server-side (e.g. idle timeout beat
      // us to it) is not worth surfacing as an error - clearing local state
      // below is the outcome the user wanted either way.
    } finally {
      setSession(null);
      setLoading(false);
    }
  }, [session]);

  const clearError = useCallback(() => setError(null), []);

  return {
    session,
    loading,
    error,
    launchLocal,
    launchLocalFromUpload,
    setRegister,
    setBreakpoint,
    setRuntimeBreakpoint,
    removeBreakpoint,
    step,
    continueExecution,
    disconnect,
    clearError,
  };
}
