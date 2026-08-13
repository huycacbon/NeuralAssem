/**
 * Raw memory dump view - the "Dump"/`db` capability every other debugger
 * has (x64dbg's Dump tab, WinDbg's `db` command): type an address and a
 * size, see the classic address / hex bytes / ASCII rows. Re-dumpable at
 * any address, any number of times, independent of the current PC - unlike
 * `AssemblyView`'s live-disassembly fallback, this never auto-follows
 * execution; the whole point is inspecting *other* memory (a buffer, a
 * decoded config blob, the stack) while stopped.
 *
 * Self-contained fetch (calls `debugApi` directly, like `AssemblyView`'s
 * live-disassembly fallback in `App.tsx`) rather than routed through
 * `useDebugSession` - a dump is on-demand display data, not part of the
 * session's own reactive state.
 */

import { useEffect, useMemo, useState } from 'react';

import { ApiError } from '@/services/analysisApi';
import { debugApi } from '@/services/debugApi';
import type { MemoryDumpResponse } from '@/types/debug';

const BYTES_PER_ROW = 16;
const DEFAULT_SIZE = 256;
const MAX_SIZE = 4096;

function parseHexAddress(address: string | null | undefined): number | null {
  if (!address) return null;
  const parsed = Number.parseInt(address.replace(/^0x/i, ''), 16);
  return Number.isNaN(parsed) ? null : parsed;
}

interface DumpRow {
  address: string;
  hexBytes: string[];
  ascii: string;
}

function formatHexDump(baseAddress: number, hex: string): DumpRow[] {
  const bytes: number[] = [];
  for (let i = 0; i + 1 < hex.length; i += 2) {
    bytes.push(Number.parseInt(hex.slice(i, i + 2), 16));
  }

  const rows: DumpRow[] = [];
  for (let offset = 0; offset < bytes.length; offset += BYTES_PER_ROW) {
    const chunk = bytes.slice(offset, offset + BYTES_PER_ROW);
    rows.push({
      address: `0x${(baseAddress + offset).toString(16)}`,
      hexBytes: chunk.map((byte) => byte.toString(16).padStart(2, '0')),
      ascii: chunk.map((byte) => (byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.')).join(''),
    });
  }
  return rows;
}

interface MemoryDumpPanelProps {
  sessionId: string;
  disabled: boolean;
  /** Current runtime address, if any - seeds the address field once so
   *  "dump here" is zero-typing, but never overwrites what the user has
   *  since typed (only fires while the field is still empty). */
  defaultAddress: string | null;
}

export function MemoryDumpPanel({
  sessionId,
  disabled,
  defaultAddress,
}: MemoryDumpPanelProps): JSX.Element {
  const [address, setAddress] = useState(defaultAddress ?? '');
  const [sizeInput, setSizeInput] = useState(String(DEFAULT_SIZE));
  const [result, setResult] = useState<MemoryDumpResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setAddress((current) => current || defaultAddress || '');
  }, [defaultAddress]);

  const handleDump = async (): Promise<void> => {
    const trimmed = address.trim();
    if (!trimmed) return;
    const parsedSize = Math.min(
      MAX_SIZE,
      Math.max(1, Number.parseInt(sizeInput, 10) || DEFAULT_SIZE),
    );

    setLoading(true);
    setError(null);
    try {
      setResult(await debugApi.dumpMemory(sessionId, trimmed, parsedSize));
    } catch (err) {
      setResult(null);
      setError(
        err instanceof ApiError
          ? `${err.message} (${err.code})`
          : 'Lỗi không xác định khi dump memory.',
      );
    } finally {
      setLoading(false);
    }
  };

  const rows = useMemo(() => {
    if (!result) return [];
    const base = parseHexAddress(result.address);
    if (base === null) return [];
    return formatHexDump(base, result.bytesHex);
  }, [result]);

  return (
    <div className="panel-section">
      <h4 style={{ margin: 0 }}>Memory dump</h4>
      <div className="chip-row" style={{ marginTop: 6 }}>
        <input
          type="text"
          className="mono"
          style={{ width: 130 }}
          placeholder="0x401000"
          value={address}
          disabled={disabled}
          onChange={(event) => setAddress(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') void handleDump();
          }}
        />
        <input
          type="number"
          className="mono"
          style={{ width: 76 }}
          min={1}
          max={MAX_SIZE}
          title={`Số byte cần dump (tối đa ${MAX_SIZE})`}
          value={sizeInput}
          disabled={disabled}
          onChange={(event) => setSizeInput(event.target.value)}
        />
        <button type="button" disabled={disabled || loading || !address.trim()} onClick={() => void handleDump()}>
          {loading ? 'Đang dump...' : 'Dump'}
        </button>
      </div>

      {error && <p className="disclaimer error-text">{error}</p>}

      {result && rows.length > 0 && (
        <pre className="disasm memory-dump-listing">
          {rows.map((row) => (
            <div className="memory-dump-row" key={row.address}>
              <span className="a">{row.address}</span>
              <span className="mono memory-dump-hex">{row.hexBytes.join(' ')}</span>
              <span className="mono memory-dump-ascii">{row.ascii}</span>
            </div>
          ))}
        </pre>
      )}

      {result && rows.length === 0 && (
        <p style={{ margin: '6px 0 0', fontSize: 12.5, color: 'var(--text-faint)' }}>
          Không đọc được byte nào tại địa chỉ này.
        </p>
      )}
    </div>
  );
}
