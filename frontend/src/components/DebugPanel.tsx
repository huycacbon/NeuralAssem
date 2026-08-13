/**
 * Live debug session panel: status, current address (runtime + the
 * address_map-translated static equivalent), registers, stack, breakpoint
 * list, and step/continue/disconnect controls.
 *
 * Registers are editable (click a value to turn it into an input, Enter/
 * blur commits) - the first real Phase 2 (patch-and-continue) capability,
 * added at explicit user request: edit a register, then Step Into/Over uses
 * the edited value, since the write lands directly in the live engine
 * context (see `backend/app/dynamic/session.py`'s `set_register` and
 * `backend/app/dynamic/debug_bridge/client.py`'s `write_register`
 * docstrings) - no extra coupling needed between this panel's edit and the
 * existing step buttons below. `write_memory` remains unimplemented.
 *
 * EFLAGS bits (cf/zf/sf/...) come back from the backend mixed into the same
 * flat `registers` list as the GPRs (the session/API layer is entirely
 * name-agnostic about this - see `client.py`'s `_FLAG_REGISTER_NAMES`) but
 * are split into their own "Flags" section here and shown as checkboxes
 * rather than hex-text inputs, since each one is genuinely just a single
 * bit - editing "0x1"/"0x0" by hand would be needlessly fiddly.
 */

import { useState } from 'react';

import type { DebugSessionState } from '@/types/debug';

/** Mirrors `_FLAG_REGISTER_NAMES` in
 *  `backend/app/dynamic/debug_bridge/client.py` - kept as a separate
 *  frontend copy (not shared) the same way this app already keeps other
 *  small enums duplicated across the boundary rather than shared. */
const FLAG_REGISTER_NAMES = new Set([
  'cf',
  'pf',
  'af',
  'zf',
  'sf',
  'tf',
  'if',
  'df',
  'of',
]);

interface DebugPanelProps {
  session: DebugSessionState;
  loading: boolean;
  error: string | null;
  /** Address of the currently-selected graph node, if any - prefills the
   *  "add breakpoint" field so setting one at the selected node is one click. */
  selectedNodeAddress: string | null;
  onStepInto: () => void;
  onStepOver: () => void;
  onContinue: () => void;
  onDisconnect: () => void;
  onSetBreakpoint: (staticAddress: string) => void;
  onRemoveBreakpoint: (breakpointId: number) => void;
  onSetRegister: (name: string, value: string) => void;
  onFocusStaticAddress: (address: string) => void;
}

export function DebugPanel({
  session,
  loading,
  error,
  selectedNodeAddress,
  onStepInto,
  onStepOver,
  onContinue,
  onDisconnect,
  onSetBreakpoint,
  onRemoveBreakpoint,
  onSetRegister,
  onFocusStaticAddress,
}: DebugPanelProps): JSX.Element {
  const [newBreakpointAddress, setNewBreakpointAddress] = useState('');
  const [editingRegister, setEditingRegister] = useState<string | null>(null);
  const [registerDraft, setRegisterDraft] = useState('');

  const startEditRegister = (name: string, currentValue: string): void => {
    setEditingRegister(name);
    setRegisterDraft(currentValue);
  };

  const commitRegisterEdit = (): void => {
    const name = editingRegister;
    setEditingRegister(null);
    if (!name) return;
    const value = registerDraft.trim();
    if (value) onSetRegister(name, value);
  };

  const addBreakpoint = (): void => {
    const address = newBreakpointAddress.trim() || selectedNodeAddress;
    if (!address) return;
    onSetBreakpoint(address);
    setNewBreakpointAddress('');
  };

  const gprRegisters = session.registers.filter((reg) => !FLAG_REGISTER_NAMES.has(reg.name));
  const flagRegisters = session.registers.filter((reg) => FLAG_REGISTER_NAMES.has(reg.name));

  return (
    <div className="panel-section debug-panel">
      <div className="debug-panel-header">
        <h4 style={{ margin: 0 }}>Debug session</h4>
        <span className={`debug-status-badge debug-status-${session.status}`}>{session.status}</span>
      </div>

      <dl className="kv" style={{ marginTop: 6 }}>
        <dt>Runtime address</dt>
        <dd>{session.runtimeAddress ?? '-'}</dd>
        <dt>Static address</dt>
        <dd>
          {session.staticAddress ? (
            <button
              type="button"
              className="link-button"
              onClick={() => onFocusStaticAddress(session.staticAddress as string)}
            >
              {session.staticAddress}
            </button>
          ) : (
            '-'
          )}
        </dd>
        <dt>Module base</dt>
        <dd>{session.moduleLoadBase ?? '-'}</dd>
      </dl>

      <div className="chip-row" style={{ marginTop: 8 }}>
        <button type="button" disabled={loading} onClick={onStepInto}>
          Step Into
        </button>
        <button type="button" disabled={loading} onClick={onStepOver}>
          Step Over
        </button>
        <button type="button" disabled={loading} onClick={onContinue}>
          Continue
        </button>
        <button type="button" disabled={loading} onClick={onDisconnect}>
          Disconnect
        </button>
      </div>

      {error && <p className="disclaimer error-text">{error}</p>}
      {session.lastError && <p className="disclaimer error-text">{session.lastError}</p>}

      <h4 style={{ marginTop: 12 }}>Registers ({gprRegisters.length})</h4>
      {gprRegisters.length > 0 ? (
        <>
          <pre className="disasm">
            {gprRegisters.map((reg) => (
              <div className="disasm-row register-row" key={reg.name}>
                <span className="a">{reg.name}</span>
                {editingRegister === reg.name ? (
                  <input
                    autoFocus
                    className="mono register-edit-input"
                    value={registerDraft}
                    disabled={loading}
                    onChange={(event) => setRegisterDraft(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter') commitRegisterEdit();
                      if (event.key === 'Escape') setEditingRegister(null);
                    }}
                    onBlur={commitRegisterEdit}
                  />
                ) : (
                  <button
                    type="button"
                    className="link-button register-value"
                    disabled={loading}
                    title="Sửa giá trị - Step Into/Step Over sau đó sẽ dùng giá trị mới này"
                    onClick={() => startEditRegister(reg.name, reg.value)}
                  >
                    {reg.value}
                  </button>
                )}
                <span />
              </div>
            ))}
          </pre>
          <p className="disclaimer" style={{ marginTop: 4 }}>
            Click vào giá trị để sửa - Step Into/Step Over kế tiếp sẽ dùng giá trị đã sửa.
          </p>
        </>
      ) : (
        <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>
          Chưa dừng ở đâu (đang chạy hoặc chưa attach).
        </p>
      )}

      {flagRegisters.length > 0 && (
        <>
          <h4 style={{ marginTop: 12 }}>Flags ({flagRegisters.length})</h4>
          <div className="chip-row flags-row">
            {flagRegisters.map((flag) => {
              const isSet = flag.value !== '0x0';
              return (
                <label key={flag.name} className="flag-toggle" title={`Bit ${flag.name.toUpperCase()}`}>
                  <input
                    type="checkbox"
                    checked={isSet}
                    disabled={loading}
                    onChange={(event) => onSetRegister(flag.name, event.target.checked ? '0x1' : '0x0')}
                  />
                  <span className="mono">{flag.name.toUpperCase()}</span>
                </label>
              );
            })}
          </div>
        </>
      )}

      <h4 style={{ marginTop: 12 }}>Stack ({session.stack.length})</h4>
      {session.stack.length > 0 ? (
        <ul className="string-list">
          {session.stack.map((frame) => (
            <li key={frame.index}>
              <span className="addr">#{frame.index}</span>
              <span className="val mono">
                {frame.runtimeReturnAddress}
                {frame.staticReturnAddress ? ` (static ${frame.staticReturnAddress})` : ''}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>Chưa có dữ liệu.</p>
      )}

      <h4 style={{ marginTop: 12 }}>Breakpoints ({session.breakpoints.length})</h4>
      <div className="chip-row" style={{ marginBottom: 6 }}>
        <input
          type="text"
          className="mono"
          style={{ width: 130 }}
          placeholder={selectedNodeAddress ?? '0x401000'}
          value={newBreakpointAddress}
          onChange={(event) => setNewBreakpointAddress(event.target.value)}
        />
        <button type="button" disabled={loading} onClick={addBreakpoint}>
          + Breakpoint
        </button>
      </div>
      {session.breakpoints.length > 0 ? (
        <div className="chip-row">
          {session.breakpoints.map((bp) => (
            <span key={bp.id} className="chip breakpoint-chip">
              {bp.staticAddress}
              <button
                type="button"
                className="chip-remove"
                onClick={() => onRemoveBreakpoint(bp.id)}
                aria-label={`Xóa breakpoint ${bp.staticAddress}`}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      ) : (
        <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-faint)' }}>Chưa có breakpoint.</p>
      )}
    </div>
  );
}
