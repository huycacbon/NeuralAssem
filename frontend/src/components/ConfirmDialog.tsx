/**
 * Generic confirm modal - plain overlay `div`, since no modal/dialog library
 * exists in this codebase yet (see `styles/app.css`'s "Debug" section for
 * styling). First user: the mandatory Debug warning modal
 * (`DebugConnectModal.tsx`); reusable for any future confirm-before-action flow.
 */

import type { ReactNode } from 'react';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  children: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  onConfirm: () => void;
  onCancel: () => void;
  /** Disables the confirm button - e.g. while an async connect is in flight. */
  confirmDisabled?: boolean;
}

export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  cancelLabel = 'Hủy',
  onConfirm,
  onCancel,
  confirmDisabled = false,
}: ConfirmDialogProps): JSX.Element | null {
  if (!open) return null;

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-header">{title}</div>
        <div className="modal-body">{children}</div>
        <div className="modal-actions">
          <button type="button" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button type="button" className="primary" disabled={confirmDisabled} onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
