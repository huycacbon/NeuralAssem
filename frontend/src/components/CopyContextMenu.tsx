/**
 * Right-click "Copy ..." menu, usable anywhere in the app - register values,
 * addresses, function/block/variable names (x64dbg/IDA convention: right
 * click any value, get a menu of what's copyable about it).
 *
 * A single instance lives at the app root (see `main.tsx`); any component
 * reaches it via the `useCopyMenu()` hook instead of a prop threaded down
 * from `App.tsx` - this is the one piece of React Context in the codebase,
 * deliberately: unlike the session/business state elsewhere (plain
 * `useState` per `useDebugSession.ts`'s own docstring), this is app-wide UI
 * plumbing that unrelated components several layers apart (AssemblyView,
 * DebugPanel, NodeDetails, FunctionList) all need to reach, and threading an
 * `onCopyMenu` callback prop through every intermediate layer for a feature
 * this generic would be worse than the one Context it costs.
 *
 * Usage: `const { openCopyMenu } = useCopyMenu();` then
 * `onContextMenu={(e) => openCopyMenu(e, [{ label: 'địa chỉ', value: address }])}`
 * on whatever element should offer it. A value only shows up as copyable if
 * the rendering component explicitly wires it up here - there is no generic
 * DOM-attribute scanning, so it never accidentally offers to copy something
 * that turned out to be the wrong text.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from 'react';

export interface CopyMenuItem {
  /** Shown as "Copy <label>" - keep it short, e.g. "địa chỉ", "tên hàm". */
  label: string;
  value: string;
}

interface CopyMenuState {
  x: number;
  y: number;
  items: CopyMenuItem[];
}

interface CopyMenuContextValue {
  openCopyMenu: (event: ReactMouseEvent, items: CopyMenuItem[]) => void;
}

const CopyMenuContext = createContext<CopyMenuContextValue | null>(null);

export function useCopyMenu(): CopyMenuContextValue {
  const ctx = useContext(CopyMenuContext);
  if (!ctx) {
    throw new Error('useCopyMenu() được gọi ngoài <CopyMenuProvider> - kiểm tra main.tsx');
  }
  return ctx;
}

export function CopyMenuProvider({ children }: { children: ReactNode }): JSX.Element {
  const [menu, setMenu] = useState<CopyMenuState | null>(null);
  // Brief "Đã copy ..." toast - the only feedback a clipboard write gets,
  // since there is nothing else on screen that changes when it succeeds.
  const [copiedLabel, setCopiedLabel] = useState<string | null>(null);

  const openCopyMenu = useCallback((event: ReactMouseEvent, items: CopyMenuItem[]) => {
    if (items.length === 0) return; // nothing copyable here - let the native menu show instead
    event.preventDefault();
    event.stopPropagation();
    // Keep the menu on screen: flip it left/up near the viewport edges
    // instead of letting it render partly off-screen.
    const menuWidthEstimate = 200;
    const menuHeightEstimate = items.length * 28 + 8;
    const x = Math.min(event.clientX, window.innerWidth - menuWidthEstimate - 8);
    const y = Math.min(event.clientY, window.innerHeight - menuHeightEstimate - 8);
    setMenu({ x: Math.max(4, x), y: Math.max(4, y), items });
  }, []);

  const close = useCallback(() => setMenu(null), []);

  // Any other click, right-click, scroll, or Escape dismisses the menu -
  // added only while a menu is actually open, and after the opening
  // event has already finished dispatching (this effect runs post-commit),
  // so the very right-click that opened the menu can never immediately
  // close it again.
  useEffect(() => {
    if (!menu) return;
    const handleKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') close();
    };
    window.addEventListener('click', close);
    window.addEventListener('contextmenu', close);
    window.addEventListener('scroll', close, true);
    window.addEventListener('keydown', handleKey);
    return () => {
      window.removeEventListener('click', close);
      window.removeEventListener('contextmenu', close);
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('keydown', handleKey);
    };
  }, [menu, close]);

  const handleCopy = useCallback(
    async (item: CopyMenuItem) => {
      try {
        await navigator.clipboard.writeText(item.value);
        setCopiedLabel(item.label);
        window.setTimeout(() => setCopiedLabel(null), 1200);
      } catch {
        // Clipboard API can reject (no permission, insecure/non-HTTPS
        // context) - the user can still select the text and Ctrl+C
        // manually, so failing silently here rather than an error banner.
      }
      close();
    },
    [close],
  );

  return (
    <CopyMenuContext.Provider value={{ openCopyMenu }}>
      {children}
      {menu && (
        <div
          className="copy-menu"
          style={{ left: menu.x, top: menu.y }}
          role="menu"
          onClick={(event) => event.stopPropagation()}
          onContextMenu={(event) => event.preventDefault()}
        >
          {menu.items.map((item) => (
            <button
              key={item.label}
              type="button"
              role="menuitem"
              onClick={() => void handleCopy(item)}
            >
              Copy {item.label}
            </button>
          ))}
        </div>
      )}
      {copiedLabel && <div className="copy-menu-toast">Đã copy {copiedLabel}</div>}
    </CopyMenuContext.Provider>
  );
}
