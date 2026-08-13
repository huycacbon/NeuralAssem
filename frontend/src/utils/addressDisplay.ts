/**
 * Rebasing every *static* address the app already carries (function list,
 * graph node labels/tooltips, CFG, assembly view) into the coordinate space
 * a live debug session is actually running in - purely presentational.
 *
 * Every address already flowing through this app (`GraphNode.address`,
 * `FunctionSummary.address`, breakpoint addresses, ...) is a *static*
 * address: `preferred ImageBase (from the PE header) + RVA`, computed once
 * by angr during static analysis. That is a "theoretical" address - it is
 * only where a function will actually run if Windows loads the module
 * exactly at its preferred ImageBase, which ASLR (or the address simply
 * being taken) routinely defeats. A live debug session's `moduleLoadBase`
 * is where the module was *actually* loaded this run.
 *
 * `rebaseDelta = moduleLoadBase - preferredImageBase` is the constant
 * offset between the two coordinate spaces for the whole module - the same
 * math `backend/app/dynamic/debug_bridge/address_map.py` already does
 * server-side for the single "where is the debugger stopped" address. This
 * module applies the identical delta client-side, to *display* text only:
 * the underlying `.address`/`.staticAddress` fields on every data object
 * are never mutated - they still carry static addresses end to end, so
 * breakpoint calls, CFG fetches, and the executing-node highlight (which
 * all compare against the static coordinate space) keep working unchanged.
 * Only the string shown to the user changes.
 */

export function parseHexAddress(address: string | null | undefined): number | null {
  if (!address) return null;
  const negative = address.trim().startsWith('-');
  const digits = address.replace(/^-/, '').replace(/^0x/i, '');
  const parsed = Number.parseInt(digits, 16);
  if (Number.isNaN(parsed)) return null;
  return negative ? -parsed : parsed;
}

export function formatHexAddress(value: number): string {
  if (value < 0) return `-0x${(-value).toString(16)}`;
  return `0x${value.toString(16)}`;
}

/** `moduleLoadBase - preferredImageBase`, or `null` when there is nothing
 *  to rebase against (no active/attached session yet) - callers treat
 *  `null` the same as a zero delta (display addresses unchanged). */
export function computeRebaseDelta(
  moduleLoadBase: string | null | undefined,
  preferredImageBase: string | null | undefined,
): number | null {
  const loadBase = parseHexAddress(moduleLoadBase);
  const imageBase = parseHexAddress(preferredImageBase);
  if (loadBase === null || imageBase === null) return null;
  return loadBase - imageBase;
}

/** Rebase a *static*-coordinate address string for display. `staticAddress`
 *  is returned unchanged when it is missing, unparsable, or `delta` is
 *  `null`/`0` (no session, or the module happened to load at its preferred
 *  base this run). */
export function displayAddress(
  staticAddress: string | null | undefined,
  delta: number | null,
): string {
  if (!staticAddress) return staticAddress ?? '';
  if (!delta) return staticAddress;
  const parsed = parseHexAddress(staticAddress);
  if (parsed === null) return staticAddress;
  return formatHexAddress(parsed + delta);
}
