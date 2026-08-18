/**
 * Converts a *static* address (already in this app's own
 * preferred-`ImageBase` coordinate space - see `types/graph.ts`'s
 * `FileInfo.imageBase` docstring) into the `module.exe+RVA` expression
 * x64dbg/WinDbg's own "go to address" box accepts.
 *
 * Why this is needed at all: a raw address copied from this app (static
 * *or* the current debug session's runtime address) is not portable to a
 * *separately launched* x64dbg instance - Windows gives the main image (and
 * every DLL) a fresh, randomised ASLR base on every single launch, so two
 * independent debuggers attached to "the same" binary almost never agree on
 * absolute addresses. The RVA (offset from the image's own preferred base,
 * fixed at compile time, unaffected by ASLR) is the one thing both tools
 * can agree on - and `module.exe+RVA` is exactly the expression syntax
 * x64dbg already understands natively in its Go-to-Expression dialog (the
 * same convention it uses to *label* addresses in its own disassembly view).
 */

import { parseHexAddress } from '@/utils/addressDisplay';

/**
 * `null` when the inputs don't make sense for this conversion (missing
 * image base, unparseable address, or an address that falls *before* the
 * image base - not a valid RVA) rather than a nonsensical negative offset.
 */
export function toX64dbgExpression(
  staticAddress: string | null | undefined,
  imageBase: string | null | undefined,
  moduleFileName: string,
): string | null {
  if (!staticAddress || !imageBase) return null;
  const address = parseHexAddress(staticAddress);
  const base = parseHexAddress(imageBase);
  if (address === null || base === null || address < base) return null;
  const rva = address - base;
  return `${moduleFileName}+${rva.toString(16)}`;
}
