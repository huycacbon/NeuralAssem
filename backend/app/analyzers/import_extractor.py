"""Extract the PE import table.

Two sources, tried in order:

1. ``pefile`` parsing of the raw import directory. This is the authoritative
   source because it preserves the DLL each symbol came from, which angr's
   loader flattens away for PE targets.
2. angr's CLE loader (``main_object.imports``) as a fallback, used when pefile
   chokes on a malformed/packed header.

Both paths only *read* the file. Nothing is mapped executable or run.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analyzers.risk_scorer import classify_capability
from app.utils.address import api_node_id, format_address

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ImportEntry:
    """One row of the PE import table."""

    module: str
    name: str
    # Address of the IAT slot. Calls to the API go through a thunk that reads
    # this slot, so it is how we map a call target back to an API name.
    iat_address: int | None = None
    # Address of the thunk stub angr recognised for this import, when found.
    thunk_address: int | None = None
    ordinal: int | None = None

    @property
    def node_id(self) -> str:
        return api_node_id(self.module, self.name)

    @property
    def capability(self) -> str:
        return classify_capability(self.name)


@dataclass(slots=True)
class ImportTable:
    entries: list[ImportEntry] = field(default_factory=list)
    #: IAT slot address -> entry. Used to resolve indirect calls.
    by_iat: dict[int, ImportEntry] = field(default_factory=dict)
    #: lowercased bare export name -> entry. Used to resolve calls that angr
    #: already named (PLT stubs, SimProcedures).
    by_name: dict[str, ImportEntry] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def index(self) -> None:
        """(Re)build the lookup dictionaries after ``entries`` is populated."""
        self.by_iat.clear()
        self.by_name.clear()
        for entry in self.entries:
            if entry.iat_address is not None:
                self.by_iat[entry.iat_address] = entry
            if entry.thunk_address is not None:
                self.by_iat.setdefault(entry.thunk_address, entry)
            self.by_name.setdefault(entry.name.lower(), entry)

    def resolve(self, *, address: int | None = None, name: str | None = None) -> ImportEntry | None:
        if address is not None:
            hit = self.by_iat.get(address)
            if hit is not None:
                return hit
        if name:
            cleaned = name.strip().lower()
            for prefix in ("__imp__", "__imp_", "_imp_"):
                cleaned = cleaned.removeprefix(prefix)
            cleaned = cleaned.split("@", 1)[0]
            hit = self.by_name.get(cleaned)
            if hit is not None:
                return hit
            # angr sometimes names PLT stubs "PLT.CreateFileW" or similar.
            if "." in cleaned:
                return self.by_name.get(cleaned.rsplit(".", 1)[-1])
        return None


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode("utf-8", errors="replace")


def _extract_with_pefile(path: Path) -> ImportTable:
    import pefile  # imported lazily so a missing optional dep degrades gracefully

    table = ImportTable()
    # fast_load skips parsing every directory; we then ask only for imports.
    pe = pefile.PE(str(path), fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            ]
        )

        directories: list[Any] = []
        directories.extend(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or [])
        directories.extend(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []) or [])

        for descriptor in directories:
            module = _decode(getattr(descriptor, "dll", None)) or "unknown"
            for symbol in getattr(descriptor, "imports", []) or []:
                ordinal = getattr(symbol, "ordinal", None)
                name = _decode(getattr(symbol, "name", None))
                if not name:
                    # Import by ordinal: no name in the file at all.
                    name = f"Ordinal_{ordinal}" if ordinal else "Ordinal_?"
                table.entries.append(
                    ImportEntry(
                        module=module,
                        name=name,
                        iat_address=getattr(symbol, "address", None),
                        ordinal=ordinal,
                    )
                )
    finally:
        pe.close()

    table.index()
    return table


def _extract_with_cle(project: Any) -> ImportTable:
    """Fallback path using angr's already-loaded object."""
    table = ImportTable()
    main_object = getattr(project.loader, "main_object", None)
    if main_object is None:
        return table

    raw_imports: dict[str, Any] = getattr(main_object, "imports", {}) or {}
    for name, relocation in raw_imports.items():
        module = "unknown"
        # CLE relocations for PE expose the owning DLL in different attributes
        # depending on the loader version; probe the known ones.
        for attribute in ("dll_name", "dll", "resolvewith", "owner_module"):
            candidate = getattr(relocation, attribute, None)
            if isinstance(candidate, str) and candidate:
                module = candidate
                break

        address: int | None = None
        for attribute in ("rebased_addr", "addr", "relative_addr"):
            candidate = getattr(relocation, attribute, None)
            if isinstance(candidate, int):
                address = candidate
                break

        table.entries.append(ImportEntry(module=module, name=name, iat_address=address))

    table.index()
    return table


def _attach_thunk_addresses(table: ImportTable, project: Any) -> None:
    """Link each import to the stub function angr created for it.

    On PE targets angr materialises imports either as PLT-like thunks or as
    SimProcedure stubs, both of which appear in ``kb.functions`` with the export
    name. Recording their addresses lets the call-graph builder recognise a call
    to an API by target address alone.
    """
    try:
        functions = project.kb.functions
    except Exception:  # pragma: no cover - kb missing on a failed load
        return

    for function in list(functions.values()):
        name = getattr(function, "name", "") or ""
        if not name:
            continue
        is_stub = bool(
            getattr(function, "is_plt", False)
            or getattr(function, "is_simprocedure", False)
            or getattr(function, "is_syscall", False)
        )
        if not is_stub:
            continue
        entry = table.resolve(name=name)
        if entry is not None and entry.thunk_address is None:
            entry.thunk_address = function.addr

    table.index()


def extract_imports(path: Path, project: Any | None = None) -> ImportTable:
    """Extract imports, preferring pefile and falling back to CLE.

    Never raises: a binary with a corrupt import directory still yields an empty
    table plus a warning rather than failing the whole analysis.
    """
    table = ImportTable()
    try:
        table = _extract_with_pefile(path)
    except Exception as exc:
        logger.warning("pefile không đọc được import table: %s", exc)
        table.warnings.append(
            "Không đọc được import table bằng pefile; dùng loader của angr thay thế."
        )
        if project is not None:
            try:
                table = _extract_with_cle(project)
                table.warnings.append(
                    "Import table được lấy từ angr/CLE; tên DLL có thể không đầy đủ."
                )
            except Exception as fallback_exc:  # pragma: no cover
                logger.warning("CLE cũng không đọc được import: %s", fallback_exc)

    if project is not None and table.entries:
        try:
            _attach_thunk_addresses(table, project)
        except Exception as exc:  # pragma: no cover
            logger.debug("Không gắn được thunk address: %s", exc)

    if not table.entries:
        table.warnings.append("Không tìm thấy imported API nào trong file.")

    return table


def import_to_dict(entry: ImportEntry) -> dict[str, Any]:
    return {
        "module": entry.module,
        "name": entry.name,
        "address": format_address(entry.iat_address) if entry.iat_address else None,
        "nodeId": entry.node_id,
        "capability": entry.capability,
    }
