"""Extract printable strings and map them to the functions that reference them.

Two independent passes:

* :func:`extract_strings` scans the raw file bytes for ASCII and UTF-16LE runs.
  This is the classic ``strings`` view and works even when the CFG is poor.
* :func:`collect_function_strings` uses angr's ``Function.string_references()``,
  which walks the data references CFGFast recorded, to attribute strings to the
  function that actually loads them. That mapping is what feeds risk scoring.

Both operate on data only.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable

from app.utils.address import format_address

logger = logging.getLogger(__name__)

MIN_STRING_LENGTH = 4
MAX_STRING_LENGTH = 512
#: Cap on the global string list. Large binaries can hold hundreds of thousands
#: of runs and the frontend has no use for them all.
MAX_STRINGS = 5000

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LENGTH)
# UTF-16LE: printable ASCII byte followed by a NUL, repeated.
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING_LENGTH)


@dataclass(slots=True)
class ExtractedString:
    address: int | None
    value: str
    encoding: str = "ascii"

    @property
    def length(self) -> int:
        return len(self.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": format_address(self.address) if self.address is not None else "",
            "value": self.value,
            "length": self.length,
        }


def _clean(value: str) -> str:
    """Trim and cap a string so one pathological run cannot bloat a response."""
    cleaned = value.strip()
    if len(cleaned) > MAX_STRING_LENGTH:
        cleaned = cleaned[:MAX_STRING_LENGTH] + "..."
    return cleaned


def extract_strings(
    data: bytes,
    image_base: int | None = None,
    limit: int = MAX_STRINGS,
) -> list[ExtractedString]:
    """Scan raw bytes for printable ASCII and UTF-16LE runs.

    ``image_base`` is only used to produce an approximate address; a file offset
    is not a virtual address once sections are mapped, so the address is treated
    as a hint. It is ``None`` when no base is supplied.
    """
    results: list[ExtractedString] = []
    seen: set[str] = set()

    for match in _ASCII_RUN.finditer(data):
        if len(results) >= limit:
            break
        value = _clean(match.group().decode("ascii", errors="replace"))
        if len(value) < MIN_STRING_LENGTH or value in seen:
            continue
        seen.add(value)
        offset = match.start()
        results.append(
            ExtractedString(
                address=(image_base + offset) if image_base is not None else None,
                value=value,
                encoding="ascii",
            )
        )

    for match in _UTF16_RUN.finditer(data):
        if len(results) >= limit:
            break
        value = _clean(match.group().decode("utf-16-le", errors="replace"))
        if len(value) < MIN_STRING_LENGTH or value in seen:
            continue
        seen.add(value)
        offset = match.start()
        results.append(
            ExtractedString(
                address=(image_base + offset) if image_base is not None else None,
                value=value,
                encoding="utf-16le",
            )
        )

    return results


def collect_function_strings(function: Any, limit: int = 64) -> list[ExtractedString]:
    """Strings referenced by a single function, via angr's data references.

    Requires ``CFGFast(data_references=True)``. Returns an empty list rather than
    raising when angr cannot resolve references for this function - a packed
    binary routinely produces such functions and must not abort the analysis.
    """
    results: list[ExtractedString] = []
    try:
        references: Iterable[tuple[int, bytes | str]] = function.string_references(
            vex_only=False
        )
    except Exception as exc:
        logger.debug(
            "string_references thất bại cho function 0x%x: %s",
            getattr(function, "addr", 0),
            exc,
        )
        return results

    seen: set[str] = set()
    for address, raw in references:
        if len(results) >= limit:
            break
        if isinstance(raw, bytes):
            value = raw.decode("utf-8", errors="replace")
        else:
            value = str(raw)
        value = _clean(value)
        if len(value) < MIN_STRING_LENGTH or value in seen:
            continue
        seen.add(value)
        results.append(ExtractedString(address=address, value=value))

    return results
