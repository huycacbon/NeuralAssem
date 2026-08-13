"""Helpers to normalise binary addresses into a single canonical string form.

angr hands back addresses as Python ``int``. The REST API and the frontend both
speak hex strings (``"0x401000"``) because that is what an analyst reads in a
disassembler. Every conversion between the two worlds goes through this module so
that node ids stay stable and lookups by address never miss because of casing or
a missing ``0x`` prefix.
"""

from __future__ import annotations

__all__ = [
    "format_address",
    "parse_address",
    "try_parse_address",
    "function_node_id",
    "block_node_id",
    "api_node_id",
    "string_node_id",
    "module_node_id",
]


def format_address(address: int) -> str:
    """Return the canonical lowercase hex representation of ``address``."""
    if address < 0:
        # angr never produces negative addresses, but a malformed binary can
        # yield a wrapped value; keep the sign rather than crashing.
        return f"-0x{-address:x}"
    return f"0x{address:x}"


def parse_address(value: str | int) -> int:
    """Parse a user- or URL-supplied address into an ``int``.

    Accepts ``0x401000``, ``401000``, ``0X401000`` and plain decimal-looking
    values (which are still read as hex, matching disassembler conventions).
    Raises ``ValueError`` when the value cannot be interpreted.
    """
    if isinstance(value, int):
        return value

    text = value.strip().lower()
    if not text:
        raise ValueError("empty address")

    negative = text.startswith("-")
    if negative:
        text = text[1:]

    if text.startswith("0x"):
        text = text[2:]
    if not text:
        raise ValueError("empty address")

    try:
        parsed = int(text, 16)
    except ValueError as exc:
        raise ValueError(f"invalid address: {value!r}") from exc

    return -parsed if negative else parsed


def try_parse_address(value: str | int) -> int | None:
    """Like :func:`parse_address` but returns ``None`` instead of raising."""
    try:
        return parse_address(value)
    except (ValueError, TypeError):
        return None


def function_node_id(address: int) -> str:
    return f"func_{address:x}"


def block_node_id(address: int) -> str:
    return f"block_{address:x}"


def api_node_id(module: str, name: str) -> str:
    """Stable id for an imported API.

    The module is included so that ``KERNEL32!CreateFileW`` and a same-named
    export from another DLL do not collapse into one node. The module is
    lowercased and stripped of its extension because PE import tables are
    inconsistent about casing (``KERNEL32.dll`` vs ``kernel32.DLL``).
    """
    normalised_module = module.lower().removesuffix(".dll").removesuffix(".exe")
    return f"api_{normalised_module}!{name}"


def string_node_id(address: int) -> str:
    return f"str_{address:x}"


def module_node_id(module: str) -> str:
    return f"mod_{module.lower()}"
