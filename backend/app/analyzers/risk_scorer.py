"""Heuristic triage scoring.

IMPORTANT: this is a *prioritisation* aid, not a detection verdict. A high score
only means "an analyst should look here first". Plenty of benign software calls
``CreateRemoteThread``; plenty of malware calls nothing interesting at all.
The frontend is required to display this disclaimer next to any score.

Scores come from two sources, summed per function:
  * imported APIs the function calls;
  * strings the function references.
"""

from __future__ import annotations

from typing import Final, Iterable

# --- API weights ---------------------------------------------------------
# Keyed by the bare export name. Lookup is case-insensitive and also tries the
# name without a trailing A/W so CreateFileA and CreateFileW both match.
API_RISK_WEIGHTS: Final[dict[str, int]] = {
    "createremotethread": 10,
    "createremotethreadex": 10,
    "ntcreatethreadex": 10,
    "rtlcreateuserthread": 10,
    "virtualallocex": 8,
    "writeprocessmemory": 8,
    "ntwritevirtualmemory": 8,
    "ntunmapviewofsection": 8,
    "queueuserapc": 8,
    "deviceiocontrol": 7,
    "createservice": 7,
    "startservice": 6,
    "setwindowshookex": 6,
    "urldownloadtofile": 6,
    "checkremotedebuggerpresent": 5,
    "regsetvalueex": 5,
    "bcryptencrypt": 5,
    "cryptencrypt": 5,
    "cryptgenkey": 5,
    "shellexecute": 5,
    "shellexecuteex": 5,
    "createtoolhelp32snapshot": 4,
    "openprocess": 4,
    "adjusttokenprivileges": 4,
    "isdebuggerpresent": 4,
    "winhttpsendrequest": 4,
    "internetopenurl": 4,
    "httpsendrequest": 4,
    "internetreadfile": 4,
    "createprocess": 4,
    "winexec": 4,
    "virtualprotect": 4,
    "loadlibrary": 3,
    "getprocaddress": 3,
    "process32next": 3,
    "regcreatekeyex": 3,
    "getasynckeystate": 3,
    "getkeystate": 3,
    "writefile": 2,
    "createfile": 1,
    "readfile": 1,
}

# --- String weights ------------------------------------------------------
# Matched as case-insensitive substrings of a referenced string literal.
STRING_RISK_PATTERNS: Final[tuple[tuple[str, int, str], ...]] = (
    ("\\\\.\\physicaldrive", 10, "Tham chiếu đường dẫn raw disk"),
    (".onion", 5, "Tham chiếu địa chỉ Tor (.onion)"),
    ("powershell", 5, "Tham chiếu powershell"),
    ("currentversion\\run", 5, "Tham chiếu registry Run key (persistence)"),
    ("cmd.exe", 3, "Tham chiếu cmd.exe"),
    ("http://", 2, "Chứa URL http://"),
    ("https://", 2, "Chứa URL https://"),
)

# --- Capability grouping -------------------------------------------------
# Coarse buckets used by the API-node details panel and by graph filters.
CAPABILITY_RULES: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    (
        "process_injection",
        (
            "createremotethread",
            "virtualallocex",
            "writeprocessmemory",
            "openprocess",
            "queueuserapc",
            "ntwritevirtualmemory",
            "ntunmapviewofsection",
            "setthreadcontext",
        ),
    ),
    (
        "execution",
        ("createprocess", "shellexecute", "winexec", "system", "createthread"),
    ),
    (
        "network",
        (
            "internet",
            "winhttp",
            "httpsend",
            "urldownload",
            "socket",
            "connect",
            "send",
            "recv",
            "wsastartup",
            "gethostby",
        ),
    ),
    (
        "crypto",
        ("crypt", "bcrypt", "ncrypt", "md5", "sha", "aes", "rc4"),
    ),
    (
        "persistence",
        ("regsetvalue", "regcreatekey", "createservice", "startservice", "schtask"),
    ),
    (
        "anti_analysis",
        (
            "isdebuggerpresent",
            "checkremotedebugger",
            "ntqueryinformationprocess",
            "outputdebugstring",
            "gettickcount",
            "queryperformancecounter",
        ),
    ),
    (
        "discovery",
        (
            "createtoolhelp32snapshot",
            "process32",
            "enumprocess",
            "getcomputername",
            "getusername",
            "getsysteminfo",
            "getvolumeinformation",
        ),
    ),
    (
        "filesystem",
        ("createfile", "writefile", "readfile", "deletefile", "movefile", "copyfile"),
    ),
    (
        "keylogging",
        ("getasynckeystate", "getkeystate", "setwindowshookex", "getrawinputdata"),
    ),
    (
        "memory",
        ("virtualalloc", "virtualprotect", "heapcreate", "loadlibrary", "getprocaddress"),
    ),
)


def _normalise_api_name(name: str) -> list[str]:
    """Return candidate lookup keys for an export name.

    Handles the common decorations found in PE import tables:
      * ``_CreateFileW@28``  -> stdcall decoration
      * ``CreateFileW``      -> ANSI/wide suffix
      * ``__imp_CreateFileW``-> import thunk prefix
    """
    lowered = name.strip().lower()
    for prefix in ("__imp__", "__imp_", "_imp_"):
        lowered = lowered.removeprefix(prefix)
    lowered = lowered.split("@", 1)[0].lstrip("_")

    candidates = [lowered]
    if lowered.endswith(("a", "w")) and len(lowered) > 2:
        candidates.append(lowered[:-1])
    if lowered.endswith("ex"):
        candidates.append(lowered[:-2])
    return candidates


def _match_api(name: str) -> tuple[str, int]:
    """Return ``(table_key, weight)`` for an export name.

    The *table* key is returned rather than the raw name so that variants which
    score identically - ``CreateFileA``/``CreateFileW``, ``OpenProcess``/
    ``OpenProcessEx`` - also deduplicate identically in :func:`score_function`.
    Falls back to the normalised name with weight 0 when nothing matches.
    """
    candidates = _normalise_api_name(name)
    for candidate in candidates:
        weight = API_RISK_WEIGHTS.get(candidate)
        if weight is not None:
            return candidate, weight
    return candidates[0], 0


def score_api(name: str) -> int:
    """Risk weight for a single API name, or 0 if it is not in the table."""
    return _match_api(name)[1]


def classify_capability(name: str) -> str:
    """Bucket an API into a coarse capability group for the details panel."""
    lowered = _normalise_api_name(name)[0]
    for capability, keywords in CAPABILITY_RULES:
        if any(keyword in lowered for keyword in keywords):
            return capability
    return "other"


def score_strings(values: Iterable[str]) -> tuple[int, list[str]]:
    """Score referenced string literals. Each pattern contributes at most once."""
    total = 0
    reasons: list[str] = []
    seen: set[str] = set()

    for value in values:
        lowered = value.lower()
        for pattern, weight, reason in STRING_RISK_PATTERNS:
            if pattern in lowered and reason not in seen:
                seen.add(reason)
                total += weight
                reasons.append(reason)
    return total, reasons


def score_function(
    api_names: Iterable[str],
    string_values: Iterable[str] = (),
) -> tuple[int, list[str]]:
    """Compute ``(risk_score, risk_reasons)`` for one function.

    Each distinct API contributes its weight once, no matter how many call sites
    reference it - otherwise a loop calling ``WriteFile`` would dominate the
    ranking over a single ``CreateRemoteThread``.
    """
    total = 0
    reasons: list[str] = []
    counted: set[str] = set()

    for name in api_names:
        key, weight = _match_api(name)
        if weight <= 0 or key in counted:
            continue
        counted.add(key)
        total += weight
        reasons.append(f"Gọi {name} (+{weight})")

    string_score, string_reasons = score_strings(string_values)
    total += string_score
    reasons.extend(string_reasons)

    return total, reasons


def risk_level(score: int) -> str:
    """Bucket used for node styling on the frontend."""
    if score >= 20:
        return "high"
    if score >= 10:
        return "medium"
    if score > 0:
        return "low"
    return "none"
