"""Dynamic analysis (Phase 1, read-only): a debug *client* only.

This package never runs, launches, or automates anything - it only opens a
TCP connection to a ``dbgsrv`` (Debugging Tools for Windows) that the user
already has running inside a VM they prepared themselves, and talks to it
through ``pykd``/``dbgeng`` to set breakpoints, step, and read
registers/stack. See ``docs/dynamic-analysis-spec.md`` for the full design
and the non-negotiable safety constraints this package must uphold.

Import direction is one-way: this package may read the static analyzer's
public surface (``app.repositories``, ``app.models``, ``app.analyzers`` for
the pure ``risk_level`` helper, ``app.utils``), but nothing under
``app.analyzers``/``app.services`` may import from here. Only ``app.main``
(HTTP router registration) and ``app.desktop_bridge`` (the packaged desktop
build's JS<->Python bridge) are allowed to import ``app.dynamic`` from
outside this package.
"""

from __future__ import annotations
