"""Debug bridge: the only part of this package that talks to `dbgsrv`.

``client.py`` holds every ``pykd``-specific call site (imported lazily, see
its module docstring). ``address_map.py`` is pure arithmetic with no I/O.
"""

from __future__ import annotations
