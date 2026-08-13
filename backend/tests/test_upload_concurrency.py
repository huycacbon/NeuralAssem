"""Regression test for a real bug: the upload endpoint blocking uvicorn's
event loop for the whole analysis.

`create_analysis` used to be the only `async def` route handler in
`api/analysis.py` that called a slow, blocking service method directly
(`service.analyze_upload(...)`, no `await`) - every other route handler is
plain `def`, which FastAPI/Starlette automatically runs in a thread pool.
`analyze_upload` blocks synchronously for the whole analysis (it waits on a
`Future` from its own internal executor to enforce the analysis timeout - see
`analysis_service._run_with_timeout`). Called straight from an `async def`
handler with no `await`, that froze uvicorn's single event loop for the
entire run (many seconds to a minute+), starving every other request -
including a second request arriving on the SAME server while the first was
still analysing. In the packaged desktop app this showed up as a spurious
"cannot connect to backend" error on upload specifically: the request itself
would eventually succeed, but nothing else could be served in the meantime.

The fix wraps the call in `await run_in_threadpool(...)`, which this test
proves by running a REAL uvicorn server (not an ASGI test transport - the bug
is about real event-loop scheduling, which is easiest to get right by using
the real thing) and firing a concurrent request while a mocked, deliberately
slow "analysis" (a genuine thread-blocking `time.sleep`, not a coroutine - a
coroutine would yield control back on its own and not reproduce the bug) is
in flight.

Note: `/api/health` does a real (first-call-only) `import angr`, which is
slow and completely unrelated to this bug - the fixture below "warms" it up
before timing anything, or the measurement would be polluted by that cost
instead of measuring what this test is actually about.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterator

import pytest
import uvicorn

from app.dependencies import get_analysis_service
from app.main import app
from app.models.analysis import AnalysisResponse, AnalysisSummary, FileInfo

SLOW_DELAY_SECONDS = 1.5


class _SlowAnalysisService:
    """Stands in for AnalysisService.analyze_upload: blocks the calling
    *thread*, exactly like a real angr run would."""

    def analyze_upload(self, stream: object, filename: str | None) -> AnalysisResponse:
        time.sleep(SLOW_DELAY_SECONDS)
        return AnalysisResponse(
            analysis_id="slow-test",
            file=FileInfo(
                name=filename or "sample.exe",
                sha256="0" * 64,
                size=1,
                architecture="x86",
                entry_point="0x0",
            ),
            summary=AnalysisSummary(),
            call_graph={"nodes": [], "edges": [], "metadata": {}},
        )


@pytest.fixture
def slow_upload_server() -> Iterator[str]:
    """A real uvicorn server on a scratch port, with analyze_upload mocked to
    block for SLOW_DELAY_SECONDS, and angr's import cost pre-warmed so it
    cannot pollute the timing measurement this test actually cares about."""
    app.dependency_overrides[get_analysis_service] = lambda: _SlowAnalysisService()

    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "test server did not start in time"

    port = server.servers[0].sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"

    import urllib.request

    with urllib.request.urlopen(f"{base_url}/api/health", timeout=30) as resp:
        resp.read()  # warm-up: absorb the one-time `import angr` cost

    try:
        yield base_url
    finally:
        app.dependency_overrides.pop(get_analysis_service, None)
        server.should_exit = True
        thread.join(timeout=5)


def _post_slow_upload(base_url: str, results: dict) -> None:
    import urllib.error
    import urllib.request

    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="sample.exe"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + b"MZ" + b"\x00" * 100 + f"\r\n--{boundary}--\r\n".encode()

    request = urllib.request.Request(f"{base_url}/api/analysis", data=body, method="POST")
    request.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")

    start = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            results["upload_status"] = resp.status
    except urllib.error.HTTPError as exc:
        results["upload_status"] = exc.code
    results["upload_elapsed"] = time.perf_counter() - start


class TestUploadDoesNotBlockOtherRequests:
    def test_health_check_responds_while_upload_is_in_flight(
        self, slow_upload_server: str
    ) -> None:
        import urllib.request

        results: dict = {}
        upload_thread = threading.Thread(
            target=_post_slow_upload, args=(slow_upload_server, results)
        )
        upload_thread.start()
        # Give the upload a head start so it is genuinely inside the blocking
        # sleep (not just "sent") when the health check fires.
        time.sleep(0.4)

        start = time.perf_counter()
        with urllib.request.urlopen(f"{slow_upload_server}/api/health", timeout=15) as resp:
            health_status = resp.status
        health_elapsed = time.perf_counter() - start

        upload_thread.join(timeout=15)

        assert health_status == 200
        assert results["upload_status"] == 200

        # The whole point: health must come back near-instantly, not only
        # after the slow upload's SLOW_DELAY_SECONDS finishes. A generous
        # margin (well under the delay) keeps this robust while still
        # catching a regression to the old fully-synchronous behaviour,
        # where this would be forced to wait out virtually the whole delay.
        assert health_elapsed < SLOW_DELAY_SECONDS * 0.5, (
            f"/api/health took {health_elapsed:.2f}s while a slow upload was "
            f"in flight (upload itself took {results['upload_elapsed']:.2f}s) "
            "- the event loop was blocked, the exact bug this test guards "
            "against."
        )
