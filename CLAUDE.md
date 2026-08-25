# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development / Build / Debug Server

Development, compilation, and debugging are performed on a remote Linux server:

- **SSH login**: `ssh alientek@172.16.51.211`
- **System**: Ubuntu (Linux alientek 5.15.0-76-generic #83~20.04.1-Ubuntu SMP, x86_64)
- **Project path on server**: `/home/alientek/work/code/autosar-idsm`

Build and test commands below are run on this server (the local checkout is on Windows and shares the same source tree).

## What This Is

AUTOSAR Intrusion Detection System Manager (IDSM) toolkit — an async-first C++17/C11 implementation of the AUTOSAR IDSM spec (R20-11/R22-11), plus an IDSRM module that forwards violations over HTTP to a Security Operations Center endpoint. Built for HIL testing/simulation, not production vehicle deployment.

## Build & Test Commands

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo   # configure (requires libcurl dev package)
cmake --build build                                 # build all targets
ctest --test-dir build --output-on-failure          # run all 39 tests

# Single test suite / single test:
./build/test_idsm --gtest_filter=IdsMTest.*
./build/test_idsrm --gtest_filter=IdsRmIntegrationTest.<TestName>

./build/idsm_cli                                    # interactive CLI (see README for commands)
python3 tests/mock_soc_server.py 8080               # local mock SOC endpoint for manual testing
```

Targets: `idsm_core` (IDSM static lib), `idsrm_core` (IDSRM static lib, links libcurl + idsm_core), `idsm_cli`, `test_idsm`, `test_idsrm`. GoogleTest is fetched via CMake FetchContent (network required on first configure).

## Architecture

Two independent async pipelines chained via a callback — **every event crosses two queues and two worker threads before leaving the process**:

```
Detector → IdsM_ReportEvent() → [IDSM queue + worker thread] → DEM callback
        → [IDSRM queue + worker thread] → HTTP POST (libcurl) → SOC endpoint
```

Key structural facts that span multiple files:

- **C API over C++ singleton**: Each module is a pair — a public C header/wrapper (`IdsM.h`/`IdsM.c`) calling into a Meyers singleton C++ manager class (`IdsM_Internal.h` / `src/IdsM_Manager.cpp`). Same pattern for IDSRM. The `*_Manager_Wrapper.h` headers are the C↔C++ bridge. When changing behavior, edit the C++ manager; the C files are thin pass-throughs.
- **Deep-copy ownership rule**: Callers pass a `payload` pointer in `IdsM_EventReportType`; `IdsM_OwnedEvent` (include/IdsM_Internal.h) deep-copies it into a `std::vector<uint8_t>` at every queue boundary. Never store the caller's pointer — copy. This invariant is relied on by tests and adapters.
- **All public APIs must stay non-blocking and thread-safe**: `IdsM_ReportEvent()` returns in <1µs (enqueue only). Flood protection, buffering, and DEM forwarding happen on the worker thread. IDSRM registers itself as the IDSM DEM callback in `IdsRm_Init()` and likewise just enqueues; HTTP happens on IDSRM's own thread with exponential-backoff retries.
- **Init ordering matters**: `IdsRm_Init()` requires `IdsM_Init()` to have run first; shutdown is the reverse (`IdsRm_DeInit()` then `IdsM_DeInit()`).
- **Per-monitor state**: Each monitor has its own ring buffer (oldest dropped on overflow), `flood_protection_ms` window, severity threshold, and per-mode enable flags (`enabled_in_pre_run/run/post_run`) — configured once at `IdsM_Init()`.
- **Cloud SOC stack** (`tools/soc_dashboard_cloud/`) is a separate deployable: a Vercel serverless ingest function → InfluxDB → Grafana. No runtime npm deps; deploy with `npx vercel@latest --prod`. It is not part of the CMake build.

## Conventions

- C files use the AUTOSAR-style API naming (`IdsM_*`, `IdsRm_*`, `STD_RETURN_TYPE`); C++ internals use standard library threading primitives (`std::mutex`, `std::condition_variable`, `std::atomic`).
- Compile with `-Wall -Wextra -Wpedantic` — keep new code warning-clean.
- IDSRM integration tests spin up an in-process POSIX socket server in test_idsrm.cpp — tests must not depend on the external Python mock server.
