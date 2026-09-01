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
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=$HOME/work/deps/googletest-1.14.0
cmake --build build                                 # build all targets
ctest --test-dir build --output-on-failure          # run all tests

# Single test suite / single test:
./build/test_idsm --gtest_filter=IdsMTest.*
./build/test_idsm --gtest_filter=IdsMProtocolTest.*
./build/test_idsrm --gtest_filter=IdsRmIntegrationTest.<TestName>

./build/idsm_cli                                    # interactive CLI (see README for commands)
python3 tests/mock_soc_server.py 8080               # local mock SOC endpoint for manual testing
```

Targets: `idsm_core` (IDSM static lib, incl. `IdsM_Protocol.c` serializer), `idsrm_core` (IDSRM static lib, links libcurl + idsm_core), `idsm_cli`, `test_idsm`, `test_idsrm`. GoogleTest is fetched via CMake FetchContent — **the server has slow GitHub access**, so googletest 1.14.0 is pre-staged at `~/work/deps/googletest-1.14.0`; always pass `-DFETCHCONTENT_SOURCE_DIR_GOOGLETEST` when configuring a fresh build tree.

## Architecture

Two independent async pipelines chained via a callback — **every event crosses two queues and two worker threads before leaving the process**:

```
Detector → IdsM_ReportEvent() → [IDSM queue + worker thread] → DEM callback
        → [IDSRM queue + worker thread] → HTTP POST (libcurl) → SOC endpoint
```

Key structural facts that span multiple files:

- **Spec references**: `docs/AutoSar/R24-11/` (CP SWS IdsM, FO PRS IDS Protocol, FO RS, CP SWS Firewall). The authoritative design doc for the ongoing R24-11 refactor is `docs/design/filter-chain-qsev-design.md` — follow it when extending IDSM.
- **R24-11 data model (phases 1–3 landed)**: events are SEvs identified by (external event ID, sensor instance ID); sensors call `IdsM_ReportSecurityEvent()` → worker thread evaluates the per-SEv **Reporting Mode** (OFF/BRIEF/DETAILED/±BYPASSING) → **filter chain** in fixed order BlockState → ForwardEveryNth → Aggregation → Threshold (short-circuit on drop) → SEv becomes a **QSEv** → dispatched to sinks (Dem / IdsR). Operating modes (PRE_RUN/RUN/POST_RUN) were removed (方案A); per-SEV reporting modes replace them. The worker loop wakes on `condition_variable::wait_for` until the earliest Aggregation/Threshold window deadline; window intervals must be multiples of `main_function_period_ms` (validated in `IdsM_Init`); `IdsM_FlushEvents()` releases a pending aggregation window early. Rate / traffic limitation filters land in phase 4 per the design doc.
- **IDS wire format**: `src/IdsM_Protocol.c` serializes QSEvs to the PRS IDS Message (8-byte Event Frame + optional Timestamp/Context Data/Signature frames, big-endian, protocol version 2). IdsRm includes the hex in its SOC JSON as `ids_message`.
- **C API over C++ singleton**: each module is a pair — a public C header/wrapper (`IdsM.h`/`IdsM.c`) calling into a Meyers singleton C++ manager (`IdsM_Internal.h` / `src/IdsM_Manager.cpp`). Same pattern for IDSRM. The `*_Manager_Wrapper.h` headers are the C↔C++ bridge. When changing behavior, edit the C++ manager; the C files are thin pass-throughs.
- **Deep-copy ownership rule**: context data is deep-copied into `std::vector<uint8_t>` at every queue boundary (`IdsM_OwnedSEv` on ingress, `IdsM_OwnedQSEv` at the sink). Never store the caller's pointer — copy.
- **All public APIs must stay non-blocking and thread-safe**: `IdsM_ReportSecurityEvent()` is enqueue-only (<1µs). Qualification and sink dispatch happen on the worker thread. IDSRM registers itself as the **IdsR sink** via `IdsM_RegisterIdsrSink()` in `IdsRm_Init()` and likewise just enqueues; HTTP happens on IDSRM's own thread with exponential-backoff retries.
- **Init ordering matters**: `IdsRm_Init()` requires `IdsM_Init()` to have run first; shutdown is the reverse (`IdsRm_DeInit()` then `IdsM_DeInit()`).
- **Event ID ranges**: 0x0000–0x7FFF AUTOSAR internal (Firewall SEvs 50–77), 0x8000–0xFFFE OEM (this project's sensors), 0xFFFF invalid.
- **Cloud SOC stack** (`tools/soc_dashboard_cloud/`) is a separate deployable: a Vercel serverless ingest function → InfluxDB → Grafana. No runtime npm deps; deploy with `npx vercel@latest --prod`. It is not part of the CMake build.

## Conventions

- C files use the AUTOSAR-style API naming (`IdsM_*`, `IdsRm_*`, `STD_RETURN_TYPE`); C++ internals use standard library threading primitives (`std::mutex`, `std::condition_variable`, `std::atomic`).
- Compile with `-Wall -Wextra -Wpedantic` — keep new code warning-clean.
- IDSRM integration tests spin up an in-process POSIX socket server in test_idsrm.cpp — tests must not depend on the external Python mock server.
