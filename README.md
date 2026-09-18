# AUTOSAR Intrusion Detection System Manager (IDSM) Toolkit

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"/></a>
  <a href="https://proudgorge193.grafana.net/public-dashboards/28e14695d6df4c079328fb8f8dc51748"><img src="https://img.shields.io/badge/SOC_Dashboard-Live-green" alt="Live SOC Dashboard"/></a>
  <img src="https://img.shields.io/badge/C%2B%2B-17-blue.svg" alt="Language: C++17"/>
  <img src="https://img.shields.io/badge/AUTOSAR-R22--11-orange.svg" alt="AUTOSAR"/>
</p>

A production-pattern, async-first C++17/C11 implementation of the AUTOSAR Intrusion Detection System Manager per specifications R20-11 & R22-11. Provides a thread-safe, non-blocking manager layer for orchestrating multiple IDS detectors, event buffering, flood protection, and seamless BSW integration.

---

## Live SOC Dashboard

Security violations reported by the IDSM/IDSR toolkit are forwarded in real-time to a cloud-hosted Security Operations Center dashboard.

**[View Live SOC Dashboard →](https://proudgorge193.grafana.net/public-dashboards/28e14695d6df4c079328fb8f8dc51748)**

| Panel | Description |
|:---|:---|
| **Total / Critical / High** | Live violation counters with severity color thresholds |
| **Violations Over Time** | Time-series chart split by severity (CRITICAL=red, HIGH=orange) |
| **Severity Distribution** | Donut chart showing LOW / MEDIUM / HIGH / CRITICAL breakdown |
| **Violations per Monitor** | Bar chart — worst offending detector modules |
| **Top Monitors Over Time** | Per-monitor event timeline |
| **Latest 100 Events** | Live sortable table with monitor ID, payload hex, and severity badges |

> Dashboard auto-refreshes every 10 seconds. No login required.

---

## Features

- **Async/Non-Blocking Core**: Background worker thread processes events instantly without blocking detector/communication threads
- **AUTOSAR-Compliant C API**: `IdsM_Init`, `IdsM_ReportEvent`, `IdsM_SetOperatingMode`, `IdsM_MainFunction` (simulated)
- **IDSRM SOC Forwarding**: HTTP POST violations to any Security Operations Center endpoint (Splunk, QRadar, Elastic, custom webhook)
- **Dynamic Payload**: Variable-length payload buffer (deep-copied) — supports CAN 2.0 (13B), CAN FD (69B), Ethernet (1514B), or any custom context
- **Pluggable Module Architecture**: Lightweight Adapter pattern for integrating CAN IDS, SecOC, FlexRay, Ethernet, or custom detectors
- **Thread-Safe State Management**: Mutex-protected queues, condition variables, and atomic flags
- **Event Buffering & Flood Protection**: Configurable per-monitor acceptance windows and anti-spam filtering
- **Lifecycle Mode Management**: Pre-Run, Run, and Post-Run operating modes with selective monitor activation
- **Comprehensive Test Suite**: 39 tests (Google Test) covering IDSM unit, IDSRM unit, and HTTP integration
- **Interactive CLI**: Real-time testing, status querying, IDSRM control, and diagnostic flushing

---

## Architecture Overview

The toolkit follows a **Manager-Adapter-Detector** pattern aligned with AUTOSAR BSW layering, with an optional **IDSRM reporting** layer and cloud SOC dashboard:

```
[Detector Engine] → [Adapter] → IdsM_ReportEvent()
                                        ↓
                                [IDSM Manager (Async Worker)]
                                        ↓
                                IdsM_DemReportCallback
                                        ↓
                          [IDSRM Worker Thread] → HTTP POST → [Vercel Ingest Bridge]
                                                                        ↓
                                                              [InfluxDB Cloud]
                                                                        ↓
                                                              [Grafana Cloud Dashboard]
```

- **Detector Engine**: Validates frames/signals (e.g., CAN IDS, SecOC verifier)
- **Adapter**: Translates detector violations into `IdsM_EventReportType` and forwards to IDSM
- **IDSM Manager**: Thread-safe queue + background worker handles buffering, flood protection, and DEM forwarding
- **IDSRM Module**: Optional. Registers as the DEM callback, enqueues events to its own worker thread, and HTTP POSTs JSON to a configurable SOC URL via libcurl
- **Vercel Ingest Bridge**: Serverless function that receives IDSRM HTTP POSTs and writes to InfluxDB Cloud
- **Grafana Cloud**: Live SOC dashboard with real-time charts, severity breakdown, and per-monitor analysis

---

## Project Structure

```
autosar-idsm-toolkit/
├── include/
│   ├── IdsM_Types.h               # AUTOSAR type definitions, enums, config structs
│   ├── IdsM.h                     # Public C API for IDSM
│   ├── IdsM_Internal.h            # C++ IdsM_Manager singleton, IdsM_OwnedEvent (deep-copy)
│   ├── IdsM_Manager_Wrapper.h     # C/C++ bridge for IDSM
│   ├── IdsRm_Types.h              # IDSRM config, stats, return codes
│   ├── IdsRm.h                    # Public C API for IDSRM
│   ├── IdsRm_Internal.h           # C++ IdsRm_Manager singleton class
│   └── IdsRm_Manager_Wrapper.h    # C/C++ bridge for IDSRM
├── src/
│   ├── IdsM.c                     # IDSM C wrapper
│   ├── IdsM_Manager.cpp           # IDSM async worker implementation
│   ├── IdsRm.c                    # IDSRM C wrapper
│   └── IdsRm_Manager.cpp          # IDSRM async HTTP forwarding (libcurl)
├── apps/
│   ├── idsm_cli/
│   │   └── main.cpp               # Interactive CLI — 5 monitors (CAN, SecOC, Ethernet, OBD-II, FW)
│   ├── eth_probe/                 # Lightweight Ethernet IDS probe (rail A, Linux)
│   │   ├── packet.h/.cpp          # L2-L4 parser (Ethernet/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP)
│   │   ├── ip_defrag.h/.cpp       # IP fragment reassembly (capped, LRU eviction)
│   │   ├── stream_tcp.h/.cpp      # TCP stream reassembly (gap-skip, memory caps)
│   │   ├── rules.h/.cpp           # Suricata-syntax-subset rule engine (+pcre2 optional)
│   │   ├── proto_doip/someip/tls/http/dns.* # app-layer parsers (DoIP, SOME/IP+SD,
│   │   │                          #   TLS metadata/JA3, HTTP/1.1, DNS)
│   │   ├── geoip.h/.cpp           # CIDR cross-border analysis (prefix trie)
│   │   ├── detectors.h/.cpp       # port scan / rate flood / flag anomaly / ARP spoof
│   │   ├── pipeline.h/.cpp        # detection pipeline wiring everything together
│   │   ├── capture.h/.cpp         # AF_PACKET live capture + pcap replay
│   │   ├── main.cpp               # probe entry: alerts → IdsM_ReportSecurityEvent()
│   │   └── rules/                 # example.rules + trimmed chnroutes.txt
│   ├── can_probe/                 # Lightweight CAN IDS probe (SocketCAN, Linux)
│   │   ├── frame.h/.cpp          # SocketCAN record parser (classic 16B / CAN-FD 72B)
│   │   ├── detectors.h/.cpp      # unknown-ID / flood / error / DLC / UDS detectors
│   │   ├── pipeline.h/.cpp       # detection pipeline wiring everything together
│   │   ├── capture.h/.cpp        # CAN_RAW live capture + SocketCAN pcap replay
│   │   ├── main.cpp              # probe entry: alerts -> IdsM_ReportSecurityEvent()
│   │   └── whitelist/            # example CAN ID whitelist (hex_id [min_interval_ms])
│   ├── host_probe/                # Lightweight host IDS probe (Linux + Android)
│   │   ├── event.h/.cpp           # host event model + replay-log parser
│   │   ├── sha256.h/.cpp          # self-contained SHA-256 (file integrity)
│   │   ├── baseline.h/.cpp        # exec / file / module baselines
│   │   ├── detectors.h/.cpp       # unknown-exec / priv-esc / fork-flood / rev-shell / ...
│   │   ├── pipeline.h/.cpp        # detection pipeline wiring everything together
│   │   ├── capture.h/.cpp         # PROC_CONNECTOR netlink + /proc poller + replay
│   │   ├── main.cpp               # probe entry: alerts -> IdsM_ReportSecurityEvent()
│   │   └── baseline/              # example exec/file/module baselines
│   └── eve_bridge/                # Suricata EVE → IDSM bridge (rail B)
│       ├── eve.h/.cpp             # minimal EVE JSON alert parser
│       └── main.cpp               # unix_stream listener → IdsM_ReportSecurityEvent()
├── tests/
│   ├── test_idsm.cpp              # IDSM unit tests (Google Test)
│   ├── test_idsrm.cpp             # IDSRM unit + integration tests
│   ├── eth_probe/                 # 88 eth_probe + eve_bridge tests
│   ├── can_probe/                 # 33 CAN probe tests
│   ├── host_probe/                # 36 host probe tests
│   └── mock_soc_server.py         # Python mock SOC endpoint for local testing
├── tools/
│   └── soc_dashboard_cloud/
│       ├── api/
│       │   └── idsm-violations.js # Vercel serverless ingest function (receives IDSRM POSTs)
│       ├── grafana_dashboard.json # Importable Grafana dashboard (6 panels, auto-refresh 10s)
│       ├── vercel.json            # Vercel routing + CORS config
│       └── package.json           # No runtime deps — deploy via npx vercel@latest --prod
└── CMakeLists.txt
```

---

## Ethernet IDS Probe (eth_probe) — Rail A

Lightweight self-contained Ethernet IDS probe (no Suricata/libpcap dependency),
built for embedded targets. Alerts enter the IDSM filter chain as one SEv per detector type
(ext `0x8003`-`0x800E`, context layout v1) and flow through IDSRM to the SOC.

**Detectors** (detector_type in context data):

| # | Detector | Notes |
|:--|:---|:---|
| 1 | Port scan | unique dst ports per source in sliding window |
| 2 | Rate flood | pps per source, pre-aggregated count |
| 3 | TCP flag anomaly | NULL / Xmas / SYN+FIN |
| 4 | Rule engine hit | Suricata-syntax subset (content/pcre/http_*/dns_query) |
| 5 | DoIP (ISO 13400) | malformed headers, routing-activation (GB 44496 surface) |
| 6 | SOME/IP + SD | malformed headers, SD offer whitelist, session-wrap |
| 7 | Reassembly resource | defrag/stream cap eviction |
| 8 | Cross-border IP | outbound to non-domestic dst (CIDR prefix trie) |
| 9 | TLS metadata | ClientHello SNI / version / JA3 (no decryption) |
| 10 | HTTP/1.1 | malformed, overlong URI |
| 11 | DNS | suspicious qtypes, illegal qnames |
| 12 | ARP spoof | binding change, gratuitous storm |

**Run** (Linux, live capture requires root):

```bash
sudo ./build/eth_probe -i eth0 --rules apps/eth_probe/rules/example.rules \
    --cidr apps/eth_probe/rules/chnroutes.txt
./build/eth_probe --pcap sample.pcap --rules ... --cidr ...   # offline replay
```

**Regulatory mapping** (GB 44495-2024 / GB 44496-2024): port scan (1), DoS (2),
malformed data (3/5/6), known-attack signatures (4), unauthorized diagnostic
access (4/5), network spoofing (12), data-export monitoring (8), event
recording & reporting (IDSM/IDSRM core). CAN-bus detection is covered by
`can_probe` below over the same IDSM API.

## CAN IDS Probe (can_probe)

Lightweight CAN/CAN-FD IDS probe over SocketCAN (no libpcap dependency), covering
the GB 44495-2024 CAN-bus detection requirements. Alerts enter the IDSM filter
chain as one SEv per detector type (ext `0x8011`-`0x801A`, CAN context layout v1,
16 bytes) and flow through IDSRM to the SOC.

**Detectors** (detector_type in context data):

| # | Detector | SEv ext | Notes |
|:--|:---|:---|:---|
| 1 | Unknown ID | 0x8011 | frame ID not in the vehicle whitelist (message injection) |
| 2 | ID flood | 0x8012 | per-ID frames/s in tumbling window (targeted DoS) |
| 3 | Bus flood | 0x8013 | bus-wide frames/s (DoS on arbitration) |
| 4 | Error burst | 0x8014 | error frames in window (bus-off / fault injection) |
| 5 | DLC anomaly | 0x8015 | classic DLC > 8, CAN-FD len > 64 (malformed frame) |
| 6 | Remote frame | 0x8016 | RTR frame on an RTR-free automotive bus |
| 7 | UDS SecurityAccess | 0x8017 | 0x27 requestSeed / sendKey brute force per tester |
| 8 | UDS service scan | 0x8018 | many distinct SIDs from one tester |
| 9 | Diagnostic flood | 0x8019 | request flood on 0x7DF / 0x7E0-0x7E7 |
| 10 | Cycle anomaly | 0x801A | periodic message faster than its min interval |

**Whitelist** (`--ids FILE`): one `hex_id [min_interval_ms]` per line (`#` comments).
Loading a whitelist enables detectors 1 and 10; the standardized diagnostics
range 0x7DF / 0x7E0-0x7EF is always treated as known. See
`apps/can_probe/whitelist/example_ids.txt`.

**Run** (Linux, live capture requires root and a configured SocketCAN interface):

```bash
sudo ip link set can0 up type can bitrate 500000        # if needed
sudo ./build/can_probe -i can0 --ids apps/can_probe/whitelist/example_ids.txt
./build/can_probe --pcap capture.pcap --ids ...          # offline replay
```

**Regulatory mapping** (GB 44495-2024 / R155): unauthorized message injection (1),
DoS via flooding (2/3/9), bus-off / fault-injection indicators (4), malformed
frames (5/6), unauthorized diagnostic access (7/8/9), periodic-message integrity
(10), event recording & reporting (IDSM/IDSRM core).
## Host IDS Probe (host_probe) — Rail A

Lightweight host-based IDS probe for Linux and Android (no libpcap/libaudit
dependency), covering the GB 44495-2024 host-side detection requirements.
Alerts enter the IDSM filter chain as one SEv per detector type
(ext `0x8021`-`0x802A`, host context layout v1, 32 bytes) and flow through
IDSRM to the SOC.

**Detectors** (detector_type in context data):

| # | Detector | SEv ext | Notes |
|:--|:---|:---|:---|
| 1 | Unknown exec | 0x8021 | exec of binary not in the allowlist (malware) |
| 2 | Privilege escalation | 0x8022 | setuid-root exec by non-root (flags: setuid/setgid) |
| 3 | Fork flood | 0x8023 | exec rate in tumbling window (fork-bomb DoS) |
| 4 | Reverse shell | 0x8024 | shell spawned by a network-facing daemon (adbd/sshd/netd/...) |
| 5 | File integrity | 0x8025 | monitored file sha256 mismatch / vanished |
| 6 | New setuid file | 0x8026 | setuid-root file outside the file baseline |
| 7 | Kernel module | 0x8027 | module load outside baseline, LKM/rootkit indicator (Linux) |
| 8 | Zombie storm | 0x8028 | zombie processes over threshold in window |
| 9 | Resource exhaustion | 0x8029 | per-process CPU permille / RSS over threshold |
| 10 | Root shell | 0x802A | uid-0 shell session (aux: TTY vs ssh/adb) |

**Event sources**: netlink `PROC_CONNECTOR` (CN_PROC exec events, real time,
root) with automatic `/proc` polling fallback (works on Android without any
kernel config); both feed one detection pipeline. Offline replay via
`--events` for testing.

**Baselines** (`apps/host_probe/baseline/` examples):
- `--baseline-exec`: one entry per line, exact path or basename
- `--baseline-files`: `sha256sum` output format (also seeds the known-path
  set for detector 6)
- `--baseline-mods`: one module name per line

**Run** (Linux; netlink exec events require root, the poller does not):

```bash
sudo ./build/host_probe --baseline-exec apps/host_probe/baseline/example_exec.txt \
    --baseline-files files.txt --baseline-mods mods.txt
./build/host_probe --no-netlink --scan-ms 1000    # poller-only mode (no root)
./build/host_probe --events sample.events          # offline replay
```

**Android** (NDK cross-build; only POSIX APIs + /proc, so bionic suffices):

```bash
cmake -B build-android \
    -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
    -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=$HOME/work/deps/googletest-1.14.0
cmake --build build-android --target host_probe
```

On-vehicle the probe runs as a root init service and reports over the UDS
sink instead of HTTP: see [`android/`](android/) for the manager APK,
init `.rc` and sepolicy templates, [`linux/`](linux/) for `idsm_managerd` and systemd units, and
[docs/vehicle-production.md](docs/vehicle-production.md) for the
probes → APK → MQTT/TLS → cloud architecture.

**Regulatory mapping** (GB 44495-2024 / R155): malicious software
protection (1), privilege-escalation detection (2), DoS via resource
exhaustion (3/9), remote control / reverse shell (4), file & firmware
integrity (5/6), kernel tampering indicators (7), abnormal process
behavior (8/10), event recording & reporting (IDSM/IDSRM core).

## Suricata Bridge (eve_bridge) — Rail B

Full-capability detection on HIL/gateway hosts: run stock Suricata (official
autotools build, untouched) with `eve-log` `filetype: unix_stream` and let
`eve_bridge` forward its alerts into the same IDSM pipeline as SEv ext
`0x8006` / sensor instance 1 (detector_type 100, aux = signature_id).

Suricata source lives outside the project build at `third_party/suricata/`
(release tarball committed for offline servers; unpack with
`third_party/suricata/fetch.sh`, then `./configure && make` the official way —
it is intentionally NOT part of the CMake build).

```bash
./build/eve_bridge --sock /tmp/suricata-eve.sock --soc http://localhost:8080/api/idsm-violations
# suricata.yaml:  outputs → eve-log → filetype: unix_stream, filename: /tmp/suricata-eve.sock
```

---

## IDSM Configuration Reference

### `IdsM_MonitorConfigType` — per-monitor, set at `IdsM_Init()`

| Field | Type | Description |
|:---|:---|:---|
| `monitor_id` | `uint16_t` | Unique identifier for this detector |
| `event_buffer_size` | `uint32_t` | Ring buffer capacity; oldest event dropped on overflow |
| `flood_protection_ms` | `uint32_t` | Minimum milliseconds between DEM forwards (0 = disabled) |
| `severity_threshold` | `IdsM_EventSeverityType` | Minimum severity to accept (LOW / MEDIUM / HIGH / CRITICAL) |
| `enabled_in_pre_run` | `boolean` | Active during PRE_RUN_MODE |
| `enabled_in_run` | `boolean` | Active during RUN_MODE |
| `enabled_in_post_run` | `boolean` | Active during POST_RUN_MODE |

**Example:**
```c
IdsM_MonitorConfigType configs[2] = {
    // {MonitorID, BufferSize, FloodWindow_ms, Severity,    PreRun, Run, PostRun}
    {0x001, 20, 100, IDSM_SEVERITY_HIGH,       true,  true,  false}, // CAN IDS
    {0x002, 10,  50, IDSM_SEVERITY_CRITICAL,    true,  true,  true}  // SecOC
};
IdsM_Init(configs, 2);
IdsM_SetOperatingMode(IDSM_RUN_MODE);
```

### `IdsM_EventReportType` — event submitted via `IdsM_ReportEvent()`

| Field | Type | Description |
|:---|:---|:---|
| `monitor_id` | `uint16_t` | Which monitor detected the violation |
| `event_id` | `uint16_t` | Unique event identifier within this monitor |
| `timestamp_ms` | `uint32_t` | Event timestamp in milliseconds |
| `payload` | `const uint8_t*` | Caller-owned buffer with context data (deep-copied on enqueue) |
| `payload_len` | `uint16_t` | Byte count of payload (any size: CAN=13B, CAN-FD=69B, Ethernet=1514B) |
| `severity` | `IdsM_EventSeverityType` | LOW / MEDIUM / HIGH / CRITICAL |

> **Note:** `payload` is a pointer to a caller-owned buffer. IDSM deep-copies the bytes
> into an internal `std::vector<uint8_t>` when `IdsM_ReportEvent()` is called, so the
> caller's buffer can safely go out of scope immediately after the call returns.

### IDSM Public API

| Function | Description |
|:---|:---|
| `IdsM_Init(config, count)` | Initialize manager, start async worker |
| `IdsM_DeInit()` | Stop worker, join thread, clear state |
| `IdsM_SetOperatingMode(mode)` | Switch PRE_RUN / RUN / POST_RUN |
| `IdsM_GetOperatingMode()` | Query current mode |
| `IdsM_ReportEvent(event)` | Submit event to async queue (non-blocking, <1us) |
| `IdsM_GetDetectionStatus(id)` | Get monitor violation status |
| `IdsM_ResetDetectionStatus(id)` | Clear violation flag |
| `IdsM_GetPendingEventCount(id)` | Count buffered events |
| `IdsM_FlushEvents(id)` | Force-forward all buffered events |
| `IdsM_SetDemReportCallback(cb)` | Register DEM callback (IDSRM sets this automatically) |
| `IdsM_SetNvmStoreCallback(cb)` | Register NVM callback |

---

## IDSRM Module — SOC Violation Forwarding

The IDSRM (Intrusion Detection System Reporting Module) forwards IDSM violations to a Security Operations Center via HTTP POST. **You do not need to build a SOC portal** — IDSRM sends JSON to any HTTP endpoint you point it at (Splunk HEC, QRadar, Elastic webhook, custom server, etc.).

This project includes a ready-to-deploy cloud SOC stack (`tools/soc_dashboard_cloud/`) — a Vercel serverless ingest bridge → InfluxDB Cloud → Grafana Cloud. See the [Live SOC Dashboard](https://proudgorge193.grafana.net/public-dashboards/28e14695d6df4c079328fb8f8dc51748).


### How It Works

1. `IdsRm_Init()` registers itself as the IDSM DEM callback
2. When the IDSM worker fires the callback, IDSRM enqueues the event (<1us, non-blocking)
3. IDSRM's own worker thread picks up events and HTTP POSTs JSON to the SOC URL
4. Failed requests retry with exponential backoff (100ms, 200ms, 400ms...)

### `IdsRm_ConfigType` — set at `IdsRm_Init()`, URL/token changeable at runtime

| Field | Type | Description |
|:---|:---|:---|
| `soc_url` | `char[256]` | HTTP/HTTPS endpoint (e.g. `https://soc.company.com/api/violations`) |
| `auth_token` | `char[512]` | Bearer token for `Authorization` header; empty string = no header |
| `timeout_ms` | `uint32_t` | Per-request HTTP timeout in milliseconds |
| `retry_count` | `uint8_t` | Number of retries on failure (max 10, exponential backoff) |
| `enabled` | `boolean` | Initial enabled/disabled state |

### Compile-Time Constants

| Constant | Default | Description |
|:---|:---|:---|
| `IDSRM_MAX_URL_LEN` | 256 | Maximum SOC URL length |
| `IDSRM_MAX_TOKEN_LEN` | 512 | Maximum auth token length |
| `IDSRM_MAX_RETRY_COUNT` | 10 | Hard cap on retry_count |
| `IDSRM_DEFAULT_QUEUE_DEPTH` | 128 | Max queued events before dropping |

### IDSRM Public API

| Function | Description |
|:---|:---|
| `IdsRm_Init(config)` | Initialize IDSRM, register DEM callback, start worker. Call after `IdsM_Init()`. |
| `IdsRm_DeInit()` | Drain remaining events, stop worker, unregister callback |
| `IdsRm_Enable()` | Enable forwarding (no-op if already enabled) |
| `IdsRm_Disable()` | Disable forwarding; events silently dropped. Worker keeps running. |
| `IdsRm_IsEnabled()` | Returns `true` if initialized AND enabled |
| `IdsRm_SetSocUrl(url)` | Update SOC URL at runtime (thread-safe, takes effect on next POST) |
| `IdsRm_SetAuthToken(token)` | Update bearer token at runtime (pass `""` to remove) |
| `IdsRm_SetLocalSink(path)` | Tee qualified events as NDJSON lines to a unix-domain socket (e.g. the IDSM manager APK); pass `""`/NULL to disable. `@name` selects an Android abstract socket |
| `IdsRm_GetStats()` | Get snapshot: received, dropped, posted, failed, retries |
| `IdsRm_ResetStats()` | Reset all counters to zero |

### Local UDS Sink — Vehicle Path to the Manager APK

For in-vehicle deployment the probes do not talk to the cloud directly.
`IdsRm_SetLocalSink()` (or the probe `--sink PATH` flag) tees every
qualified event as one NDJSON line to an AF_UNIX socket:

```
host_probe/eth_probe --sink @idsm_probe
    │  {"ids_message":"...","event_id":32805,"severity":"MEDIUM",...}
    ▼
IdsmManager APK (system app) → SQLite queue → MQTT/TLS → cloud
```

Delivery is fire-and-forget with bounded queueing (512 events) and graceful
drain on shutdown; the APK owns persistence, so the native side stays
dependency-free (no TLS/MQTT libraries). With `--sink` and no `--soc`, the
HTTP path is compiled out at runtime. The Android side (manager APK, init
`.rc`, sepolicy, MQTT/rule-update flow) lives in [`android/`](android/), the Linux gateway side (native `idsm_managerd` daemon + systemd units) in [`linux/`](linux/) —
see [docs/vehicle-production.md](docs/vehicle-production.md) for the
full production architecture and the GB 44495-2024 mapping.

### JSON Payload Format

Each violation is POSTed as:
```json
{
    "monitor_id": 1,
    "event_id": 256,
    "timestamp_ms": 42000,
    "severity": "HIGH",
    "payload": "00000123080102030405060708",
    "payload_len": 13
}
```

The `payload` field is a hex-encoded byte string (e.g., CAN frame: 4B CAN-ID + 1B DLC + 8B data = 13 bytes → `"00000123080102030405060708"`). `payload_len` is the original byte count.

### Usage Example

```c
#include "IdsM.h"
#include "IdsRm.h"

/* 1. Initialize IDSM */
IdsM_MonitorConfigType mon = {0x001, 20, 100, IDSM_SEVERITY_HIGH, true, true, false};
IdsM_Init(&mon, 1);
IdsM_SetOperatingMode(IDSM_RUN_MODE);

/* 2. Initialize IDSRM — must be called after IdsM_Init() */
IdsRm_ConfigType rm_cfg = {};
strncpy(rm_cfg.soc_url, "https://soc.company.com/api/idsm-violations", IDSRM_MAX_URL_LEN - 1);
strncpy(rm_cfg.auth_token, "my-bearer-token", IDSRM_MAX_TOKEN_LEN - 1);
rm_cfg.timeout_ms  = 3000;
rm_cfg.retry_count = 2;
rm_cfg.enabled     = true;
IdsRm_Init(&rm_cfg);

/* 3. Report violations as normal — IDSRM forwards them to the SOC automatically */
uint8_t context[] = {0x00, 0x00, 0x01, 0x23, 0x08,       /* CAN ID + DLC */
                     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}; /* CAN data */
IdsM_EventReportType evt = {0x001, 0x100, 42000, context, sizeof(context), IDSM_SEVERITY_HIGH};
IdsM_ReportEvent(&evt);  /* deep-copies payload internally */

/* 4. Check stats */
IdsRm_StatsType stats = IdsRm_GetStats();
printf("posted=%u failed=%u\n", stats.events_posted, stats.events_failed);

/* 5. Runtime control */
IdsRm_Disable();                    /* pause forwarding */
IdsRm_Enable();                     /* resume */
IdsRm_SetSocUrl("http://backup-soc:8080/api/violations"); /* switch endpoint */

/* 6. Shutdown (IDSRM first, then IDSM) */
IdsRm_DeInit();
IdsM_DeInit();
```

---

## Async Behavior & Threading Model

- `IdsM_ReportEvent()` is non-blocking: deep-copies payload into `std::vector<uint8_t>`, pushes to queue, and returns in <1us
- **Deep-Copy Ownership**: Payload bytes are copied at every queue boundary (IDSM enqueue, IDSRM enqueue). The caller's buffer can go out of scope immediately after `IdsM_ReportEvent()` returns.
- **IDSM Worker Thread**: Wakes on event submission, processes flood protection, buffers events, forwards to DEM callback
- **IDSRM Worker Thread**: Separate thread. Receives events from DEM callback, HTTP POSTs via libcurl. Uses TCP keep-alive for connection reuse.
- **Thread Safety**: All public APIs are mutex-protected. Safe to call from CAN RX threads, SecOC verifiers, or OS tasks
- **Flood Protection**: Configurable `flood_protection_ms` per monitor drops rapid duplicate violations
- **Mode Isolation**: Events submitted in disabled modes are rejected instantly with `E_MODE_INVALID`

---

## How to Integrate External Modules (e.g., CAN IDS Toolkit)

**Step 1:** Create an Adapter Class

```cpp
#pragma once
#include "IdsM.h"
#include <cstring>
#include <vector>

class CanIdsToIdsMAdapter {
public:
    explicit CanIdsToIdsMAdapter(IdsM_MonitorIdType monitor_id) : m_monitor_id(monitor_id) {}

    void reportViolation(uint16_t event_id, IdsM_EventSeverityType severity,
                         const CanFrame& frame) {
        /* Pack CAN context: [CAN_ID (4B)] [DLC (1B)] [DATA (up to 8B)] = 13B for CAN 2.0 */
        std::vector<uint8_t> buf(4 + 1 + frame.dlc);
        uint32_t can_id = frame.id;
        std::memcpy(&buf[0], &can_id, sizeof(can_id));
        buf[4] = frame.dlc;
        std::memcpy(&buf[5], frame.data, frame.dlc);

        IdsM_EventReportType evt{};
        evt.monitor_id   = m_monitor_id;
        evt.event_id     = event_id;
        evt.severity     = severity;
        evt.timestamp_ms = get_platform_timestamp_ms();
        evt.payload      = buf.data();   // IDSM deep-copies on enqueue
        evt.payload_len  = static_cast<uint16_t>(buf.size());

        IdsM_ReportEvent(&evt);  // non-blocking, deep-copies payload
    }

private:
    IdsM_MonitorIdType m_monitor_id;
};
```

The `payload` field is a **dynamic pointer** — IDSM deep-copies the bytes internally.
Any size is supported: CAN 2.0 (13B), CAN FD (69B), Ethernet (1514B), etc.

**Step 2:** Register Monitor in IDSM Configuration

```cpp
IdsM_MonitorConfigType configs[2] = {
    {0x001, 20, 100, IDSM_SEVERITY_HIGH,     true, true, false}, // CAN IDS
    {0x002, 10,  50, IDSM_SEVERITY_CRITICAL,  true, true, true}  // SecOC
};
IdsM_Init(configs, 2);
IdsM_SetOperatingMode(IDSM_RUN_MODE);

CanIdsToIdsMAdapter can_ids_adapter(0x001);
```

**Step 3:** Link in CMakeLists.txt

```cmake
add_subdirectory(modules/can-ids-toolkit)
target_link_libraries(your_app PRIVATE idsm_core idsrm_core can_ids_core)
```

**Step 4:** Forward Violations in RX Callback

```cpp
void onCanFrameReceived(const CanFrame& frame) {
    auto result = can_ids_engine.validateFrame(frame);
    if (result.status != CanIdsResult::Status::Valid) {
        can_ids_adapter.reportViolation(0x10, IDSM_SEVERITY_HIGH, frame);
    }
}
```

---

## Build & Run

### Prerequisites

| Component | Requirement | Arch Linux | Ubuntu/Debian |
|:---|:---|:---|:---|
| **Compiler** | GCC 11+ / Clang 14+ | `sudo pacman -S base-devel` | `sudo apt install build-essential` |
| **Build System** | CMake 3.16+ | `sudo pacman -S cmake` | `sudo apt install cmake` |
| **libcurl** | Required for IDSRM | `sudo pacman -S curl` | `sudo apt install libcurl4-openssl-dev` |
| **pcre2** | Optional (eth_probe pcre rules) | `sudo pacman -S pcre2` | `sudo apt install libpcre2-dev` |
| **Python 3** | Optional (mock SOC server) | pre-installed | pre-installed |

### Compile

```bash
git clone https://github.com/niketdhale/autosar-idsm-toolkit.git
cd autosar-idsm-toolkit
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
```

### Run CLI

```bash
./build/idsm_cli
```

### CLI Usage

```bash
# Initialize IDSM + IDSRM (auto-connects to localhost:8080)
init

# Switch to normal driving mode
mode run

# Simulate a detector violation (processed async, forwarded to SOC)
# pay= takes a hex byte string: e.g., CAN ID 0x123 + DLC 8 + 8 data bytes
report mon=0x001 evt=0x100 sev=2 pay=000001230801020304050607FF

# Query IDSM monitor status
status 0x001

# Force flush buffered events
flush 0x001

# IDSRM controls
idsrm status                          # show enabled state + stats
idsrm disable                         # pause SOC forwarding
idsrm enable                          # resume SOC forwarding
idsrm url http://new-soc:9090/api/v2  # change SOC endpoint at runtime
idsrm token my-new-bearer-token       # update auth token

# Graceful shutdown
quit
```

### Manual Testing with Mock SOC Server

```bash
# Terminal 1: Start the mock SOC server
python3 tests/mock_soc_server.py 8080

# Terminal 2: Run the CLI
./build/idsm_cli
init
mode run
report mon=0x001 evt=0x100 sev=2 pay=000001230801020304050607FF
idsrm status   # events_posted should be 1
quit
```
The mock server validates JSON structure and prints received events.

---

## Testing

The project uses Google Test (fetched automatically via CMake FetchContent).

### Run All Tests

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
cd build && ctest --output-on-failure
```

### Test Coverage

| Suite | Tests | Description |
|:---|:---:|:---|
| **IdsMTest** | 20 | Lifecycle, mode management, event reporting, DEM callback, flood protection, detection status, multi-monitor |
| **IdsRmPreInitTest** | 5 | Guard clauses: all APIs return error before `IdsRm_Init()` |
| **IdsRmTest** | 8 | Init/DeInit, enable/disable toggle, stats tracking, null-pointer guards |
| **IdsRmIntegrationTest** | 6 | In-process mock HTTP server: event posting, JSON validation, disable/enable, runtime URL change, multi-event |
| **Total** | **39** | All tests pass |

The IDSRM integration tests use an in-process POSIX socket server — no external Python server needed for automated testing.

---

## AUTOSAR Compliance Notes

| Specification Requirement | Status | Notes |
|:---|:---:|:---|
| **Initialization/DeInit** | Compliant | [SWS_IdM_00100-00101] |
| **Main Function (Runnable)** | Compliant | [SWS_IdM_00102] (async worker) |
| **Operating Mode Management** | Compliant | [SWS_IdM_00103-00104] |
| **Event Reporting Interface** | Compliant | [SWS_IdM_00200] (thread-safe) |
| **Detection Status Query** | Compliant | [SWS_IdM_00201-00202] |
| **DEM Event Forwarding** | Simulated | [SWS_IdM_00300] (callback-based) |
| **NVM Config Persistence** | Simulated | [SWS_IdM_00301] (in-memory only) |
| **Multi-Monitor Orchestration** | Compliant | [SWS_IdM_00400] |
| **Flood/Acceptance Windows** | Compliant | [SWS_IdM_00500] |

> **Simulator Disclaimer:** This toolkit is designed for HIL testing, simulation, and educational purposes. Production vehicle deployment requires integration with AUTOSAR OS tasks, COM/PduR routing, DEM/NVM/Csm modules, secure key storage, and ISO 21434 cybersecurity validation.

MIT License. See LICENSE for details.
