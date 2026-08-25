#include "../../include/IdsM.h"
#include "../../include/IdsRm.h"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    std::cout << "=== AUTOSAR IDSM Simulator (Async) ===\n"
              << "Commands: init, mode <pre|run|post>, report, status, flush,\n"
              << "          idsrm <enable|disable|status|url <url>|token <tok>>, quit\n";

    bool initialized      = false;
    bool idsrm_initialized = false;

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream iss(line);
        std::string cmd; iss >> cmd;
        if (cmd.empty()) continue;

        if (cmd == "quit") break;

        else if (cmd == "init") {
            // 0x001 CAN Bus IDS | 0x002 SecOC Auth | 0x003 Ethernet IDS
            // 0x004 OBD-II Scanner | 0x005 ECU Firmware Integrity
            IdsM_MonitorConfigType configs[5] = {
                {0x001, 20, 0, IDSM_SEVERITY_LOW, true, true, false},
                {0x002, 20, 0, IDSM_SEVERITY_LOW, true, true, false},
                {0x003, 20, 0, IDSM_SEVERITY_LOW, true, true, false},
                {0x004, 20, 0, IDSM_SEVERITY_LOW, true, true, false},
                {0x005, 20, 0, IDSM_SEVERITY_LOW, true, true, false},
            };
            if (IdsM_Init(configs, 5) == E_OK) {
                initialized = true;
                std::cout << "[IDSM] Initialized | Async Engine Running\n"
                          << "[IDSM] Monitors: 0x001=CAN-IDS | 0x002=SecOC"
                          << " | 0x003=Ethernet | 0x004=OBD-II | 0x005=FW-Integrity\n";
            } else {
                std::cout << "[IDSM ERR] Init failed\n";
                continue;
            }

            /* Initialize IDSRM immediately after IDSM.
               IDSRM registers itself as the DEM callback — do not call
               IdsM_SetDemReportCallback separately after this point. */
            IdsRm_ConfigType idsrm_cfg{};
            std::strncpy(idsrm_cfg.soc_url,
                         "http://localhost:8080/api/idsm-violations",
                         IDSRM_MAX_URL_LEN - 1);
            idsrm_cfg.auth_token[0] = '\0'; /* no auth for local test server */
            idsrm_cfg.timeout_ms    = 3000;
            idsrm_cfg.retry_count   = 2;
            idsrm_cfg.enabled       = true;

            if (IdsRm_Init(&idsrm_cfg) == E_OK) {
                idsrm_initialized = true;
                std::cout << "[IDSRM] Initialized | Forwarding to "
                          << idsrm_cfg.soc_url << "\n";
            } else {
                std::cout << "[IDSRM ERR] Init failed\n";
            }
        }

        else if (cmd == "mode" && initialized) {
            std::string mode_str; iss >> mode_str;
            IdsM_OperatingModeType mode;
            if      (mode_str == "pre")  mode = IDSM_PRE_RUN_MODE;
            else if (mode_str == "run")  mode = IDSM_RUN_MODE;
            else if (mode_str == "post") mode = IDSM_POST_RUN_MODE;
            else { std::cout << "[ERR] Usage: mode <pre|run|post>\n"; continue; }

            if (IdsM_SetOperatingMode(mode) == E_OK) {
                std::cout << "[IDSM] Mode set to " << mode_str << "\n";
            } else {
                std::cout << "[IDSM ERR] Mode change failed\n";
            }
        }

        else if (cmd == "report" && initialized) {
            IdsM_EventReportType evt{};
            /* Local buffer for parsed payload bytes — valid until ReportEvent copies */
            std::vector<uint8_t> pay_buf;
            std::string param;
            while (iss >> param) {
                auto eq = param.find('=');
                if (eq == std::string::npos) continue;
                std::string k = param.substr(0, eq);
                std::string v = param.substr(eq + 1);
                if      (k == "mon") evt.monitor_id = static_cast<uint16_t>(std::stoul(v, nullptr, 16));
                else if (k == "evt") evt.event_id   = static_cast<uint16_t>(std::stoul(v, nullptr, 16));
                else if (k == "sev") evt.severity   = static_cast<IdsM_EventSeverityType>(std::stoul(v));
                else if (k == "pay") {
                    /* Parse hex byte string: pay=DEADBEEF → {0xDE,0xAD,0xBE,0xEF} */
                    pay_buf.clear();
                    for (size_t j = 0; j + 1 < v.size(); j += 2) {
                        pay_buf.push_back(static_cast<uint8_t>(std::stoul(v.substr(j, 2), nullptr, 16)));
                    }
                }
            }
            evt.payload     = pay_buf.empty() ? nullptr : pay_buf.data();
            evt.payload_len = static_cast<uint16_t>(pay_buf.size());
            evt.timestamp_ms = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count() % 100000);

            if (IdsM_ReportEvent(&evt) == E_OK) {
                std::cout << "[IDSM] Event Queued | Monitor=0x"
                          << std::hex << evt.monitor_id << std::dec << "\n";
            } else {
                std::cout << "[IDSM ERR] Queue failed (check config/mode)\n";
            }
        }

        else if (cmd == "status" && initialized) {
            uint16_t mon_id; iss >> std::hex >> mon_id;
            auto st = IdsM_GetDetectionStatus(mon_id);
            const char* st_str = st == IDSM_STATUS_OK        ? "OK"        :
                                  st == IDSM_STATUS_VIOLATION ? "VIOLATION" : "UNINIT";
            std::cout << "[IDSM] Monitor 0x" << std::hex << mon_id
                      << std::dec << " Status=" << st_str << "\n";
        }

        else if (cmd == "flush" && initialized) {
            uint16_t mon_id; iss >> std::hex >> mon_id;
            if (IdsM_FlushEvents(mon_id) == E_OK) {
                std::cout << "[IDSM] Events flushed to DEM\n";
            }
        }

        else if (cmd == "idsrm") {
            if (!idsrm_initialized) {
                std::cout << "[IDSRM ERR] Not initialized — run 'init' first\n";
                continue;
            }
            std::string sub; iss >> sub;

            if (sub == "enable") {
                IdsRm_Enable();
                std::cout << "[IDSRM] Enabled\n";

            } else if (sub == "disable") {
                IdsRm_Disable();
                std::cout << "[IDSRM] Disabled\n";

            } else if (sub == "status") {
                IdsRm_StatsType st = IdsRm_GetStats();
                std::cout << "[IDSRM] Enabled=" << (IdsRm_IsEnabled() ? "yes" : "no")
                          << " | received=" << st.events_received
                          << " posted="     << st.events_posted
                          << " dropped="    << st.events_dropped
                          << " failed="     << st.events_failed
                          << " retries="    << st.http_retries << "\n";

            } else if (sub == "url") {
                std::string new_url; iss >> new_url;
                if (new_url.empty()) {
                    std::cout << "[ERR] Usage: idsrm url <url>\n";
                } else if (IdsRm_SetSocUrl(new_url.c_str()) == E_OK) {
                    std::cout << "[IDSRM] SOC URL updated to " << new_url << "\n";
                } else {
                    std::cout << "[IDSRM ERR] SetSocUrl failed\n";
                }

            } else if (sub == "token") {
                std::string tok; iss >> tok;
                IdsRm_SetAuthToken(tok.c_str());
                std::cout << "[IDSRM] Auth token updated\n";

            } else {
                std::cout << "[ERR] Usage: idsrm <enable|disable|status|url <url>|token <tok>>\n";
            }
        }

        else {
            std::cout << "[?] Unknown command or not initialized\n";
        }
    }

    if (idsrm_initialized) {
        IdsRm_StatsType st = IdsRm_GetStats();
        std::cout << "[IDSRM] Final stats | received=" << st.events_received
                  << " posted="  << st.events_posted
                  << " failed="  << st.events_failed << "\n";
        IdsRm_DeInit();
    }
    if (initialized) IdsM_DeInit();
    std::cout << "Shutdown complete.\n";
    return 0;
}
