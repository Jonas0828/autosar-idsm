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

/* SEv symbolic names (simulate configuration-generated code) */
#define SEV_CAN_IDS        ((IdsM_SecurityEventIdType)0)   /* ext 0x8001 */
#define SEV_SECOC          ((IdsM_SecurityEventIdType)1)   /* ext 0x8002 */
#define SEV_ETHERNET       ((IdsM_SecurityEventIdType)2)   /* ext 0x8003 */
#define SEV_OBD2           ((IdsM_SecurityEventIdType)3)   /* ext 0x8004 */
#define SEV_FW_INTEGRITY   ((IdsM_SecurityEventIdType)4)   /* ext 0x8005 */

/* Simulated BswM states for the Block State filter demo */
#define BLOCK_STATE_NORMAL     ((IdsM_BlockStateIdType)0)
#define BLOCK_STATE_SERVICE    ((IdsM_BlockStateIdType)1)

/* Demo: OBD-II SEv is blocked while the ECU is in SERVICE state.
   Static storage: the pointer is kept inside the IdsM configuration. */
static const IdsM_BlockStateFilterConfigType g_obd_block_states = {
    {BLOCK_STATE_SERVICE}, 1
};

static const char* reporting_mode_str(IdsM_Filters_ReportingModeType m) {
    switch (m) {
        case IDSM_REPORTING_OFF:                        return "OFF";
        case IDSM_REPORTING_BRIEF:                      return "BRIEF";
        case IDSM_REPORTING_DETAILED:                   return "DETAILED";
        case IDSM_REPORTING_BRIEF_BYPASSING_FILTERS:    return "BRIEF_BYPASSING";
        case IDSM_REPORTING_DETAILED_BYPASSING_FILTERS: return "DETAILED_BYPASSING";
        default:                                        return "?";
    }
}

int main() {
    std::cout << "=== AUTOSAR IDSM Simulator (Async, R24-11) ===\n"
              << "Commands: init, report sev=<id> [pay=<hex>] [count=<n>],\n"
              << "          rptmode <sev> [off|brief|detailed|bbypass|dbypass],\n"
              << "          blockstate <id>   (0=NORMAL, 1=SERVICE; blocks OBD-II SEv 3),\n"
              << "          status <sev>, flush <sev>,\n"
              << "          idsrm <enable|disable|status|url <url>|token <tok>>, quit\n";

    bool initialized       = false;
    bool idsrm_initialized = false;

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream iss(line);
        std::string cmd; iss >> cmd;
        if (cmd.empty()) continue;

        if (cmd == "quit") break;

        else if (cmd == "init") {
            /* 0: CAN-IDS | 1: SecOC Auth | 2: Ethernet IDS | 3: OBD-II | 4: FW Integrity
               External event IDs in the OEM range (0x8000+) [PRS_Ids_00017] */
            IdsM_SecurityEventConfigType sevs[5] = {
                /* extId,  inst, severity,             default reporting mode,   blockState, nth, agg, threshold, dem,  idsr */
                {0x8001, 0, IDSM_SEVERITY_HIGH,     IDSM_REPORTING_DETAILED, nullptr,            0, 0, {0, 0}, true, true},
                {0x8002, 0, IDSM_SEVERITY_CRITICAL, IDSM_REPORTING_DETAILED, nullptr,            0, 0, {0, 0}, true, true},
                {0x8003, 0, IDSM_SEVERITY_MEDIUM,   IDSM_REPORTING_DETAILED, nullptr,            0, 0, {0, 0}, true, true},
                {0x8004, 0, IDSM_SEVERITY_MEDIUM,   IDSM_REPORTING_DETAILED, &g_obd_block_states, 0, 0, {0, 0}, true, true},
                {0x8005, 0, IDSM_SEVERITY_CRITICAL, IDSM_REPORTING_DETAILED, nullptr,            0, 0, {0, 0}, true, true},
            };
            IdsM_ConfigType cfg{};
            cfg.idsm_instance_id        = 1;
            cfg.main_function_period_ms = 10;
            cfg.rate_limitation         = {0, 0};   /* disabled (phase 4) */
            cfg.traffic_limitation      = {0, 0};   /* disabled (phase 4) */
            cfg.sev_configs             = sevs;
            cfg.sev_count               = 5;
            cfg.event_buffer_size       = 128;

            if (IdsM_Init(&cfg) == E_OK) {
                initialized = true;
                std::cout << "[IDSM] Initialized | Async Engine Running\n"
                          << "[IDSM] SEvs: 0=CAN-IDS(0x8001) | 1=SecOC(0x8002)"
                          << " | 2=Ethernet(0x8003) | 3=OBD-II(0x8004) | 4=FW(0x8005)\n";
            } else {
                std::cout << "[IDSM ERR] Init failed\n";
                continue;
            }

            /* Initialize IDSRM immediately after IDSM.
               IDSRM registers itself as the IdsR sink — do not call
               IdsM_RegisterIdsrSink separately after this point. */
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

        else if (cmd == "report" && initialized) {
            /* report sev=<id> [pay=<hex>] [count=<n>]
               e.g. report sev=0 pay=00000123080102030405060708 count=1 */
            long sev_id = -1;
            unsigned count = 1;
            std::vector<uint8_t> pay_buf;
            std::string param;
            while (iss >> param) {
                auto eq = param.find('=');
                if (eq == std::string::npos) continue;
                std::string k = param.substr(0, eq);
                std::string v = param.substr(eq + 1);
                if      (k == "sev" || k == "mon") sev_id = std::stol(v, nullptr, 0);
                else if (k == "count")             count  = std::stoul(v, nullptr, 0);
                else if (k == "pay") {
                    /* Parse hex byte string: pay=DEADBEEF -> {0xDE,0xAD,0xBE,0xEF} */
                    pay_buf.clear();
                    for (size_t j = 0; j + 1 < v.size(); j += 2) {
                        pay_buf.push_back(static_cast<uint8_t>(std::stoul(v.substr(j, 2), nullptr, 16)));
                    }
                }
            }
            if (sev_id < 0 || !IdsM_IsSecurityEventConfigured(
                    static_cast<IdsM_SecurityEventIdType>(sev_id))) {
                std::cout << "[IDSM ERR] Unknown SEv id (see init list)\n";
                continue;
            }
            /* Deep-copied on enqueue; pay_buf may go out of scope right after */
            IdsM_ReportSecurityEvent(static_cast<IdsM_SecurityEventIdType>(sev_id),
                                     pay_buf.empty() ? nullptr : pay_buf.data(),
                                     static_cast<uint16_t>(pay_buf.size()),
                                     1 /* contextDataVersion */,
                                     static_cast<uint16_t>(count),
                                     nullptr /* timestamp: internal */);
            std::cout << "[IDSM] Event Queued | SEv=" << sev_id << "\n";
        }

        else if (cmd == "rptmode" && initialized) {
            /* rptmode <sev>            -> query
               rptmode <sev> <mode>    -> set (off|brief|detailed|bbypass|dbypass) */
            std::string sev_str, mode_str;
            iss >> sev_str;
            if (sev_str.empty()) { std::cout << "[ERR] Usage: rptmode <sev> [mode]\n"; continue; }
            auto sev_id = static_cast<IdsM_SecurityEventIdType>(std::stoul(sev_str, nullptr, 0));
            if (!IdsM_IsSecurityEventConfigured(sev_id)) {
                std::cout << "[ERR] Unknown SEv id\n"; continue;
            }
            iss >> mode_str;
            if (mode_str.empty()) {
                std::cout << "[IDSM] SEv " << sev_id << " reporting mode = "
                          << reporting_mode_str(IdsM_GetReportingMode(sev_id)) << "\n";
                continue;
            }
            IdsM_Filters_ReportingModeType mode;
            if      (mode_str == "off")      mode = IDSM_REPORTING_OFF;
            else if (mode_str == "brief")    mode = IDSM_REPORTING_BRIEF;
            else if (mode_str == "detailed") mode = IDSM_REPORTING_DETAILED;
            else if (mode_str == "bbypass")  mode = IDSM_REPORTING_BRIEF_BYPASSING_FILTERS;
            else if (mode_str == "dbypass")  mode = IDSM_REPORTING_DETAILED_BYPASSING_FILTERS;
            else { std::cout << "[ERR] mode: off|brief|detailed|bbypass|dbypass\n"; continue; }

            if (IdsM_SetReportingMode(sev_id, mode) == E_OK) {
                std::cout << "[IDSM] SEv " << sev_id << " reporting mode -> "
                          << reporting_mode_str(mode) << "\n";
            } else {
                std::cout << "[IDSM ERR] SetReportingMode failed\n";
            }
        }

        else if (cmd == "blockstate" && initialized) {
            /* blockstate <id> — simulate BswM notifying the current block state */
            std::string state_str; iss >> state_str;
            if (state_str.empty()) {
                std::cout << "[ERR] Usage: blockstate <id>  (0=NORMAL, 1=SERVICE)\n";
                continue;
            }
            auto state = static_cast<IdsM_BlockStateIdType>(std::stoul(state_str, nullptr, 0));
            IdsM_BswM_StateChanged(state);
            std::cout << "[IDSM] Block state -> " << static_cast<unsigned>(state)
                      << (state == BLOCK_STATE_SERVICE ? " (OBD-II SEv blocked)" : "") << "\n";
        }

        else if (cmd == "status" && initialized) {
            uint16_t sev_id; iss >> std::hex >> sev_id;
            auto st = IdsM_GetDetectionStatus(sev_id);
            const char* st_str = st == IDSM_STATUS_OK        ? "OK"        :
                                  st == IDSM_STATUS_VIOLATION ? "VIOLATION" : "UNINIT";
            std::cout << "[IDSM] SEv 0x" << std::hex << sev_id
                      << std::dec << " Status=" << st_str << "\n";
        }

        else if (cmd == "flush" && initialized) {
            uint16_t sev_id; iss >> std::hex >> sev_id;
            if (IdsM_FlushEvents(sev_id) == E_OK) {
                std::cout << "[IDSM] Events flushed to sinks\n";
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
