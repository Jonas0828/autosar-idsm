#pragma once
/*
 * proto_someip.h — SOME/IP (+ SOME/IP-SD) parsing and SD state tracking.
 *
 * SOME/IP header (16 bytes):
 *   service_id(2) method_id(2) length(4) client_id(2) session_id(2)
 *   proto_ver(1) iface_ver(1) msg_type(1) return_code(1)
 * SD uses service_id=0xFFFF, method_id=0x8100, UDP (default port 30490).
 */
#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <vector>

namespace ethprobe {

inline constexpr uint16_t SOMEIP_DEFAULT_PORT = 30490;

inline constexpr uint16_t SOMEIP_SD_SERVICE = 0xFFFF;
inline constexpr uint16_t SOMEIP_SD_METHOD  = 0x8100;

/* msg_type values */
inline constexpr uint8_t SOMEIP_MT_REQUEST       = 0x00;
inline constexpr uint8_t SOMEIP_MT_REQUEST_NO_RET = 0x01;
inline constexpr uint8_t SOMEIP_MT_NOTIFICATION  = 0x02;
inline constexpr uint8_t SOMEIP_MT_RESPONSE      = 0x80;
inline constexpr uint8_t SOMEIP_MT_ERROR         = 0x81;

/* SD entry types (alert aux values reuse these where relevant) */
inline constexpr uint8_t SOMEIP_SD_ENTRY_FIND  = 0x00;
inline constexpr uint8_t SOMEIP_SD_ENTRY_OFFER = 0x01;

enum SomeipError : int {
    SOMEIP_OK = 0,
    SOMEIP_ERR_TRUNCATED   = 1,
    SOMEIP_ERR_LENGTH      = 2,   /* length field inconsistent with frame */
    SOMEIP_ERR_PROTO_VER   = 3,   /* protocol version != 0x01 */
    SOMEIP_ERR_MSG_TYPE    = 4,   /* reserved message type */
};

struct SomeipInfo {
    bool     valid = false;
    uint16_t service_id  = 0;
    uint16_t method_id   = 0;
    uint16_t client_id   = 0;
    uint16_t session_id  = 0;
    uint8_t  iface_ver   = 0;
    uint8_t  msg_type    = 0;
    uint8_t  return_code = 0;
    const uint8_t* payload = nullptr;
    size_t         avail   = 0;
    int      error = SOMEIP_OK;

    bool is_sd() const { return service_id == SOMEIP_SD_SERVICE; }
};

SomeipInfo parse_someip(const uint8_t* data, size_t len);

/* One parsed SD service entry (Find/Offer; Subscribe entries not expanded) */
struct SdEntry {
    uint8_t  type        = 0;
    uint16_t service_id  = 0;
    uint16_t instance_id = 0;
    uint32_t ttl         = 0;
};

bool parse_someip_sd_entries(const uint8_t* payload, size_t len,
                             std::vector<SdEntry>& out);

/*
 * SD state machine: tracks offered services and per-source session ids.
 * Emits alert aux codes:
 *   0x1000 + service_id → Offer for a non-whitelisted service
 *   0x2000              → session-id wrap (node reboot / spoofed identity)
 */
class SomeipSdTracker {
public:
    struct Config {
        std::set<uint16_t> service_whitelist;  /* empty = all services allowed */
    };

    SomeipSdTracker();  /* empty whitelist */
    explicit SomeipSdTracker(const Config& cfg);
    ~SomeipSdTracker();

    SomeipSdTracker(const SomeipSdTracker&) = delete;
    SomeipSdTracker& operator=(const SomeipSdTracker&) = delete;

    /* Reconfigure the whitelist (keeps existing session state). */
    void set_config(const Config& cfg);

    /* Inspect one valid SD message; src_ip identifies the sending node. */
    std::vector<uint32_t> inspect(const SomeipInfo& info,
                                  const uint8_t src_ip[16],
                                  uint64_t now_ms);

private:
    struct Impl;
    std::unique_ptr<Impl> m_;
};

} /* namespace ethprobe */
