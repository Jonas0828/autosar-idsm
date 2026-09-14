#include "proto_someip.h"

#include <array>
#include <cstring>
#include <map>

namespace ethprobe {

namespace {

inline uint16_t rd16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}
inline uint32_t rd32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |  static_cast<uint32_t>(p[3]);
}

bool known_msg_type(uint8_t t) {
    switch (t) {
        case SOMEIP_MT_REQUEST:
        case SOMEIP_MT_REQUEST_NO_RET:
        case SOMEIP_MT_NOTIFICATION:
        case SOMEIP_MT_RESPONSE:
        case SOMEIP_MT_ERROR:
            return true;
        default:
            return false;
    }
}

} /* namespace */

SomeipInfo parse_someip(const uint8_t* data, size_t len) {
    SomeipInfo i;
    if (data == nullptr || len < 16) {
        i.error = SOMEIP_ERR_TRUNCATED;
        return i;
    }
    i.service_id  = rd16(data);
    i.method_id   = rd16(data + 2);
    const uint32_t length = rd32(data + 4);
    i.client_id   = rd16(data + 8);
    i.session_id  = rd16(data + 10);
    const uint8_t proto_ver = data[12];
    i.iface_ver   = data[13];
    i.msg_type    = data[14];
    i.return_code = data[15];
    i.payload     = data + 16;
    i.avail       = len - 16;

    /* length covers request-id..end: 8 (client/session/ver/type/rcode) + payload */
    if (length < 8 || static_cast<uint64_t>(length) - 8 > i.avail) {
        i.error = SOMEIP_ERR_LENGTH;
        return i;
    }
    if (proto_ver != 0x01) {
        i.error = SOMEIP_ERR_PROTO_VER;
        return i;
    }
    if (!known_msg_type(i.msg_type)) {
        i.error = SOMEIP_ERR_MSG_TYPE;
        return i;
    }
    i.valid = true;
    return i;
}

bool parse_someip_sd_entries(const uint8_t* p, size_t len,
                             std::vector<SdEntry>& out) {
    /* SD payload: flags(1) reserved(3) entries_len(4) entries... options_len(4)... */
    if (p == nullptr || len < 8) return false;
    const uint32_t entries_len = rd32(p + 4);
    if (entries_len > len - 8 || entries_len % 16 != 0) return false;
    const uint8_t* e = p + 8;
    for (uint32_t off = 0; off < entries_len; off += 16) {
        SdEntry se;
        se.type        = e[off];
        se.service_id  = rd16(e + off + 4);
        se.instance_id = rd16(e + off + 6);
        se.ttl         = (static_cast<uint32_t>(e[off + 9]) << 16) |
                         (static_cast<uint32_t>(e[off + 10]) << 8) | e[off + 11];
        out.push_back(se);
    }
    return true;
}

/* ---- SD tracker --------------------------------------------------------- */

struct SomeipSdTracker::Impl {
    Config cfg;
    /* last session id per sending node (reboot detection) */
    std::map<std::array<uint8_t, 16>, uint16_t> last_session;
};

SomeipSdTracker::SomeipSdTracker() : SomeipSdTracker(Config{}) {}

SomeipSdTracker::SomeipSdTracker(const Config& cfg) : m_(std::make_unique<Impl>()) {
    m_->cfg = cfg;
}

SomeipSdTracker::~SomeipSdTracker() = default;

void SomeipSdTracker::set_config(const Config& cfg) {
    m_->cfg = cfg;
}

std::vector<uint32_t> SomeipSdTracker::inspect(const SomeipInfo& info,
                                               const uint8_t src_ip[16],
                                               uint64_t /*now_ms*/) {
    std::vector<uint32_t> alerts;
    if (!info.valid || !info.is_sd()) return alerts;

    /* session-id wrap: a rebooting node restarts its session counter;
       a sudden decrease (outside the 0xFFFF wrap) is also a spoofing signal */
    std::array<uint8_t, 16> key{};
    std::memcpy(key.data(), src_ip, 16);
    auto [it, inserted] = m_->last_session.emplace(key, info.session_id);
    if (!inserted) {
        const uint16_t prev = it->second;
        if (info.session_id < prev && !(prev > 0xFF00 && info.session_id < 0x0100)) {
            alerts.push_back(0x2000);
        }
        it->second = info.session_id;
    }

    /* entries: offer whitelist enforcement */
    std::vector<SdEntry> entries;
    if (parse_someip_sd_entries(info.payload, info.avail, entries)) {
        for (const auto& e : entries) {
            if (e.type == SOMEIP_SD_ENTRY_OFFER && e.ttl > 0 &&
                !m_->cfg.service_whitelist.empty() &&
                m_->cfg.service_whitelist.count(e.service_id) == 0) {
                alerts.push_back(0x1000u + e.service_id);
            }
        }
    }
    return alerts;
}

} /* namespace ethprobe */
