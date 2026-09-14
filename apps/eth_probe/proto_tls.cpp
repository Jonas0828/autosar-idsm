#include "proto_tls.h"

#include "md5.h"

#include <sstream>

namespace ethprobe {

namespace {

inline uint16_t rd16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

bool is_grease(uint16_t v) {
    /* GREASE values: 0x0A0A, 0x1A1A, ..., 0xFAFA (RFC 8701) */
    return (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0x00FF);
}

void append_u16(std::ostringstream& ss, uint16_t v, bool& first) {
    if (!first) ss << '-';
    ss << v;
    first = false;
}

} /* namespace */

bool looks_like_tls(const uint8_t* data, size_t len) {
    if (data == nullptr || len < 3) return false;
    if (data[0] < 20 || data[0] > 23) return false;   /* cc, alert, handshake, appdata */
    return data[1] == 0x03 && data[2] <= 0x04;
}

TlsClientHello parse_tls_client_hello(const uint8_t* data, size_t len) {
    TlsClientHello h;
    if (!looks_like_tls(data, len)) {
        h.error = TLS_NOT_TLS;
        return h;
    }
    if (len < 5) { h.error = TLS_ERR_TRUNCATED; return h; }
    const uint8_t  rectype = data[0];
    h.record_version = rd16(data + 1);
    const uint16_t reclen = rd16(data + 3);
    if (rectype != 22) { h.error = TLS_ERR_NOT_CLIENTHELLO; return h; }
    if (len < 5 + static_cast<size_t>(reclen)) { h.error = TLS_ERR_TRUNCATED; return h; }
    if (reclen < 4 || data[5] != 1) { h.error = TLS_ERR_NOT_CLIENTHELLO; return h; }

    /* handshake body */
    const uint8_t* p   = data + 5 + 4;
    size_t         rem = reclen - 4;
    h.consumed = 5 + reclen;

    if (rem < 34) { h.error = TLS_ERR_MALFORMED; return h; }
    h.client_version = rd16(p);
    p += 2 + 32;  /* version + random */
    rem -= 34;

    /* session id */
    if (rem < 1) { h.error = TLS_ERR_MALFORMED; return h; }
    const uint8_t sid_len = p[0];
    p += 1; rem -= 1;
    if (rem < sid_len) { h.error = TLS_ERR_MALFORMED; return h; }
    p += sid_len; rem -= sid_len;

    /* cipher suites */
    if (rem < 2) { h.error = TLS_ERR_MALFORMED; return h; }
    const uint16_t cs_len = rd16(p);
    p += 2; rem -= 2;
    if (rem < cs_len || cs_len % 2 != 0) { h.error = TLS_ERR_MALFORMED; return h; }
    std::ostringstream ja3;
    ja3 << h.client_version << ',';
    {
        bool first = true;
        for (uint16_t i = 0; i + 1 < cs_len; i += 2) {
            const uint16_t cs = rd16(p + i);
            if (!is_grease(cs)) append_u16(ja3, cs, first);
        }
    }
    p += cs_len; rem -= cs_len;
    ja3 << ',';

    /* compression methods */
    if (rem < 1) { h.error = TLS_ERR_MALFORMED; return h; }
    const uint8_t comp_len = p[0];
    p += 1; rem -= 1;
    if (rem < comp_len) { h.error = TLS_ERR_MALFORMED; return h; }
    p += comp_len; rem -= comp_len;

    /* extensions */
    std::string exts, curves, formats;
    if (rem >= 2) {
        const uint16_t ext_total = rd16(p);
        p += 2; rem -= 2;
        if (rem < ext_total) { h.error = TLS_ERR_MALFORMED; return h; }
        size_t eoff = 0;
        {
            std::ostringstream e_ss, c_ss, f_ss;
            bool e_first = true, c_first = true, f_first = true;
            while (eoff + 4 <= ext_total) {
                const uint16_t etype = rd16(p + eoff);
                const uint16_t elen  = rd16(p + eoff + 2);
                if (eoff + 4 + elen > ext_total) { h.error = TLS_ERR_MALFORMED; return h; }
                const uint8_t* ed = p + eoff + 4;
                if (!is_grease(etype)) append_u16(e_ss, etype, e_first);

                if (etype == 0x0000 && elen >= 5) {  /* server_name */
                    const uint16_t list_len = rd16(ed);
                    if (list_len + 2 <= elen && ed[2] == 0) {
                        const uint16_t name_len = rd16(ed + 3);
                        if (5 + name_len <= elen)
                            h.sni.assign(reinterpret_cast<const char*>(ed + 5), name_len);
                    }
                } else if (etype == 0x000A && elen >= 2) {  /* supported_groups */
                    const uint16_t glen = rd16(ed);
                    for (uint16_t i = 0; i + 1 < glen && 2 + i + 1 < elen; i += 2) {
                        const uint16_t g = rd16(ed + 2 + i);
                        if (!is_grease(g)) append_u16(c_ss, g, c_first);
                    }
                } else if (etype == 0x000B && elen >= 1) {  /* ec_point_formats */
                    const uint8_t flen = ed[0];
                    for (uint8_t i = 0; i < flen && 1 + i < elen; ++i)
                        append_u16(f_ss, ed[1 + i], f_first);
                }
                eoff += 4 + elen;
            }
            exts    = e_ss.str();
            curves  = c_ss.str();
            formats = f_ss.str();
        }
    }

    ja3 << exts << ',' << curves << ',' << formats;
    h.ja3 = ja3.str();
    Md5 md;
    md.update(h.ja3);
    h.ja3_hash = md.final_hex();
    h.valid = true;
    return h;
}

} /* namespace ethprobe */
