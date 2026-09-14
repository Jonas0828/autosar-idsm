#include "proto_http.h"

#include <cstring>

namespace ethprobe {

namespace {

const char* kMethods[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
};

bool starts_with(const uint8_t* d, size_t len, const char* prefix) {
    const size_t n = std::strlen(prefix);
    return len >= n && std::memcmp(d, prefix, n) == 0;
}

/* find CRLF CRLF within [data, data+len); returns index of the first CR */
size_t find_header_end(const uint8_t* d, size_t len) {
    for (size_t i = 0; i + 3 < len; ++i) {
        if (d[i] == '\r' && d[i + 1] == '\n' && d[i + 2] == '\r' && d[i + 3] == '\n')
            return i;
    }
    return static_cast<size_t>(-1);
}

} /* namespace */

bool looks_like_http(const uint8_t* data, size_t len) {
    if (data == nullptr || len < 4) return false;
    for (const char* m : kMethods) {
        const size_t n = std::strlen(m);
        if (len > n && std::memcmp(data, m, n) == 0 && data[n] == ' ') return true;
    }
    return starts_with(data, len, "HTTP/");
}

HttpMessage parse_http(const uint8_t* data, size_t len) {
    HttpMessage m;
    if (!looks_like_http(data, len)) {
        m.error = HTTP_NOT_HTTP;
        return m;
    }
    if (len > HTTP_MAX_HEADER) len = HTTP_MAX_HEADER;
    const size_t hdr_end = find_header_end(data, len);
    if (hdr_end == static_cast<size_t>(-1)) {
        m.error = HTTP_INCOMPLETE;
        return m;
    }
    m.consumed = hdr_end + 4;

    /* start line */
    const uint8_t* line = data;
    size_t line_len = hdr_end;
    for (size_t i = 0; i < hdr_end; ++i) {
        if (data[i] == '\r') { line_len = i; break; }
    }
    const std::string sl(reinterpret_cast<const char*>(line), line_len);

    if (starts_with(line, line_len, "HTTP/")) {
        m.is_response = true;
        const auto sp1 = sl.find(' ');
        if (sp1 == std::string::npos || sp1 + 4 > sl.size()) {
            m.error = HTTP_ERR_MALFORMED;
            return m;
        }
        m.version = sl.substr(5, sp1 - 5);
        m.status  = static_cast<uint16_t>(std::strtoul(sl.c_str() + sp1 + 1, nullptr, 10));
    } else {
        m.is_request = true;
        const auto sp1 = sl.find(' ');
        const auto sp2 = sl.rfind(' ');
        if (sp1 == std::string::npos || sp2 == sp1) {
            m.error = HTTP_ERR_MALFORMED;
            return m;
        }
        m.method  = sl.substr(0, sp1);
        m.uri     = sl.substr(sp1 + 1, sp2 - sp1 - 1);
        m.version = sl.substr(sp2 + 1);
        if (m.version.rfind("HTTP/", 0) != 0) {
            m.error = HTTP_ERR_MALFORMED;
            return m;
        }
        if (m.uri.size() > HTTP_MAX_URI) {
            m.error = HTTP_ERR_URI_TOO_LONG;
            return m;
        }
    }

    /* header block between start line and blank line */
    size_t block_off = line_len + 2;  /* skip CRLF */
    if (block_off <= hdr_end) {
        m.header_block     = data + block_off;
        m.header_block_len = hdr_end - block_off;
    }
    return m;
}

} /* namespace ethprobe */
