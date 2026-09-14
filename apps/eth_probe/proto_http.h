#pragma once
/*
 * proto_http.h — HTTP/1.1 start-line + header block parsing over
 * reassembled TCP streams. No body handling, no chunked reassembly.
 */
#include <cstddef>
#include <cstdint>
#include <string>

namespace ethprobe {

enum HttpError : int {
    HTTP_OK = 0,
    HTTP_NOT_HTTP    = 1,  /* does not start like HTTP/1.x */
    HTTP_INCOMPLETE  = 2,  /* header block not fully present yet */
    HTTP_ERR_MALFORMED = 3,
    HTTP_ERR_URI_TOO_LONG = 4,
};

inline constexpr size_t HTTP_MAX_URI    = 2048;
inline constexpr size_t HTTP_MAX_HEADER = 8192;

struct HttpMessage {
    bool is_request  = false;
    bool is_response = false;
    std::string method;      /* request only */
    std::string uri;         /* request only */
    uint16_t    status = 0;  /* response only */
    std::string version;
    /* header block view (after start line, before the blank line) */
    const uint8_t* header_block     = nullptr;
    size_t         header_block_len = 0;
    size_t         consumed = 0;   /* bytes through end of header block */
    int            error = HTTP_OK;
};

/* True when buf plausibly starts an HTTP request or response */
bool looks_like_http(const uint8_t* data, size_t len);

HttpMessage parse_http(const uint8_t* data, size_t len);

/* alert aux codes for detector_type 10 */
inline constexpr uint32_t HTTP_ALERT_MALFORMED    = 0xA001;
inline constexpr uint32_t HTTP_ALERT_URI_TOO_LONG = 0xA002;

} /* namespace ethprobe */
