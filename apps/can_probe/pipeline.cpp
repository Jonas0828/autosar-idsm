/*
 * pipeline.cpp -- the can_probe detection pipeline (see pipeline.h).
 *
 * Feed path per frame:
 *   error frame -> ErrorBurstDetector (nothing else runs on errors)
 *   data frame  -> DLC anomaly check -> RTR check -> unknown ID ->
 *                  cycle time -> per-ID flood -> bus flood
 *   diagnostic request (0x7DF / 0x7E0-0x7E7) additionally:
 *                  diag flood -> UDS SecurityAccess -> service scan
 *
 * Everything runs on the capture thread; alerts go out through cb_.
 */
#include "pipeline.h"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <utility>

namespace canprobe {

struct CanProbePipeline::Impl {
    explicit Impl(AlertCallback cb) : cb_(std::move(cb)) {}

    Config        cfg;
    AlertCallback cb_;

    UnknownIdDetector     unknown_id_;
    CycleAnomalyDetector  cycle_;
    IdFloodDetector       id_flood_;
    BusFloodDetector      bus_flood_;
    ErrorBurstDetector    err_burst_;
    DiagFloodDetector     diag_flood_;
    UdsSecAccessDetector  sec_access_;
    UdsSvcScanDetector    svc_scan_;

    void emit(const CanAlert& a) { cb_(a); }

    void feed_frame(const CanFrame& f, uint64_t now_ms) {
        if (f.err) {
            if (auto a = err_burst_.feed(f, now_ms)) emit(*a);
            return;
        }

        if (auto a = check_dlc_anomaly(f)) emit(*a);
        if (f.rtr) {
            if (auto a = check_remote_frame(f)) emit(*a);
            return;  /* remote frames carry no payload: stop here */
        }

        /* unknown ID: standardized diagnostics addressing is never
           "unknown", even when the whitelist does not list it */
        if (unknown_id_.enabled() &&
            !is_diag_request_id(f.can_id) && !is_diag_response_id(f.can_id)) {
            if (auto a = unknown_id_.feed(f, now_ms)) emit(*a);
        }
        if (auto a = cycle_.feed(f, now_ms)) emit(*a);
        if (auto a = id_flood_.feed(f, now_ms)) emit(*a);
        if (auto a = bus_flood_.feed(f, now_ms)) emit(*a);

        if (is_diag_request_id(f.can_id)) {
            if (auto a = diag_flood_.feed(f, now_ms)) emit(*a);
            if (auto a = sec_access_.feed(f, now_ms)) emit(*a);
            if (auto a = svc_scan_.feed(f, now_ms)) emit(*a);
        }
    }
};

CanProbePipeline::CanProbePipeline(AlertCallback cb)
    : m_(std::make_unique<Impl>(std::move(cb))) {}
CanProbePipeline::~CanProbePipeline() = default;

UnknownIdDetector&    CanProbePipeline::unknown_id()  { return m_->unknown_id_; }
CycleAnomalyDetector& CanProbePipeline::cycle()       { return m_->cycle_; }
IdFloodDetector&      CanProbePipeline::id_flood()    { return m_->id_flood_; }
BusFloodDetector&     CanProbePipeline::bus_flood()   { return m_->bus_flood_; }
ErrorBurstDetector&   CanProbePipeline::err_burst()   { return m_->err_burst_; }
DiagFloodDetector&    CanProbePipeline::diag_flood()  { return m_->diag_flood_; }
UdsSecAccessDetector& CanProbePipeline::sec_access()  { return m_->sec_access_; }
UdsSvcScanDetector&   CanProbePipeline::svc_scan()    { return m_->svc_scan_; }
CanProbePipeline::Config& CanProbePipeline::config()  { return m_->cfg; }

bool CanProbePipeline::load_ids(const std::string& path, std::string& err,
                                size_t* bad) {
    std::ifstream in(path);
    if (!in) {
        err = "cannot open ids file: " + path;
        return false;
    }
    size_t skipped = 0;
    std::string line;
    while (std::getline(in, line)) {
        /* strip comments and trim */
        const auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        std::istringstream iss(line);
        std::string id_tok, min_tok;
        if (!(iss >> id_tok)) continue;  /* blank / comment-only line */
        char* end = nullptr;
        const unsigned long id = std::strtoul(id_tok.c_str(), &end, 16);
        if (end == id_tok.c_str() || *end != '\0' || id > 0x1FFFFFFFUL) {
            ++skipped;
            continue;
        }
        m_->unknown_id_.add_known(static_cast<uint32_t>(id));
        if (iss >> min_tok) {
            end = nullptr;
            const unsigned long min_ms = std::strtoul(min_tok.c_str(), &end, 10);
            if (end == min_tok.c_str() || *end != '\0' || min_ms == 0) {
                ++skipped;
                continue;
            }
            m_->cycle_.add_min_interval(static_cast<uint32_t>(id),
                                        static_cast<uint32_t>(min_ms));
        }
    }
    if (bad) *bad = skipped;
    return true;
}

void CanProbePipeline::feed_raw(const uint8_t* data, size_t len, uint64_t now_ms) {
    CanFrame f;
    if (!parse_can_frame(data, len, f)) return;
    m_->feed_frame(f, now_ms);
}

void CanProbePipeline::feed_frame(const CanFrame& f, uint64_t now_ms) {
    m_->feed_frame(f, now_ms);
}

} /* namespace canprobe */