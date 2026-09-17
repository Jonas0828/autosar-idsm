/*
 * pipeline.cpp -- the host_probe detection pipeline (see pipeline.h).
 *
 * Feed path per event kind:
 *   EXEC        -> unknown-exec (allowlist) -> priv-esc -> fork-flood
 *                  -> rev-shell -> root-shell
 *   FILE_SCAN   -> file-mod (hash baseline) -> new-setuid
 *   MODULE_SCAN -> kmod-load (module baseline)
 *   SNAPSHOT    -> zombie-storm -> res-exhaust
 *
 * Everything runs on the caller's thread; alerts go out through cb_.
 */
#include "pipeline.h"

#include "baseline.h"

#include <set>
#include <utility>

namespace hostprobe {

struct HostProbePipeline::Impl {
    explicit Impl(AlertCallback cb) : cb_(std::move(cb)) {}

    Config        cfg;
    AlertCallback cb_;

    UnknownExecDetector   unknown_exec_;
    PrivEscDetector       priv_esc_;
    ForkFloodDetector     fork_flood_;
    RevShellDetector      rev_shell_;
    FileModDetector       file_mod_;
    NewSetuidDetector     new_setuid_;
    KmodLoadDetector      kmod_;
    ZombieStormDetector   zombie_;
    ResExhaustDetector    res_;
    RootShellDetector     root_shell_;

    void emit(const HostAlert& a) { cb_(a); }
};

HostProbePipeline::HostProbePipeline(AlertCallback cb)
    : m_(std::make_unique<Impl>(std::move(cb))) {}
HostProbePipeline::~HostProbePipeline() = default;

UnknownExecDetector&   HostProbePipeline::unknown_exec() { return m_->unknown_exec_; }
PrivEscDetector&       HostProbePipeline::priv_esc()     { return m_->priv_esc_; }
ForkFloodDetector&     HostProbePipeline::fork_flood()   { return m_->fork_flood_; }
RevShellDetector&      HostProbePipeline::rev_shell()    { return m_->rev_shell_; }
FileModDetector&       HostProbePipeline::file_mod()     { return m_->file_mod_; }
NewSetuidDetector&     HostProbePipeline::new_setuid()   { return m_->new_setuid_; }
KmodLoadDetector&      HostProbePipeline::kmod()         { return m_->kmod_; }
ZombieStormDetector&   HostProbePipeline::zombie()       { return m_->zombie_; }
ResExhaustDetector&    HostProbePipeline::res()          { return m_->res_; }
RootShellDetector&     HostProbePipeline::root_shell()   { return m_->root_shell_; }
HostProbePipeline::Config& HostProbePipeline::config()   { return m_->cfg; }

bool HostProbePipeline::load_exec_allowlist(const std::string& path,
                                            std::string& err, size_t* bad) {
    std::set<std::string> exact, base;
    if (!load_exec_allowlist_file(path, exact, base, err, bad)) return false;
    for (const auto& e : exact) m_->unknown_exec_.add_allowed(e);
    for (const auto& b : base) m_->unknown_exec_.add_allowed(b);
    return true;
}

bool HostProbePipeline::load_file_baseline(const std::string& path,
                                           std::string& err, size_t* bad) {
    FileBaseline fb;
    if (!load_file_baseline_file(path, fb, err, bad)) return false;
    for (const auto& kv : fb)
        m_->new_setuid_.add_baseline_path(kv.first);
    m_->file_mod_.set_baseline(std::move(fb));
    return true;
}

bool HostProbePipeline::load_module_baseline(const std::string& path,
                                             std::string& err, size_t* bad) {
    std::set<std::string> names;
    if (!load_module_baseline_file(path, names, err, bad)) return false;
    for (const auto& n : names) m_->kmod_.add_baseline(n);
    return true;
}

void HostProbePipeline::feed_event(const HostEvent& ev) {
    switch (ev.kind) {
    case HostEventKind::EXEC:
        if (auto a = m_->unknown_exec_.feed(ev.exec, ev.ts_ms)) m_->emit(*a);
        if (auto a = m_->priv_esc_.feed(ev.exec, ev.ts_ms))     m_->emit(*a);
        if (auto a = m_->fork_flood_.feed(ev.exec, ev.ts_ms))   m_->emit(*a);
        if (auto a = m_->rev_shell_.feed(ev.exec, ev.ts_ms))    m_->emit(*a);
        if (auto a = m_->root_shell_.feed(ev.exec, ev.ts_ms))   m_->emit(*a);
        break;
    case HostEventKind::FILE_SCAN:
        if (auto a = m_->file_mod_.feed(ev.file, ev.ts_ms))   m_->emit(*a);
        if (auto a = m_->new_setuid_.feed(ev.file, ev.ts_ms)) m_->emit(*a);
        break;
    case HostEventKind::MODULE_SCAN:
        if (auto a = m_->kmod_.feed(ev.module, ev.ts_ms)) m_->emit(*a);
        break;
    case HostEventKind::SNAPSHOT:
        if (auto a = m_->zombie_.feed(ev.snap, ev.ts_ms)) m_->emit(*a);
        if (auto a = m_->res_.feed(ev.snap, ev.ts_ms))    m_->emit(*a);
        break;
    }
}

} /* namespace hostprobe */
