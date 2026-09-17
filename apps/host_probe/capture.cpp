/*
 * capture.cpp -- event sources for host_probe (see capture.h).
 *
 * The /proc readers here are deliberately defensive: a process can
 * vanish between readdir() and open(), fields may be missing on
 * non-mainline kernels (Android), so every read is best-effort and
 * failures degrade to empty fields rather than dropped events.
 */
#include "capture.h"

#include "sha256.h"

#include <chrono>
#include <cstring>
#include <dirent.h>
#include <errno.h>
#include <fstream>
#include <map>
#include <poll.h>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <sys/socket.h>
#include <linux/netlink.h>
#if defined(__has_include)
   /* quote form: GCC's angle-bracket __has_include misses /usr/include
      on some distros (verified on Ubuntu 20.04 + gcc 9.4) */
#  if __has_include("linux/connector.h") && __has_include("linux/cn_proc.h")
#    include <linux/connector.h>
#    include <linux/cn_proc.h>
#    define HOSTPROBE_HAVE_CN_PROC 1
#  endif
#endif

namespace hostprobe {

namespace {

uint64_t monotonic_ms() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

void copy_comm(char (&dst)[COMM_LEN], const std::string& s) {
    std::memset(dst, 0, COMM_LEN);
    std::strncpy(dst, s.c_str(), COMM_LEN - 1);
}

bool read_file(const std::string& path, std::string& out) {
    std::ifstream in(path);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

/*
 * Parse /proc/<pid>/stat. The comm field may contain spaces and
 * parentheses, so everything after the LAST ')' is split into fields:
 *   idx0 = state, idx1 = ppid, idx11 = utime, idx12 = stime,
 *   idx21 = rss (pages, may be negative on some kernels).
 */
bool read_stat(uint32_t pid, char& state, uint32_t& ppid, uint64_t& ticks,
               int64_t& rss_pages) {
    std::string raw;
    if (!read_file("/proc/" + std::to_string(pid) + "/stat", raw))
        return false;
    const auto rparen = raw.find_last_of(')');
    if (rparen == std::string::npos) return false;

    std::vector<std::string> f;
    std::istringstream iss(raw.substr(rparen + 1));
    std::string tok;
    while (iss >> tok) f.push_back(tok);
    if (f.size() < 22) return false;

    state = f[0].empty() ? '?' : f[0][0];
    ppid       = static_cast<uint32_t>(std::strtoul(f[1].c_str(), nullptr, 10));
    const uint64_t utime = std::strtoull(f[11].c_str(), nullptr, 10);
    const uint64_t stime = std::strtoull(f[12].c_str(), nullptr, 10);
    ticks = utime + stime;
    const long long rss = std::strtoll(f[21].c_str(), nullptr, 10);
    rss_pages = rss > 0 ? rss : 0;
    return true;
}

/* "Uid:\t<real>\t<effective>\t<saved>\t<fs>" (same for Gid:) */
bool read_status_ids(uint32_t pid, uint32_t& uid, uint32_t& euid,
                     uint32_t& gid, uint32_t& egid) {
    std::string raw;
    if (!read_file("/proc/" + std::to_string(pid) + "/status", raw))
        return false;
    std::istringstream iss(raw);
    std::string line;
    while (std::getline(iss, line)) {
        std::istringstream ls(line);
        std::string tag;
        if (!(ls >> tag)) continue;
        if (tag == "Uid:") {
            uint32_t r = 0, e = 0, s = 0, fs = 0;
            if (!(ls >> r >> e >> s >> fs)) return false;
            uid  = r;
            euid = e;
        } else if (tag == "Gid:") {
            uint32_t r = 0, e = 0, s = 0, fs = 0;
            if (!(ls >> r >> e >> s >> fs)) return false;
            gid  = r;
            egid = e;
        }
    }
    return true;
}

bool read_comm_name(uint32_t pid, char (&comm)[COMM_LEN]) {
    std::string raw;
    if (!read_file("/proc/" + std::to_string(pid) + "/comm", raw))
        return false;
    while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r'))
        raw.pop_back();
    copy_comm(comm, raw);
    return true;
}

bool read_exe_path(uint32_t pid, std::string& exe) {
    char buf[4096];
    const std::string p = "/proc/" + std::to_string(pid) + "/exe";
    const ssize_t n = ::readlink(p.c_str(), buf, sizeof(buf) - 1);
    if (n < 0) return false;
    buf[n] = '\0';
    exe = buf;
    return true;
}

/* Best-effort full ExecEvent for a live pid (netlink gives only pid +
   comm; the poller needs everything anyway). */
bool read_proc_details(uint32_t pid, ExecEvent& e) {
    e.pid = pid;
    char state = '?';
    uint64_t ticks = 0;
    int64_t rss = 0;
    if (read_stat(pid, state, e.ppid, ticks, rss)) {
        char parent[COMM_LEN]{};
        if (read_comm_name(e.ppid, parent)) copy_comm(e.parent_comm, parent);
    }
    read_status_ids(pid, e.uid, e.euid, e.gid, e.egid);
    read_comm_name(pid, e.comm);
    read_exe_path(pid, e.exe);
    return true;  /* degrade gracefully: partial data still feeds detectors */
}

bool is_number(const char* s) {
    if (s == nullptr || *s == '\0') return false;
    for (const char* p = s; *p; ++p)
        if (*p < '0' || *p > '9') return false;
    return true;
}

} /* namespace */

/* ==================== netlink PROC_CONNECTOR ==================== */

NetlinkProcCapture::~NetlinkProcCapture() {
    if (fd_ >= 0) ::close(fd_);
}

bool NetlinkProcCapture::open(std::string& err) {
#ifndef HOSTPROBE_HAVE_CN_PROC
    err = "compiled without PROC_CONNECTOR kernel headers "
          "(linux/connector.h, linux/cn_proc.h); use the /proc poller";
    return false;
#else
    fd_ = ::socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (fd_ < 0) {
        err = "socket(NETLINK_CONNECTOR): " + std::string(std::strerror(errno)) +
              " (root required)";
        return false;
    }

    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    local.nl_pid    = static_cast<uint32_t>(::getpid());
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
        err = "bind: " + std::string(std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    /* subscribe: CN_IDX_PROC / CN_VAL_PROC, PROC_CN_MCAST_LISTEN.
       Raw buffer: cn_msg ends in a zero-size data[] array, so it cannot
       be embedded in a struct together with the payload. */
    uint8_t buf[NLMSG_SPACE(sizeof(cn_msg) + sizeof(int))];
    std::memset(buf, 0, sizeof(buf));
    auto* nlh = reinterpret_cast<nlmsghdr*>(buf);
    nlh->nlmsg_len  = NLMSG_LENGTH(sizeof(cn_msg) + sizeof(int));
    nlh->nlmsg_pid  = static_cast<uint32_t>(::getpid());
    nlh->nlmsg_type = NLMSG_DONE;
    auto* cn = reinterpret_cast<cn_msg*>(NLMSG_DATA(nlh));
    cn->id.idx = CN_IDX_PROC;
    cn->id.val = CN_VAL_PROC;
    cn->len    = sizeof(int);
    const int value = PROC_CN_MCAST_LISTEN;
    std::memcpy(cn->data, &value, sizeof(value));

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (::sendto(fd_, buf, nlh->nlmsg_len, 0,
                 reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) < 0) {
        err = "sendto(PROC_CN_MCAST_LISTEN): " + std::string(std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    /* The kernel answers the LISTEN request with an ack event whose
       err field is 0 on success. Without CAP_NET_ADMIN the request is
       dropped SILENTLY (verified on Ubuntu 5.15: no ack, no events,
       sendto() still succeeds) — so only a positive ack lets us trust
       the subscription; anything else must fall back to the poller. */
    bool acked = false;
    pollfd pfd{fd_, POLLIN, 0};
    if (::poll(&pfd, 1, 1000) > 0) {
        uint8_t abuf[256];
        ssize_t n = ::recv(fd_, abuf, sizeof(abuf), MSG_DONTWAIT);
        for (nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(abuf);
             n > 0 && NLMSG_OK(nlh, n);
             nlh = NLMSG_NEXT(nlh, n)) {
            const auto* cn =
                reinterpret_cast<const cn_msg*>(NLMSG_DATA(nlh));
            if (cn->id.idx != CN_IDX_PROC) continue;
            const auto* pev = reinterpret_cast<const proc_event*>(cn->data);
            if (pev->what == proc_event::PROC_EVENT_NONE &&
                pev->event_data.ack.err != 0) {
                err = "PROC_CONNECTOR subscription refused (need root or "
                      "CAP_NET_ADMIN)";
                ::close(fd_);
                fd_ = -1;
                return false;
            }
            acked = true;
        }
    }
    if (!acked) {
        err = "PROC_CONNECTOR subscription not acknowledged (requires root "
              "or CAP_NET_ADMIN)";
        ::close(fd_);
        fd_ = -1;
        return false;
    }
    return true;
#endif
}

bool NetlinkProcCapture::run(const EventCallback& cb, std::string& err) {
#ifndef HOSTPROBE_HAVE_CN_PROC
    (void)cb;
    err = "PROC_CONNECTOR support not compiled in";
    return false;
#else
    uint8_t buf[4096];
    while (!stop_.load(std::memory_order_relaxed)) {
        pollfd pfd{fd_, POLLIN, 0};
        const int pr = ::poll(&pfd, 1, 500);
        if (pr < 0) {
            if (errno == EINTR) continue;
            err = "poll: " + std::string(std::strerror(errno));
            return false;
        }
        if (pr == 0) continue;  /* timeout: re-check stop flag */

        ssize_t n = ::recv(fd_, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            err = "recv: " + std::string(std::strerror(errno));
            return false;
        }

        for (nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buf);
             NLMSG_OK(nlh, n);
             nlh = NLMSG_NEXT(nlh, n)) {
            if (nlh->nlmsg_type == NLMSG_ERROR ||
                nlh->nlmsg_type == NLMSG_NOOP)
                continue;
            const auto* cn = reinterpret_cast<const cn_msg*>(NLMSG_DATA(nlh));
            if (cn->id.idx != CN_IDX_PROC) continue;
            const auto* pev = reinterpret_cast<const proc_event*>(cn->data);
            /* the event-type enum is scoped inside struct proc_event in
               C++ (anonymous enum member) */
            if (pev->what != proc_event::PROC_EVENT_EXEC)
                continue;  /* fork/exit: not needed */

            HostEvent ev{};
            ev.kind  = HostEventKind::EXEC;
            ev.ts_ms = monotonic_ms();
            ev.exec.pid = pev->event_data.exec.process_pid;
            /* exec events carry no comm: read ids/ppid/exe/comm from /proc */
            read_proc_details(ev.exec.pid, ev.exec);
            cb(ev);
        }
    }
    return true;
#endif
}

void NetlinkProcCapture::stop() {
    stop_.store(true, std::memory_order_relaxed);
}

/* ==================== /proc poller ==================== */

struct ProcScanCapture::Impl {
    std::atomic<bool> stop{false};
    std::vector<std::string> scan_files;
    std::set<uint32_t> known_pids;
    std::map<uint32_t, uint64_t> prev_ticks;   /* pid -> utime+stime */
    std::set<std::string> known_mods;
    bool primed = false;
    uint64_t last_scan_ms = 0;
};

ProcScanCapture::ProcScanCapture() : m_(std::make_unique<Impl>()) {}
ProcScanCapture::~ProcScanCapture() = default;

bool ProcScanCapture::open(uint32_t scan_ms, std::string& err) {
    if (scan_ms == 0) {
        err = "scan interval must be > 0";
        return false;
    }
    scan_ms_ = scan_ms;
    return true;
}

void ProcScanCapture::add_scan_file(const std::string& path) {
    m_->scan_files.push_back(path);
}

void ProcScanCapture::stop() {
    m_->stop.store(true, std::memory_order_relaxed);
}

bool ProcScanCapture::run(const EventCallback& cb, std::string& err) {
    (void)err;
    const long hz = ::sysconf(_SC_CLK_TCK) > 0 ? ::sysconf(_SC_CLK_TCK) : 100;
    const long page_kb =
        ::sysconf(_SC_PAGESIZE) > 0 ? ::sysconf(_SC_PAGESIZE) / 1024 : 4;

    while (!m_->stop.load(std::memory_order_relaxed)) {
        const uint64_t now = monotonic_ms();
        const uint64_t delta_ms =
            m_->last_scan_ms > 0 && now > m_->last_scan_ms
                ? now - m_->last_scan_ms
                : 0;
        m_->last_scan_ms = now;

        uint32_t zombies = 0;
        uint32_t top_cpu_pid = 0, top_cpu_uid = 0, top_cpu_ppm = 0;
        uint32_t top_mem_pid = 0, top_mem_uid = 0;
        uint64_t top_mem_kb = 0;
        char top_cpu_comm[COMM_LEN]{};
        char top_mem_comm[COMM_LEN]{};
        std::map<uint32_t, uint64_t> cur_ticks;

        if (DIR* proc = ::opendir("/proc")) {
            while (dirent* de = ::readdir(proc)) {
                if (!is_number(de->d_name)) continue;
                const uint32_t pid =
                    static_cast<uint32_t>(std::strtoul(de->d_name, nullptr, 10));

                char state = '?';
                uint32_t ppid = 0;
                uint64_t ticks = 0;
                int64_t rss_pages = 0;
                if (!read_stat(pid, state, ppid, ticks, rss_pages))
                    continue;  /* process vanished mid-scan */
                cur_ticks[pid] = ticks;

                /* Only report execs for processes that appear AFTER the
                   first pass: everything alive at startup is baseline.
                   Kernel threads (parent = kthreadd, pid 2) never exec
                   a userspace image, but they do show up in the pid diff
                   (e.g. kworker threads spawned on load); skip them or
                   every kthread birth is a false unknown-exec alert. */
                if (emit_execs_ && m_->primed && !m_->known_pids.count(pid) &&
                    ppid != 2) {
                    HostEvent ev{};
                    ev.kind  = HostEventKind::EXEC;
                    ev.ts_ms = now;
                    read_proc_details(pid, ev.exec);
                    cb(ev);
                }

                if (state == 'Z') ++zombies;

                /* CPU: delta since the previous pass (0 on first pass) */
                uint32_t ppm = 0;
                const auto prev = m_->prev_ticks.find(pid);
                if (prev != m_->prev_ticks.end() && delta_ms > 0 &&
                    ticks >= prev->second) {
                    const uint64_t dticks = ticks - prev->second;
                    ppm = static_cast<uint32_t>(
                        (dticks * 1000000ULL) /
                        (static_cast<uint64_t>(hz) * delta_ms));
                }
                if (ppm > top_cpu_ppm) {
                    top_cpu_pid = pid;
                    top_cpu_ppm = ppm;
                    char comm[COMM_LEN]{};
                    if (read_comm_name(pid, comm)) copy_comm(top_cpu_comm, comm);
                    uint32_t uid = 0, euid = 0, gid = 0, egid = 0;
                    if (read_status_ids(pid, uid, euid, gid, egid))
                        top_cpu_uid = uid;
                }

                const uint64_t rss_kb =
                    static_cast<uint64_t>(rss_pages) *
                    static_cast<uint64_t>(page_kb);
                if (rss_kb > top_mem_kb) {
                    top_mem_pid = pid;
                    top_mem_kb  = rss_kb;
                    char comm[COMM_LEN]{};
                    if (read_comm_name(pid, comm)) copy_comm(top_mem_comm, comm);
                    uint32_t uid = 0, euid = 0, gid = 0, egid = 0;
                    if (read_status_ids(pid, uid, euid, gid, egid))
                        top_mem_uid = uid;
                }
            }
            ::closedir(proc);
        }
        m_->prev_ticks = std::move(cur_ticks);
        /* Known-set MUST be rebuilt from THIS pass's scan, not a second
           /proc walk: a process born between the walk and the rebuild
           would be marked known without ever being reported, i.e. a
           birth in that gap is silently lost. cur_ticks holds exactly
           the pids this pass observed. */
        m_->known_pids.clear();
        for (const auto& kv : m_->prev_ticks) m_->known_pids.insert(kv.first);

        if (m_->primed) {
            HostEvent ev{};
            ev.kind  = HostEventKind::SNAPSHOT;
            ev.ts_ms = now;
            ev.snap.zombies     = zombies;
            ev.snap.top_cpu_pid = top_cpu_pid;
            ev.snap.top_cpu_uid = top_cpu_uid;
            ev.snap.top_cpu_ppm = top_cpu_ppm;
            std::memcpy(ev.snap.top_cpu_comm, top_cpu_comm, COMM_LEN);
            ev.snap.top_mem_pid    = top_mem_pid;
            ev.snap.top_mem_uid    = top_mem_uid;
            ev.snap.top_mem_rss_kb = top_mem_kb;
            std::memcpy(ev.snap.top_mem_comm, top_mem_comm, COMM_LEN);
            cb(ev);
        }

        /* kernel module diff (Linux only; file simply absent elsewhere) */
        if (std::ifstream mods("/proc/modules"); mods) {
            std::string line;
            while (std::getline(mods, line)) {
                std::istringstream ls(line);
                std::string name;
                if (!(ls >> name)) continue;
                if (m_->known_mods.insert(name).second && m_->primed) {
                    HostEvent ev{};
                    ev.kind        = HostEventKind::MODULE_SCAN;
                    ev.ts_ms       = now;
                    ev.module.name = name;
                    cb(ev);
                }
            }
        }

        /* monitored files */
        for (const auto& path : m_->scan_files) {
            HostEvent ev{};
            ev.kind  = HostEventKind::FILE_SCAN;
            ev.ts_ms = now;
            ev.file.path = path;
            struct stat st {};
            if (::stat(path.c_str(), &st) != 0) {
                ev.file.present = false;
            } else {
                ev.file.present = true;
                ev.file.mode    = static_cast<uint32_t>(st.st_mode & 07777);
                ev.file.uid     = static_cast<uint32_t>(st.st_uid);
                if (!sha256_file(path, ev.file.sha256))
                    std::memset(ev.file.sha256, 0, sizeof(ev.file.sha256));
            }
            cb(ev);
        }

        m_->primed = true;

        /* sleep scan_ms in slices so stop() stays responsive */
        for (uint32_t slept = 0; slept < scan_ms_ &&
                                  !m_->stop.load(std::memory_order_relaxed);) {
            const uint32_t slice = scan_ms_ - slept < 100 ? scan_ms_ - slept : 100;
            std::this_thread::sleep_for(std::chrono::milliseconds(slice));
            slept += slice;
        }
    }
    return true;
}

/* ==================== offline replay ==================== */

bool replay_events(const std::string& path, const EventCallback& cb,
                   std::string& err) {
    std::ifstream in(path);
    if (!in) {
        err = "cannot open events file: " + path;
        return false;
    }
    size_t bad = 0;
    std::string line;
    while (std::getline(in, line)) {
        HostEvent ev{};
        if (!parse_host_event(line, ev)) {
            const auto hash = line.find('#');
            const std::string stripped =
                hash == std::string::npos ? line : line.substr(0, hash);
            bool blank = true;
            for (char c : stripped)
                if (c != ' ' && c != '\t' && c != '\r') blank = false;
            if (!blank) ++bad;
            continue;
        }
        cb(ev);
    }
    if (bad > 0)
        err = std::to_string(bad) + " malformed line(s) skipped in " + path;
    return true;
}

} /* namespace hostprobe */
