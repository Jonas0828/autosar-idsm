/*
 * event.cpp -- host event model: replay-log parsing (see event.h).
 */
#include "event.h"

#include <cstdlib>
#include <cstring>
#include <sstream>

namespace hostprobe {

namespace {

bool parse_u32(const std::string& s, uint32_t& out) {
    char* end = nullptr;
    const unsigned long v = std::strtoul(s.c_str(), &end, 10);
    if (end == s.c_str() || *end != '\0') return false;
    out = static_cast<uint32_t>(v);
    return true;
}

bool parse_u64(const std::string& s, uint64_t& out) {
    char* end = nullptr;
    const unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (end == s.c_str() || *end != '\0') return false;
    out = static_cast<uint64_t>(v);
    return true;
}

void copy_comm(char (&dst)[COMM_LEN], const std::string& s) {
    std::memset(dst, 0, COMM_LEN);
    std::strncpy(dst, s.c_str(), COMM_LEN - 1);
}

bool hex_to_bytes(const std::string& hex, uint8_t* out, size_t n) {
    if (hex.size() != n * 2) return false;
    for (size_t i = 0; i < n; ++i) {
        const auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int hi = nib(hex[2 * i]);
        const int lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

} /* namespace */

bool parse_host_event(const std::string& line_in, HostEvent& out) {
    std::string line = line_in;
    const auto hash = line.find('#');
    if (hash != std::string::npos) line.erase(hash);

    std::istringstream iss(line);
    std::string kind;
    if (!(iss >> kind)) return false;  /* blank / comment-only line */

    out = HostEvent{};

    if (kind == "exec") {
        std::string ts, comm, parent;
        if (!(iss >> ts >> out.exec.pid >> out.exec.ppid >> out.exec.uid >>
              out.exec.euid >> out.exec.gid >> out.exec.egid >> comm >> parent))
            return false;
        if (!parse_u64(ts, out.ts_ms)) return false;
        copy_comm(out.exec.comm, comm);
        copy_comm(out.exec.parent_comm, parent);
        std::string exe;
        if (iss >> exe) out.exec.exe = exe;
        out.kind = HostEventKind::EXEC;
        return true;
    }

    if (kind == "file") {
        std::string ts, present, mode, uid, sha;
        if (!(iss >> ts >> out.file.path >> present >> mode >> uid >> sha))
            return false;
        if (!parse_u64(ts, out.ts_ms)) return false;
        out.file.present = present == "1";
        char* end = nullptr;
        const unsigned long mv = std::strtoul(mode.c_str(), &end, 8);
        if (end == mode.c_str() || *end != '\0') return false;
        out.file.mode = static_cast<uint32_t>(mv);
        if (!parse_u32(uid, out.file.uid)) return false;
        if (out.file.present && sha != "-") {
            if (!hex_to_bytes(sha, out.file.sha256, sizeof(out.file.sha256)))
                return false;
        }
        out.kind = HostEventKind::FILE_SCAN;
        return true;
    }

    if (kind == "module") {
        std::string ts;
        if (!(iss >> ts >> out.module.name)) return false;
        if (!parse_u64(ts, out.ts_ms)) return false;
        out.kind = HostEventKind::MODULE_SCAN;
        return true;
    }

    if (kind == "snap") {
        std::string ts, cpu_pid, cpu_uid, cpu_ppm, mem_pid, mem_uid, mem_kb,
            cpu_comm, mem_comm;
        if (!(iss >> ts >> out.snap.zombies >> cpu_pid >> cpu_uid >> cpu_ppm >>
              cpu_comm >> mem_pid >> mem_uid >> mem_kb >> mem_comm))
            return false;
        if (!parse_u64(ts, out.ts_ms)) return false;
        if (!parse_u32(cpu_pid, out.snap.top_cpu_pid) ||
            !parse_u32(cpu_uid, out.snap.top_cpu_uid) ||
            !parse_u32(cpu_ppm, out.snap.top_cpu_ppm) ||
            !parse_u32(mem_pid, out.snap.top_mem_pid) ||
            !parse_u32(mem_uid, out.snap.top_mem_uid) ||
            !parse_u64(mem_kb, out.snap.top_mem_rss_kb))
            return false;
        copy_comm(out.snap.top_cpu_comm, cpu_comm);
        copy_comm(out.snap.top_mem_comm, mem_comm);
        out.kind = HostEventKind::SNAPSHOT;
        return true;
    }

    return false;
}

} /* namespace hostprobe */
