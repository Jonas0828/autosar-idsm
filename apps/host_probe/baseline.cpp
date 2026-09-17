/*
 * baseline.cpp -- baseline/allowlist file loaders (see baseline.h).
 */
#include "baseline.h"

#include <fstream>
#include <sstream>

namespace hostprobe {

namespace {

/* strip '#' comments and trailing/leading whitespace of the remainder */
std::string clean_line(std::string line) {
    const auto hash = line.find('#');
    if (hash != std::string::npos) line.erase(hash);
    const auto first = line.find_first_not_of(" \t\r");
    if (first == std::string::npos) return {};
    const auto last = line.find_last_not_of(" \t\r");
    return line.substr(first, last - first + 1);
}

} /* namespace */

bool load_exec_allowlist_file(const std::string& path,
                              std::set<std::string>& exact,
                              std::set<std::string>& base,
                              std::string& err, size_t* bad) {
    std::ifstream in(path);
    if (!in) {
        err = "cannot open exec allowlist: " + path;
        return false;
    }
    size_t skipped = 0;
    std::string line;
    while (std::getline(in, line)) {
        const std::string entry = clean_line(std::move(line));
        if (entry.empty()) continue;
        if (entry.find_first_of(" \t") != std::string::npos) {
            ++skipped;   /* exe paths / comms never contain spaces */
            continue;
        }
        if (entry.find('/') != std::string::npos)
            exact.insert(entry);
        else
            base.insert(entry);
    }
    if (bad) *bad = skipped;
    return true;
}

bool load_file_baseline_file(const std::string& path, FileBaseline& out,
                             std::string& err, size_t* bad) {
    std::ifstream in(path);
    if (!in) {
        err = "cannot open file baseline: " + path +
              " (generate one with: sha256sum <files> > " + path + ")";
        return false;
    }
    size_t skipped = 0;
    std::string line;
    while (std::getline(in, line)) {
        const std::string entry = clean_line(std::move(line));
        if (entry.empty()) continue;

        /* sha256sum format: 64 hex chars, whitespace, path */
        if (entry.size() < SHA256_LEN * 2 + 2) {
            ++skipped;
            continue;
        }
        std::array<uint8_t, SHA256_LEN> digest{};
        if (!sha256_from_hex(entry.substr(0, SHA256_LEN * 2), digest.data())) {
            ++skipped;
            continue;
        }
        const auto ws = entry.find_first_of(" \t", SHA256_LEN * 2);
        if (ws == std::string::npos) {
            ++skipped;
            continue;
        }
        const auto path_start = entry.find_first_not_of(" \t", ws);
        if (path_start == std::string::npos) {
            ++skipped;
            continue;
        }
        out[entry.substr(path_start)] = digest;
    }
    if (bad) *bad = skipped;
    return true;
}

bool load_module_baseline_file(const std::string& path,
                               std::set<std::string>& out,
                               std::string& err, size_t* bad) {
    if (!load_name_set(path, out, err, bad)) {
        err += " (generate one with: awk '{print $1}' /proc/modules"
               " | sort > " + path + ")";
        return false;
    }
    return true;
}

bool load_name_set(const std::string& path, std::set<std::string>& out,
                   std::string& err, size_t* bad) {
    std::ifstream in(path);
    if (!in) {
        err = "cannot open name list: " + path;
        return false;
    }
    size_t skipped = 0;
    std::string line;
    while (std::getline(in, line)) {
        const std::string entry = clean_line(std::move(line));
        if (entry.empty()) continue;
        if (entry.find(' ') != std::string::npos)
            ++skipped;   /* module names / comms never contain spaces */
        else
            out.insert(entry);
    }
    if (bad) *bad = skipped;
    return true;
}

} /* namespace hostprobe */
