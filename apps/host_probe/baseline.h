#pragma once
/*
 * baseline.h -- allow/baseline files for host_probe.
 *
 * Three baselines, all line-based text with '#' comments (see the
 * baseline/ examples):
 *
 *   exec allowlist   one entry per line: exact exe path (contains '/')
 *                    or bare basename ("sshd"); an exec whose exe path
 *                    or basename is listed is "known"
 *   file baseline    "sha256hex  path" per line (sha256sum output
 *                    format); the same paths also form the known-path
 *                    set for the new-setuid detector
 *   module baseline  one kernel module name per line
 */
#include "sha256.h"

#include <array>
#include <cstddef>
#include <map>
#include <set>
#include <string>

namespace hostprobe {

/* path -> expected digest */
using FileBaseline = std::map<std::string, std::array<uint8_t, SHA256_LEN>>;

/*
 * Exec allowlist: entries containing '/' go to `exact`, bare names to
 * `base`. Returns false if the file cannot be opened; *bad (if given)
 * receives the skipped line count. (The *_file suffix keeps the free
 * functions distinguishable from same-named pipeline members.)
 */
bool load_exec_allowlist_file(const std::string& path,
                              std::set<std::string>& exact,
                              std::set<std::string>& base,
                              std::string& err, size_t* bad = nullptr);

/* "sha256hex  path" lines (paths may not contain spaces) */
bool load_file_baseline_file(const std::string& path, FileBaseline& out,
                             std::string& err, size_t* bad = nullptr);

/* one module name per line */
bool load_module_baseline_file(const std::string& path,
                               std::set<std::string>& out,
                               std::string& err, size_t* bad = nullptr);

/* generic "one name per line" loader (network-daemon comm overrides) */
bool load_name_set(const std::string& path, std::set<std::string>& out,
                   std::string& err, size_t* bad = nullptr);

} /* namespace hostprobe */
