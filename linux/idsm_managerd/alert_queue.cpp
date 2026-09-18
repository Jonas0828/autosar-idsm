#include "alert_queue.h"

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace idsm {

static std::string pathJoin(const std::string& dir, const char* name) {
    return dir.back() == '/' ? dir + name : dir + "/" + name;
}

bool AlertQueue::open(const std::string& dir, std::string& err) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_dir = dir;
    if (!loadCursor()) {
        /* 无游标文件则从头开始(新部署) */
        m_cursor = 0;
    }
    const std::string p = pathJoin(dir, "alerts.jsonl");
    m_fp = std::fopen(p.c_str(), "a+b");
    if (!m_fp) {
        err = "fopen(" + p + "): " + std::strerror(errno);
        return false;
    }
    /* 文件比游标小说明被外部截断过, 从头来 */
    struct stat st {};
    if (::fstat(::fileno(m_fp), &st) == 0 &&
        static_cast<uint64_t>(st.st_size) < m_cursor) {
        m_cursor = 0;
    }
    return true;
}

void AlertQueue::close() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_fp) {
        std::fclose(m_fp);
        m_fp = nullptr;
    }
}

bool AlertQueue::append(const std::string& raw_line, std::string& err) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_fp) {
        err = "queue not open";
        return false;
    }
    const std::string line = raw_line.back() == '\n' ? raw_line : raw_line + "\n";
    if (std::fwrite(line.data(), 1, line.size(), m_fp) != line.size() ||
        std::fflush(m_fp) != 0 || ::fsync(::fileno(m_fp)) != 0) {
        err = std::string("append failed: ") + std::strerror(errno);
        return false;
    }
    return true;
}

std::vector<std::string> AlertQueue::pending(size_t max) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> out;
    if (!m_fp || max == 0) return out;

    if (std::fflush(m_fp) != 0) return out;
    FILE* rd = std::fopen(pathJoin(m_dir, "alerts.jsonl").c_str(), "rb");
    if (!rd) return out;
    if (::fseeko(rd, static_cast<off_t>(m_cursor), SEEK_SET) != 0) {
        std::fclose(rd);
        return out;
    }
    char* buf = nullptr;
    size_t cap = 0;
    uint64_t pos = m_cursor;
    while (out.size() < max &&
           getline(&buf, &cap, rd) != -1) {  /* NOLINT: POSIX getline */
        std::string line(buf);
        if (!line.empty() && line.back() == '\n') line.pop_back();
        if (!line.empty()) out.push_back(std::move(line));
        pos += std::strlen(buf);
    }
    free(buf);
    std::fclose(rd);
    m_pending_end = pos;
    return out;
}

bool AlertQueue::markUploaded(std::string& err) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_pending_end < m_cursor) {
        err = "markUploaded without pending";
        return false;
    }
    m_cursor = m_pending_end;
    m_pending_end = 0;
    const bool ok = saveCursor();
    compactIfDrained();
    return ok;
}

size_t AlertQueue::backlog() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_fp) return 0;
    struct stat st {};
    if (::fstat(::fileno(m_fp), &st) != 0) return 0;
    const auto size = static_cast<uint64_t>(st.st_size);
    return size > m_cursor ? (size - m_cursor) / 128 + 1 : 0;  /* 粗略估计 */
}

bool AlertQueue::loadCursor() {
    FILE* f = std::fopen(pathJoin(m_dir, "cursor").c_str(), "rb");
    if (!f) return false;
    unsigned long long v = 0;
    const bool ok = std::fscanf(f, "%llu", &v) == 1;
    std::fclose(f);
    if (ok) m_cursor = static_cast<uint64_t>(v);
    return ok;
}

bool AlertQueue::saveCursor() {
    const std::string p = pathJoin(m_dir, "cursor");
    const std::string tmp = p + ".tmp";
    FILE* f = std::fopen(tmp.c_str(), "wb");
    if (!f) return false;
    std::fprintf(f, "%llu", static_cast<unsigned long long>(m_cursor));
    const bool ok = std::fclose(f) == 0 && ::rename(tmp.c_str(), p.c_str()) == 0;
    return ok;
}

void AlertQueue::compactIfDrained() {
    if (!m_fp) return;
    struct stat st {};
    if (::fstat(::fileno(m_fp), &st) != 0) return;
    if (static_cast<uint64_t>(st.st_size) == m_cursor && m_cursor > 0) {
        /* 全部上传完毕: 截断清空, 游标归零 */
        if (::ftruncate(::fileno(m_fp), 0) == 0) {
            m_cursor = 0;
            saveCursor();
        }
    }
}

}  /* namespace idsm */
