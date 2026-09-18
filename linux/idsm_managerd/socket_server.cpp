#include "socket_server.h"

#include <cstring>
#include <vector>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace idsm {

SocketServer::SocketServer()
    : m_running(std::make_shared<std::atomic<bool>>(false)) {}

SocketServer::~SocketServer() { stop(); }

bool SocketServer::start(const std::string& path, unsigned perm,
                         LineCallback cb, std::string& err) {
    m_path = path;
    m_cb = std::move(cb);

    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        err = "socket: " + std::string(std::strerror(errno));
        return false;
    }
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        err = "socket path too long";
        ::close(fd);
        return false;
    }
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    ::unlink(path.c_str());
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        err = "bind(" + path + "): " + std::strerror(errno);
        ::close(fd);
        return false;
    }
    ::chmod(path.c_str(), static_cast<mode_t>(perm));
    if (::listen(fd, 8) != 0) {
        err = std::string("listen: ") + std::strerror(errno);
        ::close(fd);
        ::unlink(path.c_str());
        return false;
    }
    m_listen_fd = fd;
    m_running->store(true);
    m_thread = std::thread(&SocketServer::acceptLoop, this);
    return true;
}

void SocketServer::stop() {
    if (!m_running->exchange(false) && m_listen_fd < 0) return;
    /* 唤醒 accept: 自连一次 */
    const int s = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s >= 0) {
        sockaddr_un addr {};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, m_path.c_str(), sizeof(addr.sun_path) - 1);
        ::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        ::close(s);
    }
    if (m_thread.joinable()) m_thread.join();
    {
        std::lock_guard<std::mutex> lock(m_conns_mutex);
        for (auto& t : m_conn_threads) {
            if (t.joinable()) t.join();
        }
        m_conn_threads.clear();
    }
    if (m_listen_fd >= 0) {
        ::close(m_listen_fd);
        m_listen_fd = -1;
    }
    ::unlink(m_path.c_str());
}

void SocketServer::acceptLoop() {
    auto running = m_running;  /* 连接线程与 accept 循环共享生命周期 */
    while (running->load()) {
        const int fd = ::accept(m_listen_fd, nullptr, nullptr);
        if (fd < 0) {
            if (running->load() && errno != EINTR) {
                /* 短暂退避防忙转 */
                ::usleep(10 * 1000);
            }
            continue;
        }
        std::lock_guard<std::mutex> lock(m_conns_mutex);
        m_conn_threads.emplace_back(&SocketServer::handleConn, this, fd);
    }
}

void SocketServer::handleConn(int fd) {
    auto running = m_running;
    const int peers = m_peer_count.fetch_add(1) + 1;
    if (m_peer_cb) m_peer_cb(peers);
    std::string pending;   /* 处理半行 */
    char buf[4096];
    while (running->load()) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        pending.append(buf, static_cast<size_t>(n));
        size_t pos;
        while ((pos = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, pos);
            pending.erase(0, pos + 1);
            if (!line.empty() && m_cb) m_cb(std::move(line));
        }
        if (pending.size() > 1 << 20) break;  /* 畸形客户端兜底 */
    }
    /* 连接关闭时处理尾部无换行的最后一行(已是完整事件, 正常 flush) */
    if (!pending.empty() && m_cb) {
        m_cb(std::move(pending));
    }
    ::close(fd);
    const int left = m_peer_count.fetch_sub(1) - 1;
    if (m_peer_cb) m_peer_cb(left);
}

}  /* namespace idsm */
