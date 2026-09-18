/*
 * socket_server.h -- AF_UNIX 监听,接收探针 NDJSON 行。
 *
 * Linux 侧用文件系统路径(默认 /run/idsm/probe.sock),Android 侧
 * LocalServerSocket 用 abstract —— 线上格式(NDJSON 行)完全一致。
 */
#pragma once

#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <memory>

namespace idsm {

class SocketServer {
public:
    using LineCallback = std::function<void(const std::string& line)>;

    SocketServer();
    ~SocketServer();

    /* 监听 path(先 unlink 残留)。perm 为 socket 文件权限位 */
    bool start(const std::string& path, unsigned perm,
               LineCallback cb, std::string& err);
    void stop();   /* 幂等 */

    bool running() const { return m_running->load(); }

private:
    void acceptLoop();
    void handleConn(int fd);

    std::string m_path;
    int         m_listen_fd{-1};
    LineCallback m_cb;
    std::shared_ptr<std::atomic<bool>> m_running;
    std::thread m_thread;
    std::mutex  m_conns_mutex;
    std::vector<std::thread> m_conn_threads;   /* stop() 统一 join */
};

}  /* namespace idsm */
