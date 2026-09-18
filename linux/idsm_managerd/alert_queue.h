/*
 * alert_queue.h -- 告警持久队列(append-only JSONL + 游标)。
 *
 * 与 Android 侧 AlertQueue(SQLite)语义对齐: 至少一次上传。
 * alerts.jsonl 追加每条原始 NDJSON 行, cursor 记录"下一条待发送"
 * 的字节偏移; 进程重启后从断点续传。不引 sqlite 依赖, 文件可直接
 * 用文本工具审计。
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace idsm {

class AlertQueue {
public:
    /* dir 须已存在。加载 cursor, 打开(或创建) alerts.jsonl */
    bool open(const std::string& dir, std::string& err);
    void close();

    /* 追加一条原始 NDJSON 行(内部补换行 + fsync) */
    bool append(const std::string& raw_line, std::string& err);

    /* 从游标取最多 max 条待发送行。单消费者(上传线程)语义 */
    std::vector<std::string> pending(size_t max);

    /* 确认 pending() 返回的全部行已上传, 推进游标; 追平文件末尾时压缩 */
    bool markUploaded(std::string& err);

    size_t backlog() const;   /* 待发送行数估计 */

private:
    bool  loadCursor();
    bool  saveCursor();
    void  compactIfDrained();

    mutable std::mutex m_mutex;
    std::string m_dir;
    FILE*       m_fp{nullptr};
    uint64_t    m_cursor{0};        /* 下一条待发送的字节偏移 */
    uint64_t    m_pending_end{0};   /* 本次 pending 覆盖到的偏移 */
};

}  /* namespace idsm */
