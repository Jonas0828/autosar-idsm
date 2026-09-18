/*
 * log_snapshot.h -- 日志快照分包上传(VSOC 设备接入设计 v1.0 第 11 章)。
 *
 * topic: oc/devices/{device_id}/sys/log/report (QoS1)。
 * 快照(二进制取证文件, pcap/核心转储)> 256 KB 必须分包(11 章):
 *   元消息(A.7, 扁平信封): msg_type=log_snapshot, transfer_id,
 *     filename, total_size, total_chunks, sha256(整体), log_time,
 *     event_id(关联告警), ecuCode, replay, remark
 *   分片(11.2): msg_type=log_snapshot_chunk, transfer_id, chunk_index,
 *     chunk_sha256, data(base64); 每片原始数据 <= 128 KB
 *
 * 触发: 探针经 UDS 下行命令行 {"cmd":"log_upload","file":...,
 * "event_id":...,"remark":...}(fire-and-forget, 与告警行同通道)。
 *
 * 规则(11.3):
 *  - transfer 有效期 24 h, 过期碎片清理;
 *  - 同一 transfer_id 重复分片按 chunk_index 幂等覆盖(云端语义),
 *    车端断点续传同样按 index 重发;
 *  - 断网期间快照入持久目录(pending/<transfer_id>/), 恢复后补传,
 *    meta.replay=true;
 *  - 云端整体 sha256 校验失败经 sys/log/report/negative-ack 请求补片:
 *    {"transfer_id":..., "missing":[index...]}, 仅 24 h 内受理。
 */
#pragma once

#include <functional>
#include <string>

namespace idsm {

struct SnapshotRequest {
    std::string file;       /* 本地取证文件绝对路径 */
    std::string event_id;   /* 关联告警 eventId(可空) */
    std::string remark;     /* 取证说明(可空) */
};

/* 每片原始字节上限(11.2) */
constexpr size_t kSnapshotChunkSize = 128 * 1024;
/* transfer 有效期(11.3) */
constexpr long long kSnapshotTransferTtlMs = 24LL * 3600 * 1000;
/* 单文件上限(车端资源兜底) */
constexpr size_t kSnapshotMaxFileSize = 64 * 1024 * 1024;
/* 单次 pump 最多发布的分片数(防饿死告警队列) */
constexpr int kSnapshotChunksPerPump = 8;

class LogSnapshotManager {
public:
    explicit LogSnapshotManager(std::string snapshot_dir);

    /* 暂存一次上传: 读文件、算 sha256、切分片、落盘 pending/<tid>/。
     * 返回 transfer_id; 失败返回空串并置 err。断网时也可调用,
     * 持久目录保证恢复后续传。 */
    std::string stageUpload(const SnapshotRequest& req, long long now_ms,
                            std::string& err);

    /* 发布进行中的 transfer: 先发元消息(meta_sent 记盘), 再按
     * kSnapshotChunksPerPump 发分片。publish 返回 false 即停,
     * 下轮重试。无进行中 transfer 返回 false。 */
    bool pump(const std::string& manufacturer, const std::string& device_id,
              const std::string& ecu_code, long long now_ms,
              const std::function<bool(const std::string& topic,
                                       const std::string& payload)>& publish,
              std::string& err);

    /* negative-ack 消费端: 把缺失 index 重新排入发送队列(24h 内) */
    bool onNack(const std::string& payload, long long now_ms,
                std::string& err);

private:
    std::string m_dir;
};

}  /* namespace idsm */
