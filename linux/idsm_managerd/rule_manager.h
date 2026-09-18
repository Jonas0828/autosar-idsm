/*
 * rule_manager.h -- 云端签名规则包验签、防回滚、原子切换与分发。
 *
 * 规则包格式(VSOC 设备接入设计 v1.0 10.2):
 *   {"msg_type":"rule_update", "protocol_version":"1.0", ...,
 *    "seq":N, "version":"v8", "rollback":false,
 *    "target":{"ecu":"0x01|all","nodeType":"NIDPS|all","vmodel":"t99|all"},
 *    "upgrade_type":1, "rules":[...],
 *    "issued_at":unix秒, "expires_at":unix秒,
 *    "sig_alg":"Ed25519", "pubkey_id":"sha256(raw公钥)hex[:16]",
 *    "signature":"base64(Ed25519(canonical字节))"}
 *
 * canonical 字节序列(10.1, 与 tools/vsoc_mock/mock_vsoc.py 的
 * canonical_bytes 逐字节一致, 互操作以 python 实现为基准):
 *   seq={seq}\n tenant={tenant}\n version={version}\n rollback={0|1}\n
 *   target_ecu={ecu}\n target_node={nodeType}\n target_vmodel={vmodel}\n
 *   issued_at={issued_at}\n expires_at={expires_at}\n upgrade_type={t}\n
 *   {payload 行按 ASCII 升序}\n
 * payload 行: upgrade_type=1 每条 `rule:{10000+i}:{base64(规则文本)}`;
 *             upgrade_type=2 `uri:{download_uri}`
 *
 * 防回滚: seq 平台级单调递增, seq <= 已应用最大 seq 拒绝(错误码 1005);
 * 授权回滚(rollback=1)的 seq 同样递增, 只放开 version 回退。
 * 时效: expires_at/issued_at 校验容忍 ±24h 车端时钟偏差(10.1 ③)。
 *
 * 切换成功执行 reload_cmd(如 "systemctl restart idsm-host-probe
 * idsm-eth-probe"), 探针重启后从 rules/current 读新基线。
 */
#pragma once

#include <string>
#include <vector>

namespace idsm {

/* 本机身份: 判定云端包 target 是否指向本机 */
struct DeviceIdentity {
    std::string ecu;                 /* 数据字典编码, 如 "0x01" */
    std::string vmodel;              /* 车型编码, 如 "t99" */
    std::vector<std::string> node_types;  /* 托管的 nodeType, 如 HIDPS/NIDPS */
};

enum class RuleApply {
    Applied,   /* 验签通过且 target 命中, 已原子切换 + reload */
    Skipped,   /* 验签通过但 target 未命中, 或未命中任何托管 nodeType */
    Rejected,  /* 验签/时效/序号/格式失败, 不产生任何变更 */
};

class RuleManager {
public:
    RuleManager(std::string rules_dir,
                std::string reload_cmd,
                std::string pubkey_b64_spki,
                std::string seed_dir);

    /* 首次运行: seed_dir(/etc/idsm/v0)存在且 current 缺失时播种 v0 */
    bool seedFromImageDefaults(std::string& err);

    /* 处理一条下行规则包 payload; 任一环节失败即拒绝, 不留半切换状态 */
    RuleApply applyBundle(const std::string& json_text,
                          const DeviceIdentity& self,
                          std::string& err);

    const std::string& rulesDir() const { return m_rules_dir; }

private:
    bool verifySignature(const std::string& canonical,
                         const std::string& sig_b64,
                         std::string& err) const;
    std::string configuredPubkeyId(std::string& err) const;
    bool runReload(std::string& err) const;
    long long loadMaxSeq() const;
    bool storeMaxSeq(long long seq, std::string& err) const;

    std::string m_rules_dir;
    std::string m_reload_cmd;
    std::string m_pubkey_b64;
    std::string m_seed_dir;
};

/* canonical 字节序列(10.1), 与 tools/vsoc_mock/mock_vsoc.py 的
 * canonical_bytes 逐字节一致; payload_lines 须已按 ASCII 升序排好(不含换行)。 */
std::string canonicalRuleBytes(long long seq, const std::string& tenant,
                               const std::string& version, bool rollback,
                               const std::string& target_ecu,
                               const std::string& target_node,
                               const std::string& target_vmodel,
                               long long issued_at, long long expires_at,
                               int upgrade_type,
                               const std::vector<std::string>& payload_lines);

}  /* namespace idsm */
