/*
 * rule_manager.h -- 云端规则包验签、原子切换、回滚与分发。
 *
 * 规则包格式与 Android 侧 RuleManager 完全一致:
 *   {"version":N, "files":{"name":"<b64>", ...}, "signature":"<b64 Ed25519>"}
 * canonical bytes = "v{version}\n" + 按文件名排序的 "{name}:{b64(sha256)}\n"
 * 验签公钥(base64 SPKI)由 --pubkey-b64 注入, 生产上随软件包发布。
 *
 * 切换成功执行 reload_cmd(如 "systemctl restart idsm-host-probe
 * idsm-eth-probe"), 探针重启后从 rules/current 读新基线。
 */
#pragma once

#include <map>
#include <string>

namespace idsm {

class RuleManager {
public:
    RuleManager(std::string rules_dir,
                std::string reload_cmd,
                std::string pubkey_b64_spki,
                std::string seed_dir);

    /* 首次运行: seed_dir(/etc/idsm/v0)存在且 current 缺失时播种 v0 */
    bool seedFromImageDefaults(std::string& err);

    /* 处理一条下行规则包 payload; 任一环节失败即拒绝, 不留半切换状态 */
    bool applyBundle(const std::string& json_text, std::string& err);

    const std::string& rulesDir() const { return m_rules_dir; }

private:
    bool verifySignature(const std::string& canonical,
                         const std::string& sig_b64,
                         std::string& err) const;
    bool runReload(std::string& err) const;

    std::string m_rules_dir;
    std::string m_reload_cmd;
    std::string m_pubkey_b64;
    std::string m_seed_dir;
};

/* canonical 字节序列, 与 Android 侧 RuleManager.canonicalBytes 逐字节一致 */
std::string canonicalRuleBytes(
    long long version, const std::map<std::string, std::string>& name_to_b64);

}  /* namespace idsm */
