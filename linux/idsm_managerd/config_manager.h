/*
 * config_manager.h -- 云端签名配置包验签、防回滚与落地(VSOC 设计 v1.0 10.3)。
 *
 * topic: oc/devices/{device_id}/sys/idps/config/update
 *      + oc/vmodel/{mfr}_{model}/sys/idps/config/update(车型级广播)。
 *
 * 配置包与规则包同签名体系(10.3 "同样签名"): msg_type=config_update,
 * seq/version/rollback/target/issued_at/expires_at/sig_alg/pubkey_id/
 * signature 字段语义与规则包一致(10.2), upgrade_type 对应 config_type。
 *
 * canonical 字节序列(与 tools/vsoc_mock/mock_vsoc.py canonical_config_bytes
 * 及 Android ConfigManager.kt 逐字节一致):
 *   seq={seq}\n tenant={tenant}\n version={version}\n rollback={0|1}\n
 *   target_ecu={ecu}\n target_node={nodeType}\n target_vmodel={vmodel}\n
 *   issued_at={issued_at}\n expires_at={expires_at}\n config_type={t}\n
 *   {item 行按 ASCII 升序}\n
 * item 行: item:{config_name}:{base64(item JSON)}
 *   item JSON: 键按 ASCII 升序, 紧凑分隔(无空格), 值限 ASCII 可打印
 *   (与 python json.dumps(sort_keys=True, separators=(",",":")) 一致)。
 *
 * config_type=1(黑白名单)items: {config_name, config_value: array<string>,
 *   config_version}; config_name 限 app_w_list / process_w_list /
 *   fw_ip_w_list / fw_ip_b_list / fw_port_w_list / fw_port_b_list,
 *   落地 config/current/{name}.list(一行一条, 原子写)。
 * config_type=2(策略使能)items: {config_name:"rule_enable",
 *   config_value:{rule_id:1|0}}; 落地 config/current/rule_enable.json,
 *   管理组件审计日志(config/audit.log)留痕(10.3 高危操作双人复核的
 *   车端审计侧)。
 *
 * 防回滚/时效/target 判定语义与 RuleManager 一致; 配置与规则各自维护
 * max_seq(签名服务不同, 序号空间不共享)。任一步失败整体拒绝, 当前
 * 配置不受影响(10.4); 拒绝原因由调用方经 sys/events/up 上报闭环。
 */
#pragma once

#include <string>
#include <vector>

namespace idsm {

struct DeviceIdentity;   /* rule_manager.h */

enum class ConfigApply {
    Applied,
    Skipped,
    Rejected,
};

class ConfigManager {
public:
    ConfigManager(std::string config_dir,
                  std::string reload_cmd,
                  std::string pubkey_b64_spki);

    /* 处理一条下行配置包 payload; 任一环节失败即拒绝, 不留半切换状态 */
    ConfigApply applyBundle(const std::string& json_text,
                            const DeviceIdentity& self,
                            std::string& err);

    const std::string& configDir() const { return m_config_dir; }

    /* config_type=1 允许的名单名(10.3) */
    static bool validListName(const std::string& name);

private:
    bool verifySignature(const std::string& canonical,
                         const std::string& sig_b64,
                         std::string& err) const;
    std::string configuredPubkeyId(std::string& err) const;
    long long loadMaxSeq() const;
    bool storeMaxSeq(long long seq, std::string& err) const;
    bool runReload(std::string& err) const;

    std::string m_config_dir;
    std::string m_reload_cmd;
    std::string m_pubkey_b64;
};

/* canonical 字节序列(10.3, 与 python/Kotlin 逐字节一致);
 * payload_lines 须已按 ASCII 升序排好(不含换行)。 */
std::string canonicalConfigBytes(long long seq, const std::string& tenant,
                                 const std::string& version, bool rollback,
                                 const std::string& target_ecu,
                                 const std::string& target_node,
                                 const std::string& target_vmodel,
                                 long long issued_at, long long expires_at,
                                 int config_type,
                                 const std::vector<std::string>& payload_lines);

}  /* namespace idsm */
