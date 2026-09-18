/*
 * registration.h -- 一型一证动态注册(设计文档第 4 章)。
 *
 * 量产默认走"一机一证"(产线烧录业务证书, CN=device_id, 跳过注册),
 * 本模块覆盖"一型一证"路径: 预置证书环境用车架号/车型向注册服务
 * 换 clientId + 短期 token, 凭 token 重连 MQTT(username=clientId)。
 *
 * 请求:  oc/devices/{device_id}/sys/init/request/rid={request_id}
 * 响应:  oc/devices/{device_id}/sys/init/response/rid={request_id}
 * 凭据持久化在 data_dir/credentials.json, 重启免重复注册;
 * token 过期(2h, 产线 PDI/库存期常见)时重新 init, 云端幂等返回
 * 原 clientId 并轮换 token(4.4)。
 *
 * 证书申请通道(sys/cert, 4.3)依赖预置证书 TLS + PKI 签发,
 * managerd 不接管 PKI(云端 mock 同样返回 1004), 不在本模块实现。
 */
#pragma once

#include <string>
#include <vector>

namespace idsm {

struct Credentials {
    std::string client_id;
    std::string token;
    long long   token_expire{0};   /* unix 秒, 0 = 未知 */

    bool validAt(long long now_sec) const {
        return !client_id.empty() && !token.empty() &&
               (token_expire == 0 || token_expire > now_sec);
    }
};

/* 凭据的本地持久化(JSON 原子写) */
class CredentialStore {
public:
    explicit CredentialStore(std::string path) : m_path(std::move(path)) {}

    /* 读取; 文件不存在返回 false 且 err 为空, 损坏返回 false + err */
    bool load(Credentials& out, std::string& err) const;
    bool save(const Credentials& c, std::string& err) const;

private:
    std::string m_path;
};

/* 生成 UUID v4(请求标识), 失败退化为时间戳+随机数 */
std::string newRequestId();

/* 构造注册请求(6.1 信封 + 4.3 content) */
std::string buildInitRequest(const std::string& manufacturer,
                             const std::string& request_id,
                             long long timestamp_ms,
                             const std::string& vin,
                             const std::string& model_code,
                             const std::vector<std::string>& ecu_list);

/* 解析注册响应: 校验 rc/rn/request_id 并提取 paras.client_id/token。
 * rc != 0 时返回 false, err 带对外模糊原因(6.5) */
bool parseInitResponse(const std::string& payload,
                       const std::string& expect_request_id,
                       Credentials& out,
                       std::string& err);

}  /* namespace idsm */
