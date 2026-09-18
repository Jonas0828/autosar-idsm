/*
 * cert_manager.h -- 业务证书续期客户端(VSOC 设计 v1.0 3.3 / 4.3)。
 *
 * 仅"一型一证"路径需要: 设备用预置证书走 cert 通道换发/续期业务证书
 * (一机一证产线证书即业务证书, 无此步骤)。规则(3.3):
 *  - 业务证书剩余有效期 < 总有效期 1/3 时自动重新申请;
 *  - 新旧证书重叠期 <= 7 天(云端按序列号短期双认);
 *  - 请求必须携带产线注入安全存储的 device_serial, 云端按 MES 核对
 *    device_serial <-> VIN 绑定后才签发(预置证书共享场景防任意 VIN
 *    申请业务证书, 安全关键);
 *  - 无 RTC 设备不校验证书有效期, enforcement 在云端。
 *
 * topic: oc/devices/{device_id}/sys/cert/request/rid={request_id}
 * content: {csr_pem(必, PKCS#10), device_serial(必),
 *           cert_type(必, "business"), renew(可, bool)}
 * 响应: oc/devices/{device_id}/sys/cert/response/rid={request_id}
 * paras: {msg, cert_pem, chain_pem, serial_number, expire_at};
 * rc != 0 时 paras 只含 {msg}, 原因码对终端模糊化(6.5; PKI 类失败
 * 云端返 1004, mock 同样返 1004)。
 *
 * managerd 不接管 PKI 签发; 本模块负责: 到期判定 -> CSR 生成(复用
 * 设备私钥) -> 请求/响应 -> 原子换证 -> 触发重连。失败按错误码退避。
 */
#pragma once

#include <string>

namespace idsm {

class CertManager {
public:
    /* device_id 用于 CSR subject CN; device_serial 产线注入(可空,
     * 实验室/mock 环境下发请求时省略该字段) */
    CertManager(std::string cert_file, std::string key_file,
                std::string device_id, std::string device_serial,
                std::string manufacturer);

    /* cert_file 未配置或读取失败返回 false(err 非空);
     * 剩余有效期 < 总有效期 1/3 返回 true(3.3) */
    bool needsRenewal(long long now_sec, std::string& err) const;

    /* 构造证书申请请求(4.3, 信封同 init: request_id/timestamp/
     * manufacturer/type=2/content) */
    std::string buildRequest(const std::string& request_id,
                             long long now_ms, std::string& err) const;

    /* 处理证书响应: rc==0 时 paras.cert_pem 原子替换 cert_file
     * (旧证备份 .bak, 重叠期双认), 返回 true(调用方触发重连);
     * rc!=0 返回 false, err 只带模糊码(6.5) */
    bool applyResponse(const std::string& payload,
                       const std::string& expect_request_id,
                       std::string& err) const;

private:
    std::string m_cert_file;
    std::string m_key_file;
    std::string m_device_id;
    std::string m_device_serial;
    std::string m_manufacturer;
};

}  /* namespace idsm */
