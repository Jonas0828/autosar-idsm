/*
 * mqtt_uploader.h -- MQTT 上行/下行(VSOC 设备接入设计 v1.0 第 6/10 章):
 * 上行 oc/devices/{device_id}/sys/idps/{host|eth|can}/log (QoS1),
 * 下行 oc/devices/{device_id}/sys/idps/rule/update +
 *     oc/vmodel/{mfr}_{model}/sys/idps/rule/update (车型级广播) +
 *     同体系 config/update (10.3) +
 *     oc/devices/{device_id}/sys/log/report/negative-ack (11.2 补片)。
 *
 * 有 libmosquitto 时编译真实实现(-DHAVE_MOSQUITTO),否则用 Stub
 * (打印日志, 便于无依赖环境联调 UDS/队列/规则链路)。
 */
#pragma once

#include <functional>
#include <memory>
#include <string>

namespace idsm {

struct MqttConfig {
    std::string host{"localhost"};
    int         port{8883};
    std::string device_id{"UNKNOWN"};
    std::string manufacturer{"caic"};
    std::string model_code{"t99"};
    std::string client_id;  /* 空 = "idsm-"+device_id; 注册后更新 */
    std::string token;      /* 短期令牌, 连接时刷新 */
    bool        tls{true};  /* false = 实验室 tcp:// 明文(mock 云) */
    std::string cafile;     /* CA 或自签校验; pinning 见 mosquitto 实现的
                               mosquitto_tls_set 注释 */
    std::string cert_file;  /* 车端业务证书(双向 TLS; 一型一证换发后由
                               reloadTls 热更新, 3.3) */
    std::string key_file;   /* 车端私钥 */
    std::string will_topic;     /* LWT(5.3), 空 = 不带遗嘱 */
    std::string will_payload;   /* nodeStatus=0 单节点属性信封 */
    int         timeout_ms{10000};
};

class MqttUploader {
public:
    using DownlinkCallback = std::function<void(const std::string& topic,
                                                const std::string& payload)>;

    virtual ~MqttUploader() = default;

    /* 连接 + 订阅规则 topic; on_downlink 由网络线程回调 */
    virtual bool start(DownlinkCallback on_downlink, std::string& err) = 0;
    virtual void stop() = 0;
    virtual bool connected() const = 0;

    /* QoS1 发布到任意 topic(VSOC 信封/属性/事件); 成功返回 true */
    virtual bool publish(const std::string& topic, const std::string& payload,
                         std::string& err) = 0;

    /* 注册成功后热更新凭据(username=clientId)并触发重连;
     * 空 token 保持匿名(未注册/一机一证直连由调用方决定) */
    virtual bool updateCredentials(const std::string& client_id,
                                   const std::string& token,
                                   std::string& err) = 0;

    /* 证书续期换证后(3.3)热更新 TLS 证书并触发重连; 空参数不更新 */
    virtual bool reloadTls(const std::string& cert_file,
                           const std::string& key_file,
                           std::string& err) = 0;

    /* 订阅任意 topic(如按 request_id 精确订阅注册响应, 7 章) */
    virtual bool subscribe(const std::string& topic, std::string& err) = 0;

    static std::unique_ptr<MqttUploader> create(const MqttConfig& cfg);

    static std::string rulesTopic(const std::string& device_id) {
        return "oc/devices/" + device_id + "/sys/idps/rule/update";
    }
    static std::string rulesBroadcastTopic(const std::string& mfr,
                                           const std::string& model_code) {
        return "oc/vmodel/" + mfr + "_" + model_code + "/sys/idps/rule/update";
    }
    static std::string configTopic(const std::string& device_id) {
        return "oc/devices/" + device_id + "/sys/idps/config/update";
    }
    static std::string configBroadcastTopic(const std::string& mfr,
                                            const std::string& model_code) {
        return "oc/vmodel/" + mfr + "_" + model_code + "/sys/idps/config/update";
    }
    static std::string snapshotNackTopic(const std::string& device_id) {
        return "oc/devices/" + device_id + "/sys/log/report/negative-ack";
    }
    static std::string eventUpTopic(const std::string& device_id) {
        return "oc/devices/" + device_id + "/sys/events/up";
    }
};

}  /* namespace idsm */
