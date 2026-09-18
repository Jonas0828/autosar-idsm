/*
 * mqtt_uploader.h -- MQTT 上行/下行(VSOC 设备接入设计 v1.0 第 6/10 章):
 * 上行 oc/devices/{device_id}/sys/idps/{host|eth|can}/log (QoS1),
 * 下行 oc/devices/{device_id}/sys/idps/rule/update +
 *     oc/vmodel/{mfr}_{model}/sys/idps/rule/update (车型级广播)。
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
    std::string token;      /* 短期令牌, 连接时刷新 */
    bool        tls{true};  /* false = 实验室 tcp:// 明文(mock 云) */
    std::string cafile;     /* CA 或自签校验; pinning 见 mosquitto 实现的
                               mosquitto_tls_set 注释 */
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

    static std::unique_ptr<MqttUploader> create(const MqttConfig& cfg);

    static std::string rulesTopic(const std::string& device_id) {
        return "oc/devices/" + device_id + "/sys/idps/rule/update";
    }
    static std::string rulesBroadcastTopic(const std::string& mfr,
                                           const std::string& model_code) {
        return "oc/vmodel/" + mfr + "_" + model_code + "/sys/idps/rule/update";
    }
};

}  /* namespace idsm */
