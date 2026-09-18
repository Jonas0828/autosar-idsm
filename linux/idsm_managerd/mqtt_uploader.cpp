#include "mqtt_uploader.h"

#include <cstdio>

#ifdef HAVE_MOSQUITTO
#include <mosquitto.h>
#include <cstring>
#include <chrono>
#include <thread>
#endif

namespace idsm {

#ifdef HAVE_MOSQUITTO

class MosquittoUploader final : public MqttUploader {
public:
    explicit MosquittoUploader(const MqttConfig& cfg) : m_cfg(cfg) {
        mosquitto_lib_init();
        m_mosq = mosquitto_new(nullptr, true, this);
    }
    ~MosquittoUploader() override {
        stop();
        if (m_mosq) mosquitto_destroy(m_mosq);
        mosquitto_lib_cleanup();
    }

    bool start(DownlinkCallback cb, std::string& err) override {
        m_downlink = std::move(cb);
        if (m_cfg.client_id.empty()) m_cfg.client_id = "idsm-" + m_cfg.device_id;
        mosquitto_connect_callback_set(m_mosq, onConnect);
        mosquitto_disconnect_callback_set(m_mosq, onDisconnect);
        mosquitto_message_callback_set(m_mosq, onMessage);
        mosquitto_log_callback_set(m_mosq, onLog);
        if (!m_cfg.will_topic.empty()) {
            /* LWT(5.3): 属性同通道, nodeStatus=0 单节点, QoS1 retain false */
            mosquitto_will_set(m_mosq, m_cfg.will_topic.c_str(),
                               static_cast<int>(m_cfg.will_payload.size()),
                               m_cfg.will_payload.data(), 1, false);
        }
        /* 未拿到注册令牌前保持匿名 CONNECT;带用户名但密码为空会被
           认证插件(如 amqtt auth_file)直接拒绝 */
        if (!m_cfg.token.empty()) {
            mosquitto_username_pw_set(m_mosq, m_cfg.client_id.c_str(),
                                      m_cfg.token.c_str());
        }
        if (m_cfg.tls && (!m_cfg.cafile.empty() || !m_cfg.cert_file.empty())) {
            /* 量产建议换成证书/公钥 pinning:
               mosquitto_tls_set 后校验对端证书指纹白名单,
               与 Android 侧 PinningTrustManager 语义一致 */
            mosquitto_tls_set(m_mosq, m_cfg.cafile.c_str(), nullptr,
                              m_cfg.cert_file.empty() ? nullptr
                                  : m_cfg.cert_file.c_str(),
                              m_cfg.key_file.empty() ? nullptr
                                  : m_cfg.key_file.c_str(),
                              nullptr);
        }
        /* broker 可能晚于本进程就绪(冷启动/依赖服务拉起):connect_async
           立即建连,ECONNREFUSED 会同步返回,这里轮询等待后由 loop 线程
           接管后续断线重连(指数退避) */
        mosquitto_reconnect_delay_set(m_mosq, 1, 30, false);
        int rc = MOSQ_ERR_ERRNO;
        for (int i = 0; i < 30; ++i) {
            rc = mosquitto_connect_async(m_mosq, m_cfg.host.c_str(),
                                         m_cfg.port, 30);
            if (rc == MOSQ_ERR_SUCCESS) break;
            std::fprintf(stderr, "[MQTT] connect %s:%d rc=%d, retry %d/30\n",
                         m_cfg.host.c_str(), m_cfg.port, rc, i + 1);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (rc != MOSQ_ERR_SUCCESS) {
            err = "connect: " + std::string(mosquitto_strerror(rc));
            return false;
        }
        mosquitto_loop_start(m_mosq);
        return true;
    }

    void stop() override {
        if (m_mosq) {
            mosquitto_loop_stop(m_mosq, true);
            mosquitto_disconnect(m_mosq);
        }
    }

    bool connected() const override {
        return m_mosq && m_connected;
    }

    bool publish(const std::string& topic, const std::string& payload,
                 std::string& err) override {
        const int rc = mosquitto_publish(
            m_mosq, nullptr, topic.c_str(),
            static_cast<int>(payload.size()),
            payload.data(), 1, false);
        if (rc != MOSQ_ERR_SUCCESS) {
            err = "publish: " + std::string(mosquitto_strerror(rc));
            return false;
        }
        return true;
    }

    bool updateCredentials(const std::string& client_id,
                           const std::string& token,
                           std::string& err) override {
        m_cfg.client_id = client_id;
        m_cfg.token = token;
        if (token.empty()) {
            /* 匿名重连: 清掉旧用户名, 否则重连仍带老凭据 */
            mosquitto_username_pw_set(m_mosq, nullptr, nullptr);
        } else {
            mosquitto_username_pw_set(m_mosq, client_id.c_str(), token.c_str());
        }
        if (m_connected) {
            /* 手动 disconnect 不会自动重连, 必须显式 reconnect_async;
             * loop 线程执行断开+重连, 新凭据生效。
             * 注意: 非优雅断开会让 broker 代发一次 LWT(短暂离线假象),
             * reconnect 后 5s 内的全量属性上报(8.3)会恢复在线语义;
             * 不用 mosquitto_disconnect 是因为它非线程安全(loop 线程
             * 运行中从业务线程调用有竞态)。 */
            const int rc = mosquitto_reconnect_async(m_mosq);
            if (rc != MOSQ_ERR_SUCCESS) {
                err = "reconnect for credential refresh: " +
                      std::string(mosquitto_strerror(rc));
                return false;
            }
        }
        return true;
    }

    bool subscribe(const std::string& topic, std::string& err) override {
        const int rc = mosquitto_subscribe(m_mosq, nullptr, topic.c_str(), 1);
        if (rc != MOSQ_ERR_SUCCESS) {
            err = "subscribe: " + std::string(mosquitto_strerror(rc));
            return false;
        }
        return true;
    }

    bool reloadTls(const std::string& cert_file,
                   const std::string& key_file,
                   std::string& err) override {
        if (!cert_file.empty()) m_cfg.cert_file = cert_file;
        if (!key_file.empty()) m_cfg.key_file = key_file;
        if (!m_cfg.tls || m_cfg.cert_file.empty()) return true;
        const int rc = mosquitto_tls_set(
            m_mosq, m_cfg.cafile.empty() ? nullptr : m_cfg.cafile.c_str(),
            nullptr, m_cfg.cert_file.c_str(),
            m_cfg.key_file.empty() ? nullptr : m_cfg.key_file.c_str(),
            nullptr);
        if (rc != MOSQ_ERR_SUCCESS) {
            err = "tls reload: " + std::string(mosquitto_strerror(rc));
            return false;
        }
        if (m_connected) {
            /* 同 updateCredentials: 换证后必须显式 reconnect_async */
            const int rrc = mosquitto_reconnect_async(m_mosq);
            if (rrc != MOSQ_ERR_SUCCESS) {
                err = "reconnect for cert refresh: " +
                      std::string(mosquitto_strerror(rrc));
                return false;
            }
        }
        return true;
    }

private:
    static void onConnect(mosquitto* m, void* obj, int rc) {
        auto* self = static_cast<MosquittoUploader*>(obj);
        std::fprintf(stderr, "[MQTT] on_connect rc=%d (%s)\n", rc,
                     mosquitto_connack_string(rc));
        if (rc == 0) {
            self->m_connected = true;
            mosquitto_subscribe(m, nullptr, rulesTopic(self->m_cfg.device_id).c_str(), 1);
            mosquitto_subscribe(m, nullptr,
                                rulesBroadcastTopic(self->m_cfg.manufacturer,
                                                    self->m_cfg.model_code).c_str(), 1);
            /* 配置下发(10.3, 签名体系同规则包) + 快照补片(11.2) */
            mosquitto_subscribe(m, nullptr,
                                configTopic(self->m_cfg.device_id).c_str(), 1);
            mosquitto_subscribe(m, nullptr,
                                configBroadcastTopic(self->m_cfg.manufacturer,
                                                     self->m_cfg.model_code).c_str(), 1);
            mosquitto_subscribe(m, nullptr,
                                snapshotNackTopic(self->m_cfg.device_id).c_str(), 1);
        }
    }
    static void onDisconnect(mosquitto*, void* obj, int rc) {
        auto* self = static_cast<MosquittoUploader*>(obj);
        self->m_connected = false;
        std::fprintf(stderr, "[MQTT] disconnected rc=%d\n", rc);
    }
    static void onLog(mosquitto*, void*, int, const char* msg) {
        std::fprintf(stderr, "[MQTT] %s\n", msg);
    }
    static void onMessage(mosquitto*, void* obj,
                          const mosquitto_message* msg) {
        auto* self = static_cast<MosquittoUploader*>(obj);
        if (self->m_downlink && msg->payloadlen > 0) {
            self->m_downlink(msg->topic,
                             std::string(static_cast<const char*>(msg->payload),
                                         static_cast<size_t>(msg->payloadlen)));
        }
    }

    MqttConfig m_cfg;
    mosquitto* m_mosq{nullptr};
    DownlinkCallback m_downlink;
    bool m_connected{false};
};

#else

class StubUploader final : public MqttUploader {
public:
    explicit StubUploader(const MqttConfig& cfg) : m_cfg(cfg) {}
    bool start(DownlinkCallback, std::string&) override {
        std::fprintf(stderr, "[IDSMD] STUB MQTT: no libmosquitto, "
                             "alerts would go to %s:%d topic %s\n",
                     m_cfg.host.c_str(), m_cfg.port, m_cfg.device_id.c_str());
        return true;
    }
    void stop() override {}
    bool connected() const override { return true; }
    bool publish(const std::string& topic, const std::string& payload,
                 std::string&) override {
        std::fprintf(stderr, "[IDSMD] STUB publish %zu bytes to %s\n",
                     payload.size(), topic.c_str());
        return true;
    }
    bool updateCredentials(const std::string& client_id,
                           const std::string& token,
                           std::string&) override {
        m_cfg.client_id = client_id;
        m_cfg.token = token;
        std::fprintf(stderr, "[IDSMD] STUB credentials -> %s\n",
                     client_id.c_str());
        return true;
    }
    bool subscribe(const std::string& topic, std::string&) override {
        std::fprintf(stderr, "[IDSMD] STUB subscribe %s\n", topic.c_str());
        return true;
    }
    bool reloadTls(const std::string&, const std::string&, std::string&) override {
        return true;
    }
private:
    MqttConfig m_cfg;
};

#endif

std::unique_ptr<MqttUploader> MqttUploader::create(const MqttConfig& cfg) {
#ifdef HAVE_MOSQUITTO
    return std::make_unique<MosquittoUploader>(cfg);
#else
    return std::make_unique<StubUploader>(cfg);
#endif
}

}  /* namespace idsm */
