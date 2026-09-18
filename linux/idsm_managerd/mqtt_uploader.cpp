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
        mosquitto_connect_callback_set(m_mosq, onConnect);
        mosquitto_disconnect_callback_set(m_mosq, onDisconnect);
        mosquitto_message_callback_set(m_mosq, onMessage);
        mosquitto_log_callback_set(m_mosq, onLog);
        /* 未拿到注册令牌前保持匿名 CONNECT;带用户名但密码为空会被
           认证插件(如 amqtt auth_file)直接拒绝 */
        if (!m_cfg.token.empty()) {
            mosquitto_username_pw_set(m_mosq, ("idsm-" + m_cfg.device_id).c_str(),
                                      m_cfg.token.c_str());
        }
        if (m_cfg.tls && !m_cfg.cafile.empty()) {
            /* 量产建议换成证书/公钥 pinning:
               mosquitto_tls_set 后校验对端证书指纹白名单,
               与 Android 侧 PinningTrustManager 语义一致 */
            mosquitto_tls_set(m_mosq, m_cfg.cafile.c_str(), nullptr,
                              nullptr, nullptr, nullptr);
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
