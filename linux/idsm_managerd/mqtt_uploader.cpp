#include "mqtt_uploader.h"

#include <cstdio>

#ifdef HAVE_MOSQUITTO
#include <mosquitto.h>
#include <cstring>
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
        mosquitto_message_callback_set(m_mosq, onMessage);
        mosquitto_username_pw_set(m_mosq, ("idsm-" + m_cfg.vin).c_str(),
                                  m_cfg.token.c_str());
        if (!m_cfg.cafile.empty()) {
            /* 量产建议换成证书/公钥 pinning:
               mosquitto_tls_set 后校验对端证书指纹白名单,
               与 Android 侧 PinningTrustManager 语义一致 */
            mosquitto_tls_set(m_mosq, m_cfg.cafile.c_str(), nullptr,
                              nullptr, nullptr, nullptr);
        }
        int rc = mosquitto_connect(m_mosq, m_cfg.host.c_str(), m_cfg.port, 30);
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
        return m_mosq && mosquitto_socket(m_mosq) >= 0;
    }

    bool publishAlerts(const std::string& json_array, std::string& err) override {
        const int rc = mosquitto_publish(
            m_mosq, nullptr,
            alertsTopic(m_cfg.vin).c_str(),
            static_cast<int>(json_array.size()),
            json_array.data(), 1, false);
        if (rc != MOSQ_ERR_SUCCESS) {
            err = "publish: " + std::string(mosquitto_strerror(rc));
            return false;
        }
        return true;
    }

private:
    static void onConnect(mosquitto* m, void* obj, int rc) {
        auto* self = static_cast<MosquittoUploader*>(obj);
        if (rc == 0) {
            mosquitto_subscribe(m, nullptr, rulesTopic(self->m_cfg.vin).c_str(), 1);
        }
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
};

#else

class StubUploader final : public MqttUploader {
public:
    explicit StubUploader(const MqttConfig& cfg) : m_cfg(cfg) {}
    bool start(DownlinkCallback, std::string&) override {
        std::fprintf(stderr, "[IDSMD] STUB MQTT: no libmosquitto, "
                             "alerts would go to %s:%d topic %s\n",
                     m_cfg.host.c_str(), m_cfg.port,
                     alertsTopic(m_cfg.vin).c_str());
        return true;
    }
    void stop() override {}
    bool connected() const override { return true; }
    bool publishAlerts(const std::string& json_array, std::string&) override {
        std::fprintf(stderr, "[IDSMD] STUB publish %zu bytes to %s\n",
                     json_array.size(), alertsTopic(m_cfg.vin).c_str());
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
