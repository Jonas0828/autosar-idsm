# Linux IDSM manager daemon: 探针 UDS 告警 -> 持久队列 -> MQTT/TLS 上云,
# 云端签名规则包 -> 原子切换 -> 重启探针。与 Android IdsmManager APK 同协议。

add_library(idsm_managerd_lib STATIC
    alert_queue.cpp
    socket_server.cpp
    mqtt_uploader.cpp
    property_report.cpp
    registration.cpp
    rule_manager.cpp
    vsoc_envelope.cpp
)
target_include_directories(idsm_managerd_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(idsm_managerd_lib PUBLIC Threads::Threads)
target_include_directories(idsm_managerd_lib PUBLIC ${CMAKE_SOURCE_DIR}/third_party)
target_compile_options(idsm_managerd_lib PRIVATE -Wall -Wextra -Wpedantic)

find_package(OpenSSL REQUIRED)
target_link_libraries(idsm_managerd_lib PRIVATE OpenSSL::Crypto)

# 可选 libmosquitto: 有则编真实 MQTT 实现, 无则 Stub(日志打印, 其余链路照常)
find_path(MOSQUITTO_INCLUDE_DIR mosquitto.h)
find_library(MOSQUITTO_LIBRARY NAMES mosquitto)
if(MOSQUITTO_INCLUDE_DIR AND MOSQUITTO_LIBRARY)
    target_compile_definitions(idsm_managerd_lib PRIVATE HAVE_MOSQUITTO)
    target_include_directories(idsm_managerd_lib PRIVATE ${MOSQUITTO_INCLUDE_DIR})
    target_link_libraries(idsm_managerd_lib PRIVATE ${MOSQUITTO_LIBRARY})
    message(STATUS "idsm_managerd: libmosquitto found -- real MQTT enabled")
else()
    message(STATUS "idsm_managerd: libmosquitto not found -- MQTT stub mode "
                   "(UDS/queue/rules fully active, install libmosquitto-dev to enable)")
endif()

add_executable(idsm_managerd main.cpp)
target_link_libraries(idsm_managerd PRIVATE idsm_managerd_lib)
target_compile_options(idsm_managerd PRIVATE -Wall -Wextra -Wpedantic)
