cmake_minimum_required(VERSION 3.16)
project(autosar-idsm-toolkit LANGUAGES CXX C)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Core library: mix of C (AUTOSAR API) and C++ (manager)
find_package(Threads REQUIRED)
add_library(idsm_core STATIC
    src/IdsM.c
    src/IdsM_Manager.cpp
    src/IdsM_Protocol.c
)
target_include_directories(idsm_core PUBLIC include)
target_link_libraries(idsm_core PUBLIC Threads::Threads)
target_compile_options(idsm_core PRIVATE -Wall -Wextra -Wpedantic)

# IDSRM library: SOC violation forwarding module
find_package(CURL REQUIRED)
add_library(idsrm_core STATIC
    src/IdsRm.c
    src/IdsRm_Manager.cpp
)
target_include_directories(idsrm_core PUBLIC include)
target_link_libraries(idsrm_core
    PUBLIC  idsm_core
    PRIVATE CURL::libcurl
)
target_compile_options(idsrm_core PRIVATE -Wall -Wextra -Wpedantic)

# CLI application
add_executable(idsm_cli apps/idsm_cli/main.cpp)
target_link_libraries(idsm_cli PRIVATE idsm_core idsrm_core)

# Ethernet IDS probe (Linux-only: AF_PACKET capture)
if(UNIX AND NOT APPLE)
    add_library(eth_probe_lib STATIC
        apps/eth_probe/packet.cpp
        apps/eth_probe/ip_defrag.cpp
        apps/eth_probe/stream_tcp.cpp
        apps/eth_probe/rules.cpp
        apps/eth_probe/alert.cpp
        apps/eth_probe/md5.cpp
        apps/eth_probe/proto_doip.cpp
        apps/eth_probe/proto_someip.cpp
        apps/eth_probe/proto_tls.cpp
        apps/eth_probe/proto_http.cpp
        apps/eth_probe/proto_dns.cpp
        apps/eth_probe/geoip.cpp
        apps/eth_probe/detectors.cpp
        apps/eth_probe/pipeline.cpp
        apps/eth_probe/capture.cpp
    )
    # Optional pcre2: enables pcre:"..." rule options; otherwise such rules are skipped
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(PCRE2 QUIET libpcre2-8)
    endif()
    if(PCRE2_FOUND)
        message(STATUS "eth_probe: pcre2 found (${PCRE2_VERSION}) — pcre rules enabled")
        target_compile_definitions(eth_probe_lib PUBLIC ETH_PROBE_WITH_PCRE2)
        target_include_directories(eth_probe_lib PRIVATE ${PCRE2_INCLUDE_DIRS})
        target_link_directories(eth_probe_lib PRIVATE ${PCRE2_LIBRARY_DIRS})
        target_link_libraries(eth_probe_lib PRIVATE ${PCRE2_LIBRARIES})
    else()
        message(STATUS "eth_probe: pcre2 NOT found — pcre rules will be skipped at load")
    endif()

    add_executable(eth_probe apps/eth_probe/main.cpp)
    target_link_libraries(eth_probe PRIVATE eth_probe_lib)

    # Rail B: Suricata EVE → IDSM bridge (no Suricata build dependency)
    add_executable(eve_bridge apps/eve_bridge/main.cpp apps/eve_bridge/eve.cpp)
    target_include_directories(eve_bridge PRIVATE apps/eve_bridge)
    target_link_libraries(eve_bridge PRIVATE idsm_core idsrm_core)
    target_compile_options(eve_bridge PRIVATE -Wall -Wextra -Wpedantic)
    target_include_directories(eth_probe_lib PUBLIC apps/eth_probe)
    target_link_libraries(eth_probe_lib PUBLIC idsm_core idsrm_core)
    target_compile_options(eth_probe_lib PRIVATE -Wall -Wextra -Wpedantic)

    # CAN IDS probe (Linux-only: SocketCAN capture)
    add_library(can_probe_lib STATIC
        apps/can_probe/frame.cpp
        apps/can_probe/alert.cpp
        apps/can_probe/detectors.cpp
        apps/can_probe/pipeline.cpp
        apps/can_probe/capture.cpp
    )
    target_include_directories(can_probe_lib PUBLIC apps/can_probe)
    target_link_libraries(can_probe_lib PUBLIC idsm_core idsrm_core)
    target_compile_options(can_probe_lib PRIVATE -Wall -Wextra -Wpedantic)

    add_executable(can_probe apps/can_probe/main.cpp)
    target_link_libraries(can_probe PRIVATE can_probe_lib)

    # Host IDS probe (Linux + Android: netlink PROC_CONNECTOR + /proc polling)
    add_library(host_probe_lib STATIC
        apps/host_probe/event.cpp
        apps/host_probe/sha256.cpp
        apps/host_probe/baseline.cpp
        apps/host_probe/alert.cpp
        apps/host_probe/detectors.cpp
        apps/host_probe/pipeline.cpp
        apps/host_probe/capture.cpp
    )
    target_include_directories(host_probe_lib PUBLIC apps/host_probe)
    target_link_libraries(host_probe_lib PUBLIC idsm_core idsrm_core)
    target_compile_options(host_probe_lib PRIVATE -Wall -Wextra -Wpedantic)

    add_executable(host_probe apps/host_probe/main.cpp)
    target_link_libraries(host_probe PRIVATE host_probe_lib)
else()
    message(STATUS "Skipping eth_probe/can_probe/host_probe: requires Linux (AF_PACKET/SocketCAN/POSIX procfs)")

endif()

# Linux IDSM manager daemon (probes --sink -> UDS -> MQTT/TLS cloud),
# same wire protocol as the Android IdsmManager APK
if(UNIX AND NOT APPLE)
    add_subdirectory(linux/idsm_managerd)
endif()

# Tests
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(test_idsm tests/test_idsm.cpp)
target_link_libraries(test_idsm PRIVATE idsm_core GTest::gtest_main)
target_compile_options(test_idsm PRIVATE -Wall -Wextra)

add_executable(test_idsrm tests/test_idsrm.cpp tests/test_idsrm_sink.cpp)
target_link_libraries(test_idsrm PRIVATE idsrm_core GTest::gtest_main)
target_compile_options(test_idsrm PRIVATE -Wall -Wextra)

include(GoogleTest)
gtest_discover_tests(test_idsm)
gtest_discover_tests(test_idsrm)

if(TARGET idsm_managerd_lib)
    add_executable(test_managerd tests/test_managerd.cpp)
    target_link_libraries(test_managerd PRIVATE idsm_managerd_lib GTest::gtest_main)
    target_compile_options(test_managerd PRIVATE -Wall -Wextra)
    gtest_discover_tests(test_managerd)
endif()

if(TARGET eth_probe_lib)
    add_executable(test_eth_probe
        tests/eth_probe/test_packet.cpp
        tests/eth_probe/test_ip_defrag.cpp
        tests/eth_probe/test_stream_tcp.cpp
        tests/eth_probe/test_rules.cpp
        tests/eth_probe/test_proto.cpp
        tests/eth_probe/test_geoip.cpp
        tests/eth_probe/test_detectors.cpp
        tests/eth_probe/test_pipeline.cpp
        tests/eth_probe/test_eve_bridge.cpp
        apps/eve_bridge/eve.cpp
    )
    target_include_directories(test_eth_probe PRIVATE apps/eve_bridge)
    target_link_libraries(test_eth_probe PRIVATE eth_probe_lib GTest::gtest_main)
    target_compile_options(test_eth_probe PRIVATE -Wall -Wextra)
    gtest_discover_tests(test_eth_probe)
endif()

if(TARGET can_probe_lib)
    add_executable(test_can_probe
        tests/can_probe/test_frame.cpp
        tests/can_probe/test_detectors.cpp
        tests/can_probe/test_pipeline.cpp
    )
    target_link_libraries(test_can_probe PRIVATE can_probe_lib GTest::gtest_main)
    target_compile_options(test_can_probe PRIVATE -Wall -Wextra)
    gtest_discover_tests(test_can_probe)
endif()

if(TARGET host_probe_lib)
    add_executable(test_host_probe
        tests/host_probe/test_sha256.cpp
        tests/host_probe/test_events.cpp
        tests/host_probe/test_detectors.cpp
        tests/host_probe/test_pipeline.cpp
        tests/host_probe/test_capture.cpp
    )
    target_link_libraries(test_host_probe PRIVATE host_probe_lib GTest::gtest_main)
    target_compile_options(test_host_probe PRIVATE -Wall -Wextra)
    gtest_discover_tests(test_host_probe)
endif()


# Install targets
install(TARGETS idsm_core idsrm_core idsm_cli
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include)
