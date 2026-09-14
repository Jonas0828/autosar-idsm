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
else()
    message(STATUS "Skipping eth_probe: requires Linux (AF_PACKET)")
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

add_executable(test_idsrm tests/test_idsrm.cpp)
target_link_libraries(test_idsrm PRIVATE idsrm_core GTest::gtest_main)
target_compile_options(test_idsrm PRIVATE -Wall -Wextra)

include(GoogleTest)
gtest_discover_tests(test_idsm)
gtest_discover_tests(test_idsrm)

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

# Install targets
install(TARGETS idsm_core idsrm_core idsm_cli
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include)