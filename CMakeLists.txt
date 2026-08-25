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

# Install targets
install(TARGETS idsm_core idsrm_core idsm_cli
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include)