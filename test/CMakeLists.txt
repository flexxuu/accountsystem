cmake_minimum_required(VERSION 3.22)

# 查找Catch2测试框架
find_package(Catch2 2 REQUIRED)

# 收集测试源文件
file(GLOB TEST_SOURCES "*.cpp")

# 创建测试可执行文件
add_executable(account_system_tests ${TEST_SOURCES})

target_include_directories(account_system_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

# 链接测试库和主程序库
 target_link_libraries(account_system_tests PRIVATE
    account_system_lib
    Catch2::Catch2WithMain
    Poco::Net
    Poco::Util
    spdlog::spdlog
)

# 启用测试发现
include(CTest)
include(Catch)
catch_discover_tests(account_system_tests)