cmake_minimum_required(VERSION 3.22)

# 查找Google Test和依赖
include_directories(${CMAKE_SOURCE_DIR}/thirdlib/googletest/googletest/include)
find_library(GTEST_LIBRARY gtest PATHS ${CMAKE_SOURCE_DIR}/lib)
find_library(GTEST_MAIN_LIBRARY gtest_main PATHS ${CMAKE_SOURCE_DIR}/lib)
find_package(Poco REQUIRED COMPONENTS Foundation Util Net Crypto JSON)
find_package(OpenSSL REQUIRED)
include_directories(${CMAKE_SOURCE_DIR}/include)
link_directories(${CMAKE_SOURCE_DIR}/lib)

# 收集测试源文件
file(GLOB TEST_SOURCES "*.cpp")

# 创建测试可执行文件
add_executable(account_system_tests ${TEST_SOURCES})

set_target_properties(account_system_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}
)

target_include_directories(account_system_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

# 链接测试库和主程序库
 target_link_libraries(account_system_tests PRIVATE
    account_system_lib
    gtest
    gtest_main
    ${Poco_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    spdlog::spdlog
)

# 启用测试发现
include(CTest)
include(GoogleTest)
gtest_discover_tests(account_system_tests)

target_include_directories(account_system_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)