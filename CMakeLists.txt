cmake_minimum_required(VERSION 3.22)
cmake_policy(SET CMP0079 NEW)
project(AccountSystem C CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(JWT_JSON_LIBRARY "nlohmann_json" CACHE STRING "JSON library to use" FORCE)
set(JWT_BUILD_TESTS OFF CACHE BOOL "Build tests" FORCE)
set(JWT_DISABLE_PICOJSON ON CACHE BOOL "Disable picojson support" FORCE)
set(JWT_USE_NLOHMANN_JSON ON CACHE BOOL "Use nlohmann_json" FORCE)
add_subdirectory(thirdlib/jwt-cpp)
include_directories(${PROJECT_SOURCE_DIR}/thirdlib/jwt-cpp/include)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加编译选项
add_compile_options(-Wall -Wextra -Wpedantic)

# 查找依赖库

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
find_package(spdlog REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(fmt REQUIRED)
find_package(Poco REQUIRED COMPONENTS Net NetSSL Util)
add_subdirectory(src)
add_subdirectory(test)

# 设置可执行文件输出目录
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

# 安装目标
install(TARGETS account_system_server DESTINATION bin)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/config DESTINATION .)

# 修改target_link_libraries添加日志库
target_link_libraries(account_system_server PRIVATE jwt-cpp::jwt-cpp

  nlohmann_json::nlohmann_json
  spdlog::spdlog
  fmt::fmt
  Poco::Net
  Poco::NetSSL_OpenSSL
  Poco::Util
)