cmake_minimum_required(VERSION 3.10)

project(AccountSystem CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加编译选项
add_compile_options(-Wall -Wextra -Wpedantic)

# 查找依赖库
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)
# 添加spdlog依赖
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(Poco REQUIRED COMPONENTS Net NetSSL Util)

# 添加子目录
add_subdirectory(src)
add_subdirectory(test)

# 设置可执行文件输出目录
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

# 安装目标
install(TARGETS account_system_server DESTINATION bin)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/config DESTINATION .)

# 修改target_link_libraries添加日志库
target_link_libraries(account_system_server PRIVATE
  OpenSSL::SSL
  nlohmann_json::nlohmann_json
  spdlog::spdlog
  fmt::fmt
  Poco::Net
  Poco::NetSSL
  Poco::Util
)