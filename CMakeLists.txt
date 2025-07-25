# ==============================================================================
# 根目录CMakeLists.txt - 项目主构建配置
# 负责：全局设置、依赖管理、子目录组织和整体构建协调
# 与子目录关系：通过add_subdirectory()包含子项目，子目录继承根目录配置但可覆盖特定设置
# ==============================================================================

# 设置CMake最低版本要求，确保支持现代CMake特性
cmake_minimum_required(VERSION 3.22)

# 启用策略CMP0079 - 允许子目录目标链接到父目录定义的目标
# 这是根目录与子目录协作的关键策略
cmake_policy(SET CMP0079 NEW)

# 定义项目名称及支持的编程语言
# 根目录项目作为整个构建系统的入口点
project(AccountSystem C CXX)

# ==============================================================================
# 全局配置区 - 这些设置将影响所有子目录
# ==============================================================================

# JWT库配置 - 根目录统一管理第三方库选项，子目录无需重复设置
set(JWT_JSON_LIBRARY "nlohmann_json" CACHE STRING "强制JWT使用nlohmann_json库" FORCE)
set(JWT_BUILD_TESTS OFF CACHE BOOL "禁用JWT测试构建" FORCE)
set(JWT_DISABLE_PICOJSON ON CACHE BOOL "禁用picojson支持" FORCE)
set(JWT_USE_NLOHMANN_JSON ON CACHE BOOL "启用nlohmann_json支持" FORCE)

# 设置C++标准为C++17并强制实施
# 根目录统一设置语言标准，确保所有子项目一致性
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加全局编译选项 - 开启严格警告确保代码质量
add_compile_options(-Wall -Wextra -Wpedantic)

# ==============================================================================
# 依赖管理区 - 根目录集中管理所有第三方依赖
# 子目录通过导入根目录定义的目标来使用这些依赖
# ==============================================================================

# 添加自定义CMake模块路径，用于项目特定查找模块
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# 配置Poco库查找路径 - 优先使用本地编译版本
# 根目录控制依赖位置，确保所有子项目使用相同版本依赖
list(APPEND CMAKE_PREFIX_PATH "${PROJECT_SOURCE_DIR}/thirdlib/poco-poco-1.14.2-release/build")
set(Poco_DIR "${PROJECT_SOURCE_DIR}/thirdlib/poco-poco-1.14.2-release/build" CACHE PATH "Poco库路径" FORCE)

# 查找核心依赖库 - 根目录统一查找，子目录直接使用
find_package(spdlog REQUIRED)           # 日志库
find_package(nlohmann_json 3.2.0 REQUIRED) # JSON库
find_package(fmt REQUIRED)              # 格式化库

# 查找本地编译的Poco库（关键依赖）
# 使用NO_*选项确保只使用项目内编译的版本，不依赖系统库
find_package(Poco REQUIRED COMPONENTS Net NetSSL JSON Util Foundation Crypto
    PATHS "${PROJECT_SOURCE_DIR}/thirdlib/poco-poco-1.14.2-release/build"
    NO_DEFAULT_PATH        # 不使用默认搜索路径
    NO_CMAKE_PATH          # 不搜索CMAKE_PREFIX_PATH
    NO_CMAKE_ENVIRONMENT_PATH # 忽略环境变量
    NO_SYSTEM_ENVIRONMENT_PATH # 忽略系统环境变量
    NO_CMAKE_PACKAGE_REGISTRY # 不使用CMake包注册表
    NO_CMAKE_BUILDS_PATH   # 不搜索其他构建目录
    NO_CMAKE_SYSTEM_PATH)  # 不使用系统路径

# 配置Poco库链接 - 根目录设置后所有子目录共享
link_directories("${PROJECT_SOURCE_DIR}/thirdlib/poco-poco-1.14.2-release/build/lib")
set(Poco_LIBRARIES PocoFoundation PocoNet PocoNetSSL PocoJSON PocoUtil PocoCrypto)

# ==============================================================================
# 子目录管理 - 根目录组织项目结构，子目录专注于具体模块实现
# ==============================================================================

# ==============================================================================
# 构建输出配置 - 根目录统一管理输出位置
# ==============================================================================

# 设置可执行文件输出目录为build的父目录
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/..)

# ==============================================================================
# 子目录管理 - 根目录组织项目结构，子目录专注于具体模块实现
# ==============================================================================

# 添加jwt-cpp第三方库（外部依赖）
add_subdirectory(thirdlib/jwt-cpp)

# 添加主源代码目录（核心业务逻辑）
# src子目录负责：源代码编译、库和可执行文件生成
# 根目录与src关系：提供依赖和配置，src实现具体功能
add_subdirectory(src)

# 测试目录（当前禁用）
# add_subdirectory(test)

# 配置RPATH - 确保运行时能找到本地编译的库
# 解决动态链接库路径问题，根目录统一设置避免子目录重复工作
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${PROJECT_SOURCE_DIR}/thirdlib/poco-poco-1.14.2-release/build/lib")
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

# ==============================================================================
# 安装配置 - 根目录定义安装规则
# ==============================================================================
install(TARGETS account_system_server DESTINATION bin)  # 安装可执行文件
install(DIRECTORY ${CMAKE_SOURCE_DIR}/config DESTINATION .)  # 安装配置文件
