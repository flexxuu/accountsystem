# ==============================================================================
# src/CMakeLists.txt - 子目录构建配置
# 角色：负责编译项目核心源代码，生成库和可执行文件
# 与根目录关系：继承根目录的所有全局设置和依赖配置，专注于源代码构建
# ==============================================================================

# 子目录不需要重复设置CMake最低版本，自动继承根目录设置
# cmake_minimum_required(VERSION 3.22) - 已在根目录定义

# ==============================================================================
# 源文件管理 - 子目录负责管理自己的源代码文件
# ==============================================================================

# 收集所有源文件（排除main.cpp，它将用于生成可执行文件）
set(SOURCES
    controller/base_request_handler.cpp
    controller/change_password_handler.cpp
    controller/delete_account_handler.cpp
    controller/get_account_handler.cpp
    controller/login_handler.cpp
    controller/not_found_handler.cpp
    controller/oauth2_authorize_handler.cpp
    controller/register_handler.cpp
    controller/request_handler_factory.cpp
    controller/rest_api_server.cpp
    controller/update_account_handler.cpp
    controller/verify_email_handler.cpp
    model/account.cpp
    repository/in_memory_account_repository.cpp
    service/account_service_impl.cpp
    service/oauth2_service_impl.cpp
    service/smtp_email_service.cpp
    util/config_utils.cpp
    util/http_client.cpp
    util/log.cpp
    util/security_utils.cpp
    util/poco_http_client.cpp
    util/http_client_factory.cpp
)
list(REMOVE_ITEM SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp")

# ==============================================================================
# 构建配置 - 使用根目录提供的依赖和设置
# ==============================================================================

# 包含头文件目录
#  ../include: 根目录下的公共头文件
#  ${CMAKE_CURRENT_SOURCE_DIR}: 当前目录的源文件头文件
include_directories(${CMAKE_SOURCE_DIR}/include)

# 创建静态库 - 子目录核心产物之一
# account_system_lib: 包含所有业务逻辑，供可执行文件链接
add_library(account_system_lib STATIC ${SOURCES})

target_include_directories(account_system_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}  # 库内部头文件
        ../include                   # 根目录公共头文件
)

# 打印JWT头文件路径 - 调试信息
message("JWT-CPP Include Path: ${CMAKE_SOURCE_DIR}/include")

# ==============================================================================
# 依赖链接 - 子目录使用根目录查找的依赖目标
# ==============================================================================

# JWT编译定义 - 继承根目录JWT配置
# 注意：子目录应遵循根目录统一设置，不重复定义全局选项

target_compile_definitions(account_system_lib
    PRIVATE
        JWT_DISABLE_PICOJSON  # 与根目录JWT_DISABLE_PICOJSON保持一致
)

# 链接库依赖 - 使用根目录已查找的目标
# 子目录无需重复find_package，直接使用根目录定义的目标
# 这种方式确保依赖版本一致性

target_link_libraries(account_system_lib
    PUBLIC
        # Poco库组件 - 使用根目录配置的本地版本
        Poco::Net Poco::NetSSL Poco::JSON Poco::Util Poco::Foundation Poco::Crypto
        # 其他第三方库 - 由根目录统一管理
        spdlog::spdlog
        jwt-cpp::jwt-cpp
        nlohmann_json::nlohmann_json
        fmt::fmt
)

# ==============================================================================
# 可执行文件生成 - 子目录最终产物
# ==============================================================================

# 创建主可执行文件
add_executable(account_system_server main.cpp)

# 链接静态库 - 可执行文件仅依赖本地库，不直接链接第三方库
# 这种设计确保依赖传递的清晰性

target_link_libraries(account_system_server
    PRIVATE
        account_system_lib  # 链接本目录生成的静态库
        # 注意：不需要重复链接第三方库，account_system_lib已包含这些依赖
)