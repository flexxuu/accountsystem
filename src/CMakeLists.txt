cmake_minimum_required(VERSION 3.22)

# Collect all source files except main.cpp
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
)
list(REMOVE_ITEM SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp")

# 手动查找Poco库头文件和库文件
include_directories(/usr/include)

# Create library
add_library(account_system_lib STATIC ${SOURCES})
target_include_directories(account_system_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ../thirdlib/jwt-cpp/include)
message("JWT-CPP Include Path: ${CMAKE_SOURCE_DIR}/thirdlib/jwt-cpp/include")

# Link required libraries
target_compile_definitions(account_system_lib PRIVATE JWT_DISABLE_PICOJSON)
target_link_libraries(account_system_lib PUBLIC ${POCO_NET_LIB} ${POCO_UTIL_LIB} ${POCO_JSON_LIB} ${POCO_FOUNDATION_LIB} spdlog::spdlog jwt-cpp::jwt-cpp)

# Create executable
add_executable(account_system_server main.cpp)
target_link_libraries(account_system_server PRIVATE account_system_lib)