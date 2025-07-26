/**
 * main.cpp
 * 账号系统主程序入口
 */
#include <iostream>
#include <memory>
#include <string>
#include "service/account_service_impl.h"
#include "repository/in_memory_account_repository.h"
#include "service/smtp_email_service.h"
#include "controller/rest_api_server.h"
#include "service/config_service.h"
#include "service/json_config_service.h"
#include "service/oauth2_service.h"
#include "service/service_container.h"
#include "service/oauth2_service_impl.h"
#include "service/service_registry.h"
#include "util/http_client.h"
#include "util/config_utils.h"
#include "util/poco_http_client.h"
#include <Poco/JSON/Parser.h>
#include <fstream>
#include "nlohmann/json.hpp"
#include "util/log.h"

using json = nlohmann::json;

int main() {
    try {
        // 获取配置服务
        std::unique_ptr<ConfigService> configService = std::make_unique<JsonConfigService>("/home/luc/account-system-cpp/config/app.json");

        // 初始化日志系统
        auto logConfig = configService->getLogConfig();
        util::Log::initialize(
            logConfig.at("level"),
            logConfig.at("file_path"),
            static_cast<size_t>(std::stoul(logConfig.at("max_size"))),
            static_cast<size_t>(std::stoul(logConfig.at("max_files")))
        );

        util::Log::info("应用配置加载成功");

        // 从配置读取参数
        std::string jwtSecret = configService->getJwtSecret();
        std::string smtpServer = configService->getSmtpConfig().server;
        int smtpPort = configService->getSmtpConfig().port;
        std::string smtpUsername = configService->getSmtpConfig().username;
        std::string smtpPassword = configService->getSmtpConfig().password;
        int serverPort = configService->getServerPort();
        
        // 注册核心服务
        registerCoreServices();
        registerOAuth2Services();

        // 条件注册OAuth2服务
        std::shared_ptr<OAuth2Service> oauth2Service = nullptr;
        if (configService->isOAuth2Enabled()) {
            registerOAuth2Services();
            oauth2Service = GET_SERVICE(OAuth2Service, "default");
        }

        // 获取账号服务
        auto accountService = GET_SERVICE(AccountService, "default");

        // 初始化REST API服务器
        auto server = std::make_shared<RestApiServer>(accountService, oauth2Service, serverPort);
        
        // 启动服务器
        util::Log::info("Starting account system server on port {}", serverPort);
        server->start();
        
        // 等待服务器停止
        std::cout << "Server started. Press Enter to stop..." << std::endl;
        std::cin.get();
        
        // 停止服务器
        server->stop();
        std::cout << "Server stopped." << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        util::Log::critical("Fatal error: {}", e.what());
        return 1;
    }
}