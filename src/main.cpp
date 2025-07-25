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
#include "service/oauth2_service_impl.h"
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
        // 读取配置文件
        std::ifstream config_file("config/app.json");
        if (!config_file.is_open()) {
            throw std::runtime_error("无法打开配置文件");
        }
        json config;
        config_file >> config;

        // 初始化日志系统
        util::Log::initialize(
            config["log"]["level"].get<std::string>(),
            config["log"]["file_path"].get<std::string>(),
            config["log"]["max_size"].get<size_t>(),
            config["log"]["max_files"].get<size_t>()
        );

        util::Log::info("应用配置加载成功");

        // 从配置读取参数
        std::string jwtSecret = config["jwt"]["secret"].get<std::string>();
        std::string smtpServer = config["smtp"]["server"].get<std::string>();
        int smtpPort = config["smtp"]["port"].get<int>();
        std::string smtpUsername = config["smtp"]["username"].get<std::string>();
        std::string smtpPassword = config["smtp"]["password"].get<std::string>();
        int serverPort = config["server"]["port"].get<int>();
        
        // 初始化HTTP客户端和JSON解析器
        auto httpClient = std::make_shared<PocoHttpClient>();
        
        
        // 初始化存储库
        auto repository = std::make_shared<InMemoryAccountRepository>();
        repository->initialize();

        // 初始化邮件服务
        auto emailService = std::make_shared<SmtpEmailService>(
            smtpServer, smtpPort, smtpUsername, smtpPassword
        );

        // 初始化账户服务
        auto accountServiceImpl = std::make_shared<AccountServiceImpl>(
            repository, emailService, jwtSecret
        );

        // 初始化JSON解析器
        auto jsonParser = std::make_shared<Poco::JSON::Parser>();

        // 初始化OAuth2服务
        auto oauth2Config = util::ConfigUtils::getOAuth2Config(OAuth2Provider::GOOGLE);
        auto oauth2Service = std::make_shared<OAuth2ServiceImpl>(accountServiceImpl, httpClient, jsonParser);
        if (oauth2Config.has_value()) {
            std::map<OAuth2Provider, OAuth2Config> oauth2Configs;
        oauth2Configs[OAuth2Provider::GOOGLE] = oauth2Config.value();
        oauth2Service->initialize(oauth2Configs);
        } else {
            util::Log::error("Failed to load OAuth2 configuration");
            return 1;
        }
        
        // 初始化REST API服务器
        auto server = std::make_shared<RestApiServer>(accountServiceImpl, oauth2Service, serverPort);
        
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