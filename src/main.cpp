/**
 * main.cpp
 * 账号系统主程序入口
 */
#include <iostream>
#include <memory>
#include <string>
#include "account_service_impl.h"
#include "in_memory_account_repository.h"
#include "smtp_email_service.h"
#include "rest_api_server.h"
#include "oauth2_service_impl.h"
#include "http_client.h"
#include "json_parser.h"
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
        Log::initialize(
            config["log"]["level"].get<std::string>(),
            config["log"]["file_path"].get<std::string>(),
            config["log"]["max_size"].get<size_t>(),
            config["log"]["max_files"].get<size_t>()
        );

        Log::info("应用配置加载成功");

        // 从配置读取参数
        std::string jwtSecret = config["jwt"]["secret"].get<std::string>();
        std::string smtpServer = config["smtp"]["server"].get<std::string>();
        int smtpPort = config["smtp"]["port"].get<int>();
        std::string smtpUsername = config["smtp"]["username"].get<std::string>();
        std::string smtpPassword = config["smtp"]["password"].get<std::string>();
        int serverPort = config["server"]["port"].get<int>();
        
        // 初始化HTTP客户端和JSON解析器
        auto httpClient = std::make_shared<HttpClient>();
        auto jsonParser = std::make_shared<JsonParser>();
        
        // 初始化OAuth2服务
        auto oauth2Config = ConfigUtils::getOAuth2Config();
        auto oauth2Service = std::make_shared<OAuth2ServiceImpl>(accountService, httpClient, jsonParser, oauth2Config);
        
        // 初始化存储库
        auto repository = std::make_shared<InMemoryAccountRepository>();
        repository->initialize();
        
        // 初始化邮件服务
        auto emailService = std::make_shared<SmtpEmailService>(
            smtpServer, smtpPort, smtpUsername, smtpPassword
        );
        
        // 初始化账号服务
        auto accountService = std::make_shared<AccountServiceImpl>(
            repository, emailService, jwtSecret
        );
        
        // 初始化REST API服务器
        auto server = std::make_shared<RestApiServer>(accountService, oauth2Service, serverPort);
        
        // 启动服务器
        Log::info("Starting account system server on port {}", serverPort);
        server->start();
        
        // 等待服务器停止
        std::cout << "Server started. Press Enter to stop..." << std::endl;
        std::cin.get();
        
        // 停止服务器
        server->stop();
        std::cout << "Server stopped." << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        Log::critical("Fatal error: {}", e.what());
        return 1;
    }
}