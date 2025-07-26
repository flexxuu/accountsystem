#include "service_container.h"
#include "account_service_impl.h"
#include "oauth2_service_impl.h"
#include "smtp_email_service.h"
#include "config_service.h"
#include "json_config_service.h"
#include "../util/poco_http_client.h"
#include "../repository/in_memory_account_repository.h"
#include <Poco/JSON/Parser.h>
#include <memory>
#include "service_registry.h"

void registerCoreServices() {
    // 注册HTTP客户端
    REGISTER_SERVICE(HttpClient, "default", []() {
        return std::make_shared<PocoHttpClient>();
    });

    // 注册JSON解析器
    REGISTER_SERVICE(Poco::JSON::Parser, "default", []() {
        return std::make_shared<Poco::JSON::Parser>();
    });

    // 注册账号存储库
    REGISTER_SERVICE(AccountRepository, "in_memory", []() {
        auto repo = std::make_shared<InMemoryAccountRepository>();
        repo->initialize();
        return repo;
    });

    // 注册配置服务
    REGISTER_SERVICE(ConfigService, "json", []() {
        return std::make_shared<JsonConfigService>("config/app.json");
    });

    // 注册邮件服务
    REGISTER_SERVICE(EmailService, "smtp", []() -> std::shared_ptr<EmailService> {
        auto configService = ServiceContainer::getInstance().getService<ConfigService>("json");
        auto smtpConfig = configService->getSmtpConfig();
        return std::make_shared<SmtpEmailService>(
            smtpConfig.server,
            smtpConfig.port,
            smtpConfig.username,
            smtpConfig.password
        );
    });

    // 注册账号服务
    REGISTER_SERVICE(AccountService, "default", []() {
        auto repo = GET_SERVICE(AccountRepository, "in_memory");
        auto emailService = GET_SERVICE(EmailService, "smtp");
        auto configService = GET_SERVICE(ConfigService, "json");
        std::string jwtSecret = configService->getJwtSecret();
        return std::make_shared<AccountServiceImpl>(repo, emailService, configService);
    });
}

void registerOAuth2Services() {
    REGISTER_SERVICE(OAuth2Service, "default", []() -> std::shared_ptr<OAuth2Service> {
        auto accountService = GET_SERVICE(AccountService, "default");
        auto httpClient = GET_SERVICE(HttpClient, "default");
        auto jsonParser = GET_SERVICE(Poco::JSON::Parser, "default");
        return std::make_shared<OAuth2ServiceImpl>(accountService, httpClient, jsonParser);
    });
}
