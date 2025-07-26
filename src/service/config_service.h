#ifndef CONFIG_SERVICE_H
#define CONFIG_SERVICE_H

#include <string>
#include <optional>
#include <map>
#include <vector>
#include "Poco/JSON/Parser.h"
#include "oauth2_service.h"

struct SmtpConfig {
    std::string server;
    int port;
    std::string username;
    std::string password;
};

class ConfigService {
public:
    virtual ~ConfigService() = default;
    virtual std::string getString(const std::string& key) const = 0;

    // 获取JWT密钥
    virtual std::string getJwtSecret() const = 0;

    // 获取服务器端口
    virtual int getServerPort() const = 0;

    // 获取SMTP配置
    virtual SmtpConfig getSmtpConfig() const = 0;

    // 获取OAuth2配置
    virtual std::optional<OAuth2Config> getOAuth2Config(OAuth2Provider provider) const = 0;

    // 检查OAuth2是否启用
    virtual bool isOAuth2Enabled() const = 0;

    // 获取日志配置
    virtual std::map<std::string, std::string> getLogConfig() const = 0;
};

#endif // CONFIG_SERVICE_H
