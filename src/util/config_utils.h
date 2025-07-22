#ifndef CONFIG_UTILS_H
#define CONFIG_UTILS_H

#include <string>
#include <map>
#include <optional>
#include "service/oauth2_service.h"

// 配置项结构体
struct AppConfig {
    // 服务器配置
    struct Server {
        int port = 8080;
        std::string host = "0.0.0.0";
        std::string log_level = "info";
    } server;

    // JWT配置
    struct JWT {
        std::string secret_key;
        int expires_hours = 24;
    } jwt;

    // 刷新令牌配置
    struct RefreshToken {
        std::string secret_key;
        int expires_days = 30;
    } refresh_token;

    // SMTP配置
    struct SMTP {
        std::string host;
        int port = 587;
        std::string username;
        std::string password;
        std::string from_email;
    } smtp;

    // OAuth2提供商配置
    std::map<OAuth2Provider, OAuth2Config> oauth2_providers;
};

// 配置工具类
class ConfigUtils {
public:
    // 加载配置文件
    static bool load(const std::string& file_path);

    // 获取服务器配置
    static const AppConfig::Server& getServerConfig();

    // 获取JWT配置
    static const AppConfig::JWT& getJWTConfig();

    // 获取刷新令牌配置
    static const AppConfig::RefreshToken& getRefreshTokenConfig();

    // 获取SMTP配置
    static const AppConfig::SMTP& getSMTPConfig();

    // 获取OAuth2提供商配置
    static std::optional<OAuth2Config> getOAuth2Config(OAuth2Provider provider);

    // 检查配置是否已加载
    static bool isLoaded();

private:
    static inline AppConfig config_;
    static inline bool is_loaded_ = false;
};

#endif // CONFIG_UTILS_H