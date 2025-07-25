#ifndef UTIL_CONFIG_UTILS_H
#define UTIL_CONFIG_UTILS_H

#include <string>
#include <map>
#include <optional>
#include <nlohmann/json.hpp>
#include "service/oauth2_service.h"

namespace util {

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
    /**
     * 加载应用配置
     * @param configPath 配置文件路径
     * @return 是否加载成功
     */
    static bool load(const std::string& file_path);

    /**
     * 获取服务器配置
     * @return 服务器配置
     */
    static const AppConfig::Server& getServerConfig();

    /**
     * 获取JWT配置
     * @return JWT配置
     */
    static const AppConfig::JWT& getJWTConfig();

    /**
     * 获取刷新令牌配置
     * @return 刷新令牌配置
     */
    static const AppConfig::RefreshToken& getRefreshTokenConfig();

    /**
     * 获取SMTP配置
     * @return SMTP配置
     */
    static const AppConfig::SMTP& getSMTPConfig();

    /**
     * 获取OAuth2配置
     * @param provider 提供商枚举
     * @return OAuth2配置（如果存在）
     */
    static std::optional<OAuth2Config> getOAuth2Config(OAuth2Provider provider);

    /**
     * 获取服务器端口
     * @return 服务器端口
     */
    static int getServerPort();

    /**
     * 获取数据库连接字符串
     * @return 数据库连接字符串
     */
    static std::string getDatabaseConnectionString();

    /**
     * 检查配置是否已加载
     * @return 配置是否已加载
     */
    static bool isLoaded();

private:
    static inline AppConfig config_;
    static inline bool is_loaded_ = false;
    static inline nlohmann::json app_config_;
};

} // namespace util

#endif // UTIL_CONFIG_UTILS_H