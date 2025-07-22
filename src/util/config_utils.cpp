#include "config_utils.h"
#include "log.h"
#include <fstream>
#include <nlohmann/json.hpp>
#include <stdexcept>

using json = nlohmann::json;

bool ConfigUtils::load(const std::string& file_path) {
    try {
        std::ifstream file(file_path);
        if (!file.is_open()) {
            Log::error("配置文件打开失败: {}", file_path);
            return false;
        }

        json j;
        file >> j;

        // 解析服务器配置
        if (j.contains("server")) {
            auto& server = j["server"];
            if (server.contains("port")) config_.server.port = server["port"];
            if (server.contains("host")) config_.server.host = server["host"];
            if (server.contains("log_level")) config_.server.log_level = server["log_level"];
        }

        // 解析JWT配置
        if (j.contains("jwt")) {
            auto& jwt = j["jwt"];
            if (jwt.contains("secret_key")) config_.jwt.secret_key = jwt["secret_key"];
            if (jwt.contains("expires_hours")) config_.jwt.expires_hours = jwt["expires_hours"];
        }

        // 解析刷新令牌配置
        if (j.contains("refresh_token")) {
            auto& rt = j["refresh_token"];
            if (rt.contains("secret_key")) config_.refresh_token.secret_key = rt["secret_key"];
            if (rt.contains("expires_days")) config_.refresh_token.expires_days = rt["expires_days"];
        }

        // 解析SMTP配置
        if (j.contains("smtp")) {
            auto& smtp = j["smtp"];
            if (smtp.contains("host")) config_.smtp.host = smtp["host"];
            if (smtp.contains("port")) config_.smtp.port = smtp["port"];
            if (smtp.contains("username")) config_.smtp.username = smtp["username"];
            if (smtp.contains("password")) config_.smtp.password = smtp["password"];
            if (smtp.contains("from_email")) config_.smtp.from_email = smtp["from_email"];
        }

        // 解析OAuth2提供商配置
        if (j.contains("oauth2_providers")) {
            auto& providers = j["oauth2_providers"];
            for (auto& [key, value] : providers.items()) {
                OAuth2Provider provider;
                if (key == "google") provider = OAuth2Provider::GOOGLE;
                else if (key == "facebook") provider = OAuth2Provider::FACEBOOK;
                else if (key == "github") provider = OAuth2Provider::GITHUB;
                else continue;

                OAuth2Config cfg;
                cfg.clientId = value["client_id"];
                cfg.clientSecret = value["client_secret"];
                cfg.redirectUri = value["redirect_uri"];
                cfg.scope = value["scope"];
                cfg.authUrl = value["auth_url"];
                cfg.tokenUrl = value["token_url"];
                cfg.userInfoUrl = value["user_info_url"];
                config_.oauth2_providers[provider] = cfg;
            }
        }

        is_loaded_ = true;
        Log::info("配置文件加载成功: {}", file_path);
        return true;
    } catch (const std::exception& e) {
        Log::error("配置文件解析失败: {}", e.what());
        is_loaded_ = false;
        return false;
    }
}

const AppConfig::Server& ConfigUtils::getServerConfig() {
    if (!is_loaded_) throw std::runtime_error("配置未加载");
    return config_.server;
}

const AppConfig::JWT& ConfigUtils::getJWTConfig() {
    if (!is_loaded_) throw std::runtime_error("配置未加载");
    return config_.jwt;
}

const AppConfig::RefreshToken& ConfigUtils::getRefreshTokenConfig() {
    if (!is_loaded_) throw std::runtime_error("配置未加载");
    return config_.refresh_token;
}

const AppConfig::SMTP& ConfigUtils::getSMTPConfig() {
    if (!is_loaded_) throw std::runtime_error("配置未加载");
    return config_.smtp;
}

std::optional<OAuth2Config> ConfigUtils::getOAuth2Config(OAuth2Provider provider) {
    if (!is_loaded_) return std::nullopt;
    auto it = config_.oauth2_providers.find(provider);
    return (it != config_.oauth2_providers.end()) ? std::make_optional(it->second) : std::nullopt;
}

bool ConfigUtils::isLoaded() {
    return is_loaded_;
}