#include "json_config_service.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

JsonConfigService::JsonConfigService(const std::string& configPath) {
    if (!loadConfig(configPath)) {
        throw std::runtime_error("Failed to load configuration file");
    }
}

// 修复所有成员函数的语法错误
std::string JsonConfigService::getString(const std::string& key) const {
    nlohmann::json current = config;
    std::stringstream ss(key);
    std::string part;

    while (std::getline(ss, part, '.')) {
        if (!current.contains(part)) {
            throw std::runtime_error("配置键不存在: " + key);
        }
        current = current[part];
    }

    if (!current.is_string()) {
        throw std::runtime_error("配置值不是字符串类型: " + key);
    }

    return current.get<std::string>();
}

bool JsonConfigService::loadConfig(const std::string& configPath) {
    std::ifstream file(configPath);
    if (!file.is_open()) {
        return false;
    }
    try {
        file >> config;
        return true;
    } catch (const nlohmann::json::parse_error&) {
        return false;
    }
}

std::string JsonConfigService::getJwtSecret() const {
    if (config.contains("jwt") && config["jwt"].contains("secret")) {
        return config["jwt"]["secret"].get<std::string>();
    }
    throw std::runtime_error("JWT密钥配置不存在");
}

int JsonConfigService::getServerPort() const {
    if (config.contains("server") && config["server"].contains("port")) {
        return config["server"]["port"].get<int>();
    }
    return 8080; // 默认端口
}

SmtpConfig JsonConfigService::getSmtpConfig() const {
    SmtpConfig smtpConfig;
    if (config.contains("smtp")) {
        auto& smtpNode = config["smtp"];
        smtpConfig.server = smtpNode.value("server", "smtp.example.com");
        smtpConfig.port = smtpNode.value("port", 587);
        smtpConfig.username = smtpNode.value("username", "");
        smtpConfig.password = smtpNode.value("password", "");
    }
    return smtpConfig;
}

std::string JsonConfigService::providerToString(OAuth2Provider provider) const {
    switch (provider) {
        case OAuth2Provider::GITHUB: return "github";
        default: return "custom";
    }
}

std::optional<OAuth2Config> JsonConfigService::getOAuth2Config(OAuth2Provider provider) const {
    if (!config.contains("oauth2") || !config["oauth2"].is_object()) {
        return std::nullopt;
    }

    std::string providerName = providerToString(provider);
    std::transform(providerName.begin(), providerName.end(), providerName.begin(), ::tolower);

    if (config["oauth2"].contains(providerName)) {
        auto& oauthNode = config["oauth2"][providerName];
        OAuth2Config config;
        config.clientId = oauthNode.value("clientId", "");
        config.clientSecret = oauthNode.value("clientSecret", "");
        config.redirectUri = oauthNode.value("redirectUri", "");
        config.scope = oauthNode.value("scope", "");
        config.authUrl = oauthNode.value("authUrl", "");
        config.tokenUrl = oauthNode.value("tokenUrl", "");
        config.userInfoUrl = oauthNode.value("userInfoUrl", "");
        return config;
    }
    return std::nullopt;
}

bool JsonConfigService::isOAuth2Enabled() const {
    return config.contains("oauth2") && config["oauth2"].is_object();
}

std::map<std::string, std::string> JsonConfigService::getLogConfig() const {
    std::map<std::string, std::string> logConfig;
    if (config.contains("log")) {
        auto& logNode = config["log"];
        logConfig["level"] = logNode.value("level", "info");
        logConfig["file_path"] = logNode.value("file_path", "./logs/");
        logConfig["max_size"] = std::to_string(logNode.value("max_size", 10));
        logConfig["max_files"] = std::to_string(logNode.value("max_files", 5));
    }
    return logConfig;
}