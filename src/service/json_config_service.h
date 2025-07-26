#ifndef JSON_CONFIG_SERVICE_H
#define JSON_CONFIG_SERVICE_H

#include <string>
#include <optional>
#include <nlohmann/json.hpp>
#include "config_service.h"
#include <string>
#include <nlohmann/json.hpp>

class JsonConfigService : public ConfigService {
public:
    explicit JsonConfigService(const std::string& configPath);
    std::string getString(const std::string& key) const override;
      ~JsonConfigService() override = default;
      std::string providerToString(OAuth2Provider provider) const;
    SmtpConfig getSmtpConfig() const override;
    std::optional<OAuth2Config> getOAuth2Config(OAuth2Provider provider) const override;
    std::string getJwtSecret() const override;
    int getServerPort() const override;
    bool isOAuth2Enabled() const override;
    std::map<std::string, std::string> getLogConfig() const override;

private:
    bool loadConfig(const std::string& configPath);
    nlohmann::json config;
};

#endif // JSON_CONFIG_SERVICE_H