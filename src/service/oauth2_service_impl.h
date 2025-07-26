#ifndef OAUTH2_SERVICE_IMPL_H
#define OAUTH2_SERVICE_IMPL_H

#include "oauth2_service.h"
#include <Poco/JSON/Parser.h>
#include <mutex>
#include <memory>
#include <map>
#include <string>
#include <chrono>
#include <stdexcept>
#include "account_service.h"
#include "util/http_client.h"
#include "util/security_utils.h"
#include <nlohmann/json.hpp>

class OAuth2ServiceImpl : public OAuth2Service {
public:
    OAuth2ServiceImpl(std::shared_ptr<AccountService> accountService,
                     std::shared_ptr<HttpClient> httpClient,
                     std::shared_ptr<Poco::JSON::Parser> jsonParser);

    // 禁止复制
    OAuth2ServiceImpl(const OAuth2ServiceImpl&) = delete;
    OAuth2ServiceImpl& operator=(const OAuth2ServiceImpl&) = delete;

    // 允许移动
    OAuth2ServiceImpl(OAuth2ServiceImpl&&) = default;
    OAuth2ServiceImpl& operator=(OAuth2ServiceImpl&&) = default;

    // 初始化第三方平台配置
    void initialize(const std::map<OAuth2Provider, OAuth2Config>& configs) override;

    // 获取第三方授权URL
    std::string getAuthorizationUrl(OAuth2Provider provider, const std::string& state = "") override;

    // 验证授权码并获取访问令牌
    OAuth2AuthResult authenticate(OAuth2Provider provider, const std::string& code, const std::string& state = "") override;

    // 刷新访问令牌
    std::string refreshAccessToken(OAuth2Provider provider, const std::string& refreshToken) override;

    // 撤销访问令牌
    bool revokeToken(OAuth2Provider provider, const std::string& token) override;

private:
    // 从第三方平台获取用户信息
    std::map<std::string, std::string> getUserInfo(OAuth2Provider provider, const std::string& accessToken);

    // 处理第三方用户信息，创建或关联本地账号
    std::string processUserInfo(const std::string& provider, const std::map<std::string, std::string>& userInfo);

    // 生成随机state值
    std::string generateState();

    // 验证state值
    bool verifyState(const std::string& state);

    // 存储state值用于验证
    void storeState(const std::string& state);

    // 清理过期的state值
    void cleanupExpiredStates();

    std::shared_ptr<AccountService> accountService_;
    std::shared_ptr<HttpClient> httpClient_;
    std::shared_ptr<Poco::JSON::Parser> jsonParser_;
    std::map<OAuth2Provider, OAuth2Config> providerConfigs_;
    std::map<std::string, std::chrono::system_clock::time_point> stateStore_;
    std::mutex stateMutex_;
    
    // State的过期时间（默认5分钟）
    const std::chrono::minutes STATE_EXPIRY = std::chrono::minutes(5);
};

#endif // OAUTH2_SERVICE_IMPL_H