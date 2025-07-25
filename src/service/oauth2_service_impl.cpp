#include "oauth2_service_impl.h"
#include "util/log.h"
using namespace util;
#include <sstream>
#include <chrono>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/URI.h>
#include <Poco/Net/Context.h>
#include <Poco/StreamCopier.h>
#include <Poco/Exception.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/JSON.h>
#include <Poco/JSON/Object.h>
#include <Poco/SharedPtr.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace {

// HTTP客户端实现（使用libcurl）

// JSON解析器实现
class JsonParser {
public:
    std::map<std::string, std::string> parse(const std::string& jsonStr) {
        try {
            auto j = json::parse(jsonStr);
            std::map<std::string, std::string> result;
            parseJson(j, result);
            return result;
        } catch (const std::exception& e) {
            Log::error("JSON解析失败: {}", e.what());
            return {};
        }
    }

private:
    void parseJson(const json& j, std::map<std::string, std::string>& result, const std::string& prefix = "") {
        if (j.is_object()) {
            for (auto& [key, value] : j.items()) {
                std::string newPrefix = prefix.empty() ? key : prefix + "." + key;
                parseJson(value, result, newPrefix);
            }
        } else if (j.is_array()) {
            for (size_t i = 0; i < j.size(); ++i) {
                std::string newPrefix = prefix + "[" + std::to_string(i) + "]";
                parseJson(j[i], result, newPrefix);
            }
        } else if (j.is_string()) {
            result[prefix] = j.get<std::string>();
        } else if (j.is_number()) {
            result[prefix] = std::to_string(j.get<double>());
        } else if (j.is_boolean()) {
            result[prefix] = j.get<bool>() ? "true" : "false";
        }
    }
};

} // namespace

OAuth2ServiceImpl::OAuth2ServiceImpl(std::shared_ptr<AccountService> accountService,
                                   std::shared_ptr<HttpClient> httpClient,
                                   std::shared_ptr<Poco::JSON::Parser> jsonParser)
    : accountService_(std::move(accountService)),
      httpClient_(std::move(httpClient)),
      jsonParser_(std::move(jsonParser)) {
    if (!httpClient_) httpClient_ = HttpClientFactory::createDefaultFactory()->createClient();
    if (!jsonParser_) jsonParser_ = std::make_shared<Poco::JSON::Parser>();
    Log::info("OAuth2ServiceImpl初始化成功");
}

void OAuth2ServiceImpl::initialize(const std::map<OAuth2Provider, OAuth2Config>& configs) {
    providerConfigs_ = configs;
    Log::info("OAuth2服务初始化完成，支持{}个第三方平台", configs.size());
}

std::string OAuth2ServiceImpl::getAuthorizationUrl(OAuth2Provider provider, const std::string& state) {
    auto it = providerConfigs_.find(provider);
    if (it == providerConfigs_.end()) {
        Log::error("不支持的OAuth2 provider");
        return "";
    }

    const auto& config = it->second;
    std::string actualState = state.empty() ? generateState() : state;
    storeState(actualState);

    std::stringstream ss;
    ss << config.authUrl << "?client_id=" << config.clientId
       << "&redirect_uri=" << config.redirectUri
       << "&response_type=code"
       << "&scope=" << config.scope
       << "&state=" << actualState;

    Log::info("生成OAuth2授权URL: {}", ss.str());
    return ss.str();
}

OAuth2AuthResult OAuth2ServiceImpl::authenticate(OAuth2Provider provider, const std::string& code, const std::string& state) {
    OAuth2AuthResult result;
    result.success = false;

    if (!verifyState(state)) {
        result.errorMessage = "无效的state参数"; 
        Log::warn("OAuth2认证失败: {}", result.errorMessage);
        return result;
    }

    auto it = providerConfigs_.find(provider);
    if (it == providerConfigs_.end()) {
        result.errorMessage = "不支持的OAuth2 provider";
        Log::warn("OAuth2认证失败: {}", result.errorMessage);
        return result;
    }

    try {
        const auto& config = it->second;
        std::stringstream ss;
        ss << "code=" << code
           << "&client_id=" << config.clientId
           << "&client_secret=" << config.clientSecret
           << "&redirect_uri=" << config.redirectUri
           << "&grant_type=authorization_code";

        std::map<std::string, std::string> headers = {
            {"Content-Type", "application/x-www-form-urlencoded"}
        };

        Log::info("请求OAuth2令牌: {}", config.tokenUrl);
        std::string tokenResponse = httpClient_->post(config.tokenUrl, ss.str(), headers);
        if (tokenResponse.empty()) {
            result.errorMessage = "获取令牌失败"; 
            Log::warn("OAuth2认证失败: {}", result.errorMessage);
            return result;
        }

        auto tokenData = jsonParser_->parse(tokenResponse);
        Poco::JSON::Object::Ptr tokenObj = tokenData.extract<Poco::JSON::Object::Ptr>();
        if (!tokenObj->has("access_token")) {
            result.errorMessage = "令牌响应不包含access_token: " + tokenResponse;
            Log::warn("OAuth2认证失败: {}", result.errorMessage);
            return result;
        }

        std::string accessToken = tokenObj->getValue<std::string>("access_token");
        auto userInfo = getUserInfo(provider, accessToken);
        if (userInfo.empty()) {
            result.errorMessage = "获取用户信息失败";
            Log::warn("OAuth2认证失败: {}", result.errorMessage);
            return result;
        }

        std::string providerName;
        switch (provider) {
            case OAuth2Provider::GOOGLE: providerName = "google";
                break;
            case OAuth2Provider::FACEBOOK: providerName = "facebook";
                break;
            case OAuth2Provider::GITHUB: providerName = "github";
                break;
            default: providerName = "custom";
        }

        result.accountId = processUserInfo(providerName, userInfo);
        result.userInfo = userInfo;
        result.success = true;
        Log::info("OAuth2认证成功: accountId={}", result.accountId);

    } catch (const std::exception& e) {
        result.errorMessage = std::string("认证过程异常: ") + e.what();
        Log::error("OAuth2认证异常: {}", result.errorMessage);
    }

    return result;
}

std::string OAuth2ServiceImpl::refreshAccessToken(OAuth2Provider provider, const std::string& refreshToken) {
    auto it = providerConfigs_.find(provider);
    if (it == providerConfigs_.end()) {
        Log::error("不支持的OAuth2 provider");
        return "";
    }

    const auto& config = it->second;
    std::stringstream ss;
    ss << "client_id=" << config.clientId
       << "&client_secret=" << config.clientSecret
       << "&refresh_token=" << refreshToken
       << "&grant_type=refresh_token";

    std::map<std::string, std::string> headers = {
        {"Content-Type", "application/x-www-form-urlencoded"}
    };

    Log::info("刷新OAuth2令牌: {}", config.tokenUrl);
    std::string response = httpClient_->post(config.tokenUrl, ss.str(), headers);
    auto tokenData = jsonParser_->parse(response);

    Poco::JSON::Object::Ptr tokenObj = tokenData.extract<Poco::JSON::Object::Ptr>();
    if (tokenObj->has("access_token")) {
        Log::info("OAuth2令牌刷新成功");
        return tokenObj->getValue<std::string>("access_token");
    }

    Log::warn("OAuth2令牌刷新失败: {}", response);
    return "";
}

bool OAuth2ServiceImpl::revokeToken(OAuth2Provider provider, const std::string& token) {
    auto it = providerConfigs_.find(provider);
    if (it == providerConfigs_.end()) {
        Log::error("不支持的OAuth2 provider");
        return false;
    }

    // 实际实现需要根据各provider的撤销令牌API来实现
    Log::info("撤销OAuth2令牌: {}", token);
    return true;
}

std::map<std::string, std::string> OAuth2ServiceImpl::getUserInfo(OAuth2Provider provider, const std::string& accessToken) {
    auto it = providerConfigs_.find(provider);
    if (it == providerConfigs_.end()) {
        Log::error("不支持的OAuth2 provider");
        return {};
    }

    const auto& config = it->second;
    std::map<std::string, std::string> headers = {
        {"Authorization", "Bearer " + accessToken},
        {"Accept", "application/json"}
    };

    Log::info("获取用户信息: {}", config.userInfoUrl);
    std::string response = httpClient_->get(config.userInfoUrl, headers);
    if (response.empty()) {
        Log::warn("获取用户信息失败");
        return {};
    }

    auto jsonVar = jsonParser_->parse(response);
    Poco::JSON::Object::Ptr jsonObj = jsonVar.extract<Poco::JSON::Object::Ptr>();
    std::map<std::string, std::string> userInfoMap;
    if (jsonObj) {
        std::vector<std::string> keys;
        jsonObj->getNames(keys);
        for (const auto& key : keys) {
            userInfoMap[key] = jsonObj->getValue<std::string>(key);
        }
    }
    return userInfoMap;
}

std::string OAuth2ServiceImpl::processUserInfo(const std::string& provider, const std::map<std::string, std::string>& userInfo) {
    // 根据第三方用户信息创建或关联本地账号
    // 实际实现应根据各平台的用户信息字段进行适配
    std::string email;
    auto it = userInfo.find("email");
    if (it != userInfo.end()) {
        email = it->second;
    } else {
        // 生成一个唯一ID作为邮箱
        std::string id;
        it = userInfo.find("id");
        if (it != userInfo.end()) id = it->second;
        email = provider + "." + id + "@oauth2.local";
    }

    // 检查邮箱是否已存在
    auto account = accountService_->getAccountByEmail(email);
    if (account) {
        Log::info("第三方账号已关联: {}", email);
        return account->getId();
    }

    // 创建新账号
    std::string username;
    it = userInfo.find("login"); // GitHub
    if (it == userInfo.end()) it = userInfo.find("name"); // Google/Facebook
    if (it != userInfo.end()) username = it->second;
    if (username.empty()) username = "oauth2_" + security::generateSecureRandomString(8);

    // 生成随机密码
    std::string password = security::generateSecureRandomString(16);
    return accountService_->createAccount(username, password, email);
}

std::string OAuth2ServiceImpl::generateState() {
    return security::generateSecureRandomString(32);
}

bool OAuth2ServiceImpl::verifyState(const std::string& state) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    auto now = std::chrono::system_clock::now();
    
    // 清理过期的state
    auto it = stateStore_.begin();
    while (it != stateStore_.end()) {
        if (now - it->second > std::chrono::minutes(5)) {
            it = stateStore_.erase(it);
        } else {
            ++it;
        }
    }
    
    // 验证state
    bool exists = stateStore_.count(state) > 0;
    if (exists) {
        stateStore_.erase(state); // 一次性使用
    }
    return exists;
}

void OAuth2ServiceImpl::storeState(const std::string& state) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    stateStore_[state] = std::chrono::system_clock::now();
}