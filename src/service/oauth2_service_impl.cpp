#include "oauth2_service_impl.h"
#include "util/log.h"
#include "util/http_client_factory.h"
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
#include <Poco/URIStreamFactory.h>
#include <Poco/Net/HTTPSClientSession.h>
#include <nlohmann/json.hpp>

using namespace util;
using json = nlohmann::json;

namespace {

// JSON解析工具类，统一处理JSON解析逻辑
class JsonHelper {
public:
    static std::map<std::string, std::string> parsePocoJson(Poco::Dynamic::Var& jsonVar) {
        std::map<std::string, std::string> result;
        try {
            if (jsonVar.isEmpty()) {
                Log::warn("JSON解析失败: 空对象");
                return result;
            }

            Poco::JSON::Object::Ptr jsonObj = jsonVar.extract<Poco::JSON::Object::Ptr>();
            if (!jsonObj) {
                Log::warn("JSON解析失败: 无法转换为对象");
                return result;
            }

            std::vector<std::string> keys;
            jsonObj->getNames(keys);
            for (const auto& key : keys) {
                try {
                    Poco::Dynamic::Var value = jsonObj->get(key);
                    if (!value.isEmpty()) {
                        result[key] = value.convert<std::string>();
                    }
                } catch (const std::exception& e) {
                    Log::warn("解析JSON字段 {} 失败: {}", key, e.what());
                }
            }
        } catch (const std::exception& e) {
            Log::error("JSON解析异常: {}", e.what());
        }
        return result;
    }

    static std::map<std::string, std::string> parseNlohmannJson(const std::string& jsonStr) {
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
    static void parseJson(const json& j, std::map<std::string, std::string>& result, const std::string& prefix = "") {
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
    if (!accountService_) {
        throw std::invalid_argument("AccountService不能为空");
    }
    
    if (!httpClient_) {
        Log::info("使用默认HTTP客户端");
        httpClient_ = HttpClientFactory::createDefaultFactory()->createClient();
    }
    
    if (!jsonParser_) {
        Log::info("创建默认JSON解析器");
        jsonParser_ = std::make_shared<Poco::JSON::Parser>();
    }
    
    Log::info("OAuth2ServiceImpl初始化成功");
}

void OAuth2ServiceImpl::initialize(const std::map<OAuth2Provider, OAuth2Config>& configs) {
    if (configs.empty()) {
        Log::warn("初始化OAuth2服务时配置为空");
    }
    
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

    try {
        Poco::URI uri(config.authUrl);
        uri.addQueryParameter("client_id", config.clientId);
        uri.addQueryParameter("redirect_uri", config.redirectUri);
        uri.addQueryParameter("response_type", "code");
        uri.addQueryParameter("scope", config.scope);
        uri.addQueryParameter("state", actualState);

        std::string url = uri.toString();
        Log::info("生成OAuth2授权URL: {}", url);
        return url;
    } catch (const std::exception& e) {
        Log::error("生成授权URL失败: {}", e.what());
        return "";
    }
}

OAuth2AuthResult OAuth2ServiceImpl::authenticate(OAuth2Provider provider, const std::string& code, const std::string& state) {
    OAuth2AuthResult result;
    result.success = false;

    // 验证state参数
    if (!verifyState(state)) {
        result.errorMessage = "无效的state参数"; 
        Log::warn("OAuth2认证失败: {}", result.errorMessage);
        return result;
    }

    // 检查provider是否支持
    auto it = providerConfigs_.find(provider);
    if (it == providerConfigs_.end()) {
        result.errorMessage = "不支持的OAuth2 provider";
        Log::warn("OAuth2认证失败: {}", result.errorMessage);
        return result;
    }

    try {
        const auto& config = it->second;
        
        // 构建令牌请求参数
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
            result.errorMessage = "获取令牌失败，响应为空"; 
            Log::warn("OAuth2认证失败: {}", result.errorMessage);
            return result;
        }

        // 解析令牌响应
        auto tokenData = jsonParser_->parse(tokenResponse);
        auto tokenMap = JsonHelper::parsePocoJson(tokenData);
        
        if (tokenMap.find("access_token") == tokenMap.end()) {
            result.errorMessage = "令牌响应不包含access_token: " + tokenResponse;
            Log::warn("OAuth2认证失败: {}", result.errorMessage);
            return result;
        }

        // 提取令牌信息
        std::string accessToken = tokenMap["access_token"];
        result.accessToken = accessToken;
        
        if (tokenMap.find("refresh_token") != tokenMap.end()) {
            result.refreshToken = tokenMap["refresh_token"];
        }
        
        if (tokenMap.find("expires_in") != tokenMap.end()) {
            try {
                result.expiresIn = std::chrono::seconds(std::stoi(tokenMap["expires_in"]));
            } catch (const std::exception& e) {
                Log::warn("解析过期时间失败: {}", e.what());
            }
        }

        // 获取用户信息
        auto userInfo = getUserInfo(provider, accessToken);
        if (userInfo.empty()) {
            result.errorMessage = "获取用户信息失败";
            Log::warn("OAuth2认证失败: {}", result.errorMessage);
            return result;
        }

        // 处理用户信息，创建或关联账号
        std::string providerName;
        switch (provider) {
            case OAuth2Provider::GITHUB: providerName = "github"; break;
            default: providerName = "custom"; break;
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
    
    try {
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
        if (response.empty()) {
            Log::warn("刷新令牌响应为空");
            return "";
        }

        auto tokenData = jsonParser_->parse(response);
        auto tokenMap = JsonHelper::parsePocoJson(tokenData);
        
        if (tokenMap.find("access_token") != tokenMap.end()) {
            Log::info("OAuth2令牌刷新成功");
            return tokenMap["access_token"];
        }

        Log::warn("OAuth2令牌刷新失败: 响应中没有access_token - {}", response);
    } catch (const std::exception& e) {
        Log::error("刷新令牌异常: {}", e.what());
    }
    
    return "";
}

bool OAuth2ServiceImpl::revokeToken(OAuth2Provider provider, const std::string& token) {
    auto it = providerConfigs_.find(provider);
    if (it == providerConfigs_.end()) {
        Log::error("不支持的OAuth2 provider");
        return false;
    }

    const auto& config = it->second;
    if (config.revokeUrl.empty()) {
        Log::warn("未配置撤销令牌URL，无法撤销令牌");
        return false;
    }

    try {
        std::stringstream ss;
        ss << "token=" << token
           << "&client_id=" << config.clientId
           << "&client_secret=" << config.clientSecret;

        std::map<std::string, std::string> headers = {
            {"Content-Type", "application/x-www-form-urlencoded"}
        };

        Log::info("撤销OAuth2令牌: {}", config.revokeUrl);
        std::string response = httpClient_->post(config.revokeUrl, ss.str(), headers);
        
        // 不同提供商的撤销响应可能不同，这里简化处理
        Log::info("令牌撤销响应: {}", response);
        return true;
    } catch (const std::exception& e) {
        Log::error("撤销令牌异常: {}", e.what());
        return false;
    }
}

std::map<std::string, std::string> OAuth2ServiceImpl::getUserInfo(OAuth2Provider provider, const std::string& accessToken) {
    auto it = providerConfigs_.find(provider);
    if (it == providerConfigs_.end()) {
        Log::error("不支持的OAuth2 provider");
        return {};
    }

    const auto& config = it->second;
    if (config.userInfoUrl.empty()) {
        Log::warn("未配置用户信息URL");
        return {};
    }

    try {
        std::map<std::string, std::string> headers = {
            {"Authorization", "Bearer " + accessToken},
            {"Accept", "application/json"}
        };

        Log::info("获取用户信息: {}", config.userInfoUrl);
        std::string response = httpClient_->get(config.userInfoUrl, headers);
        if (response.empty()) {
            Log::warn("获取用户信息失败，响应为空");
            return {};
        }

        return JsonHelper::parseNlohmannJson(response);
    } catch (const std::exception& e) {
        Log::error("获取用户信息异常: {}", e.what());
        return {};
    }
}

std::string OAuth2ServiceImpl::processUserInfo(const std::string& provider, const std::map<std::string, std::string>& userInfo) {
    // 根据第三方用户信息创建或关联本地账号
    std::string email;
    auto it = userInfo.find("email");
    if (it != userInfo.end() && !it->second.empty()) {
        email = it->second;
    } else {
        // 生成一个唯一ID作为邮箱
        std::string id;
        it = userInfo.find("id");
        if (it != userInfo.end()) {
            id = it->second;
        } else {
            Log::error("用户信息中没有找到id字段");
            throw std::runtime_error("无法获取第三方用户ID");
        }
        
        email = provider + "." + id + "@oauth2.local";
        Log::info("使用生成的邮箱: {}", email);
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
    if (it == userInfo.end() || it->second.empty()) {
        it = userInfo.find("name"); // Google/Facebook
    }
    
    if (it != userInfo.end() && !it->second.empty()) {
        username = it->second;
    } else {
        username = "oauth2_" + security::generateSecureRandomString(8);
        Log::info("生成随机用户名: {}", username);
    }

    // 生成随机密码
    std::string password = security::generateSecureRandomString(16);
    std::string accountId = accountService_->createAccount(username, password, email);
    
    if (accountId.empty()) {
        throw std::runtime_error("创建账号失败");
    }
    
    return accountId;
}

std::string OAuth2ServiceImpl::generateState() {
    return security::generateSecureRandomString(32);
}

bool OAuth2ServiceImpl::verifyState(const std::string& state) {
    if (state.empty()) {
        Log::warn("state参数为空");
        return false;
    }

    std::lock_guard<std::mutex> lock(stateMutex_);
    auto now = std::chrono::system_clock::now();
    
    // 清理过期的state
    cleanupExpiredStates();
    
    // 验证state
    bool exists = stateStore_.count(state) > 0;
    if (exists) {
        stateStore_.erase(state); // 一次性使用
    } else {
        Log::warn("无效的state: {}", state);
    }
    
    return exists;
}

void OAuth2ServiceImpl::storeState(const std::string& state) {
    if (state.empty()) {
        Log::warn("尝试存储空的state");
        return;
    }

    std::lock_guard<std::mutex> lock(stateMutex_);
    cleanupExpiredStates(); // 存储前先清理过期状态
    stateStore_[state] = std::chrono::system_clock::now();
    Log::debug("存储state: {}", state);
}

void OAuth2ServiceImpl::cleanupExpiredStates() {
    auto now = std::chrono::system_clock::now();
    auto it = stateStore_.begin();
    
    while (it != stateStore_.end()) {
        if (now - it->second > STATE_EXPIRY) {
            Log::debug("清理过期state: {}", it->first);
            it = stateStore_.erase(it);
        } else {
            ++it;
        }
    }
}
