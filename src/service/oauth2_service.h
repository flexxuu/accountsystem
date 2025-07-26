#ifndef OAUTH2_SERVICE_H
#define OAUTH2_SERVICE_H

#include <string>
#include <memory>
#include <map>
#include <chrono>
#include <system_error>

// 第三方平台类型
enum class OAuth2Provider {
    GITHUB,
    CUSTOM
};

// OAuth2认证结果
struct OAuth2AuthResult {
    bool success;               // 是否成功
    std::string accountId;      // 关联的本地账号ID
    std::string errorMessage;   // 错误信息
    std::map<std::string, std::string> userInfo; // 用户信息
    std::string accessToken;    // 访问令牌
    std::string refreshToken;   // 刷新令牌
    std::chrono::seconds expiresIn; // 过期时间
};

// OAuth2配置
struct OAuth2Config {
    std::string clientId;       // 客户端ID
    std::string clientSecret;   // 客户端密钥
    std::string redirectUri;    // 重定向URI
    std::string scope;          // 请求权限
    std::string authUrl;        // 授权URL
    std::string tokenUrl;       // 令牌URL
    std::string userInfoUrl;    // 用户信息URL
    std::string revokeUrl;      // 撤销令牌URL（可选）
};

// OAuth2服务接口
class OAuth2Service {
public:
    virtual ~OAuth2Service() = default;

    // 禁止复制
    OAuth2Service(const OAuth2Service&) = delete;
    OAuth2Service& operator=(const OAuth2Service&) = delete;

    // 允许移动
    OAuth2Service(OAuth2Service&&) = default;
    OAuth2Service& operator=(OAuth2Service&&) = default;

    // 初始化第三方平台配置
    virtual void initialize(const std::map<OAuth2Provider, OAuth2Config>& configs) = 0;

    // 获取第三方授权URL
    virtual std::string getAuthorizationUrl(OAuth2Provider provider, const std::string& state = "") = 0;

    // 验证授权码并获取访问令牌
    virtual OAuth2AuthResult authenticate(OAuth2Provider provider, const std::string& code, const std::string& state = "") = 0;

    // 刷新访问令牌
    virtual std::string refreshAccessToken(OAuth2Provider provider, const std::string& refreshToken) {
        throw std::system_error(std::make_error_code(std::errc::function_not_supported), 
                              "refreshAccessToken not implemented");
    }

    // 撤销访问令牌
    virtual bool revokeToken(OAuth2Provider provider, const std::string& token) {
        throw std::system_error(std::make_error_code(std::errc::function_not_supported), 
                              "revokeToken not implemented");
        return false;
    }

protected:
    // 保护的构造函数，允许派生类构造
    OAuth2Service() = default;
};

// 创建OAuth2服务实例
std::unique_ptr<OAuth2Service> createOAuth2Service();

#endif // OAUTH2_SERVICE_H