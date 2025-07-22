#ifndef OAUTH2_SERVICE_H
#define OAUTH2_SERVICE_H

#include <string>
#include <memory>
#include <map>

// 第三方平台类型
enum class OAuth2Provider {
    GOOGLE,
    FACEBOOK,
    GITHUB,
    CUSTOM
};

// OAuth2认证结果
struct OAuth2AuthResult {
    bool success;               // 是否成功
    std::string accountId;      // 关联的本地账号ID
    std::string errorMessage;   // 错误信息
    std::map<std::string, std::string> userInfo; // 用户信息
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
};

// OAuth2服务接口
class OAuth2Service {
public:
    virtual ~OAuth2Service() = default;

    // 初始化第三方平台配置
    virtual void initialize(const std::map<OAuth2Provider, OAuth2Config>& configs) = 0;

    // 获取第三方授权URL
    virtual std::string getAuthorizationUrl(OAuth2Provider provider, const std::string& state = "") = 0;

    // 验证授权码并获取访问令牌
    virtual OAuth2AuthResult authenticate(OAuth2Provider provider, const std::string& code, const std::string& state = "") = 0;

    // 刷新访问令牌
    virtual std::string refreshAccessToken(OAuth2Provider provider, const std::string& refreshToken) = 0;

    // 撤销访问令牌
    virtual bool revokeToken(OAuth2Provider provider, const std::string& token) = 0;
};

// 创建OAuth2服务实例
std::unique_ptr<OAuth2Service> createOAuth2Service();

#endif // OAUTH2_SERVICE_H