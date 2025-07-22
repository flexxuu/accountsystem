#include "security_utils.h"
#include "config_utils.h"
#include <Poco/Crypto/SHA256Engine.h>
#include <Poco/Crypto/HMACEngine.h>
#include <Poco/Crypto/Random.h>
#include <Poco/DigestStream.h>
#include <Poco/StreamCopier.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <jwt/jwt.h>
#include "log.h"

namespace security {

// 生成随机盐值
std::string generateSalt(size_t length) {
    std::vector<unsigned char> salt(length);
    Poco::Crypto::Random::bytes(salt.data(), salt.size());
        Log::error("生成随机盐值失败");
        throw std::runtime_error("Failed to generate salt");
    }
    
    std::stringstream ss;
    for (unsigned char c : salt) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

// 使用SHA256和盐值哈希密码
std::string hashPasswordWithSalt(const std::string& password, const std::string& salt) {
    std::string saltedPassword = password + salt;
    Poco::Crypto::SHA256Engine sha256;
    sha256.update(saltedPassword);
    const auto& digest = sha256.digest();
    
    std::stringstream ss;
    for (unsigned char c : digest) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

// 验证密码哈希
bool verifyPasswordWithSalt(const std::string& password, const std::string& salt, const std::string& hash) {
    return hashPasswordWithSalt(password, salt) == hash;
}

// 生成安全随机字符串
std::string generateSecureRandomString(size_t length) {
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::string result;
    result.reserve(length);
    
    std::vector<unsigned char> randomBytes(length);
    if (RAND_bytes(randomBytes.data(), randomBytes.size()) != 1) {
        Log::error("生成随机字符串失败");
        throw std::runtime_error("Failed to generate random string");
    }
    
    for (unsigned char b : randomBytes) {
        result += chars[b % chars.size()];
    }
    
    return result;
}

// HMAC-SHA256签名
std::string hmacSha256(const std::string& key, const std::string& data) {
    Poco::Crypto::HMACEngine hmac(Poco::Crypto::DigestEngine::ALG_SHA256, key.data(), key.size());
    hmac.update(data);
    const auto& digest = hmac.digest();
    
    std::stringstream ss;
    for (unsigned char c : digest) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

// 生成JWT访问令牌
std::string generateJwtToken(const std::string& accountId) {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(ConfigUtils::getJWTConfig().expires_hours);

    jwt::jwt_object obj{jwt::params{
        .algorithm = "HS256",
        .secret = ConfigUtils::getJWTConfig().secret_key,
        .payload_claims = {
            {"sub", accountId},
            {"iat", std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count()},
            {"exp", std::chrono::duration_cast<std::chrono::seconds>(exp.time_since_epoch()).count()},
            {"jti", generateSecureRandomString(16)}
        }
    }};
    return obj.signature();
}

// 生成JWT刷新令牌
std::string generateRefreshToken(const std::string& accountId) {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::days(30); // 刷新令牌有效期30天
    
    std::stringstream payload;
    payload << "sub=" << accountId
            << ";iat=" << std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count()
            << ";exp=" << std::chrono::duration_cast<std::chrono::seconds>(exp.time_since_epoch()).count()
            << ";jti=" << generateSecureRandomString(16);
    
    // 从配置获取刷新令牌密钥（实际实现应从配置文件读取）
    std::string refreshSecret = ConfigUtils::getRefreshTokenConfig().secret_key;
    return hmacSha256(refreshSecret, payload.str());
}

// 验证JWT刷新令牌
bool validateRefreshToken(const std::string& token, std::string& accountId) {
    try {
        // 从配置获取刷新令牌密钥（实际实现应从配置文件读取）
        std::string refreshSecret = ConfigUtils::getRefreshTokenConfig().secret_key;
        
        // 简单实现：分割令牌并验证签名
        // 实际实现应使用JWT库解析和验证
        std::string payload = token.substr(0, token.find_last_of('.'));
        std::string signature = token.substr(token.find_last_of('.') + 1);
        
        if (hmacSha256(refreshSecret, payload) != signature) {
            return false;
        }
        
        // 解析payload获取accountId
        // 实际实现应解析JWT payload中的claims
        size_t subPos = payload.find("sub=");
        if (subPos == std::string::npos) return false;
        
        size_t iatPos = payload.find(";iat=", subPos);
        if (iatPos == std::string::npos) return false;
        
        accountId = payload.substr(subPos + 4, iatPos - subPos - 4);
        return true;
    } catch (const std::exception& e) {
        Log::warn("刷新令牌验证失败: {}", e.what());
        return false;
    }
}

} // namespace security