#include "security_utils.h"
#include "config_utils.h"
#include <Poco/SHA2Engine.h>
#include <Poco/HMACEngine.h>

#include <Poco/DigestStream.h>
#include <Poco/StreamCopier.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <nlohmann/json.hpp>

#include "log.h"

namespace security {

// 生成随机盐值
std::string generateSalt(size_t length) {
    std::vector<unsigned char> salt(length);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        util::Log::error("生成随机盐值失败");
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
    Poco::SHA2Engine sha256(Poco::SHA2Engine::SHA_256);
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
        util::Log::error("生成随机字符串失败");
        throw std::runtime_error("Failed to generate random string");
    }
    
    for (unsigned char b : randomBytes) {
        result += chars[b % chars.size()];
    }
    
    return result;
}

// HMAC-SHA256签名
std::string hmacSha256(const std::string& key, const std::string& data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen;
    
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha256(), nullptr);
    HMAC_Update(ctx, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    HMAC_Final(ctx, digest, &digestLen);
    HMAC_CTX_free(ctx);
    
    std::stringstream ss;
    for (unsigned int i = 0; i < digestLen; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    return ss.str();
}

// 生成JWT访问令牌
std::string generateJwtToken(const std::string& accountId) {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(util::ConfigUtils::getJWTConfig().expires_hours);

    auto token = jwt::create<jwt::traits::nlohmann_json>()
        .set_issued_at(now)
        .set_expires_at(exp)
        .set_payload_claim("sub", jwt::basic_claim<jwt::traits::nlohmann_json>(accountId))
        .set_payload_claim("jti", jwt::basic_claim<jwt::traits::nlohmann_json>(generateSecureRandomString(16)))
        .sign(jwt::algorithm::hs256(util::ConfigUtils::getJWTConfig().secret_key));
    return token;
}

// 生成JWT刷新令牌
std::string generateRefreshToken(const std::string& accountId) {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(24 * 30);
    
    auto token = jwt::create<jwt::traits::nlohmann_json>()
        .set_issued_at(now)
        .set_expires_at(exp)
        .set_payload_claim("sub", jwt::basic_claim<jwt::traits::nlohmann_json>(accountId))
        .set_payload_claim("jti", jwt::basic_claim<jwt::traits::nlohmann_json>(generateSecureRandomString(16)))
        .sign(jwt::algorithm::hs256(util::ConfigUtils::getRefreshTokenConfig().secret_key));
    return token;
}

// 验证JWT刷新令牌
bool validateRefreshToken(const std::string& token, std::string& accountId) {
    try {
        // 从配置获取刷新令牌密钥（实际实现应从配置文件读取）
        std::string refreshSecret = util::ConfigUtils::getRefreshTokenConfig().secret_key;
        
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
        util::Log::warn("刷新令牌验证失败: {}", e.what());
        return false;
    }
}

// SecurityUtils类方法实现
std::string SecurityUtils::hashPassword(const std::string& password) {
    std::string salt = generateSalt();
    std::string hash = hashPasswordWithSalt(password, salt);
    return salt + ":" + hash;
}

bool SecurityUtils::verifyPassword(const std::string& password, const std::string& hashedPassword) {
    size_t colonPos = hashedPassword.find(':');
    if (colonPos == std::string::npos) return false;
    
    std::string salt = hashedPassword.substr(0, colonPos);
    std::string hash = hashedPassword.substr(colonPos + 1);
    
    return verifyPasswordWithSalt(password, salt, hash);
}

std::string SecurityUtils::generateRandomString(size_t length) {
    return generateSecureRandomString(length);
}

} // namespace security