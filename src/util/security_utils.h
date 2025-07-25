#ifndef SECURITY_UTILS_H
#define SECURITY_UTILS_H

#include <string>
#include <vector>

namespace security {

// 生成随机盐值
std::string generateSalt(size_t length = 16);

// 使用SHA256和盐值哈希密码
std::string hashPasswordWithSalt(const std::string& password, const std::string& salt);

// 验证密码哈希
bool verifyPasswordWithSalt(const std::string& password, const std::string& salt, const std::string& hash);

// 生成安全随机字符串
std::string generateSecureRandomString(size_t length = 32);

// HMAC-SHA256签名
std::string hmacSha256(const std::string& key, const std::string& data);

// 生成JWT访问令牌
std::string generateJwtToken(const std::string& accountId);

// 生成JWT刷新令牌
std::string generateRefreshToken(const std::string& accountId);

// 验证JWT刷新令牌
bool validateRefreshToken(const std::string& token, std::string& accountId);

class SecurityUtils {
public:
    /**
     * 哈希密码
     * @param password 原始密码
     * @return 哈希后的密码
     */
    static std::string hashPassword(const std::string& password);

    /**
     * 验证密码
     * @param password 原始密码
     * @param hashedPassword 哈希后的密码
     * @return 是否验证成功
     */
    static bool verifyPassword(const std::string& password, const std::string& hashedPassword);

    /**
     * 生成随机字符串
     * @param length 字符串长度
     * @return 随机字符串
     */
    static std::string generateRandomString(size_t length);
};

} // namespace security

#endif // SECURITY_UTILS_H