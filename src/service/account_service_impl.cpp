#include "../../thirdlib/jwt-cpp/include/jwt-cpp/jwt.h"
#include "account_service_impl.h"
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <regex>
using json_traits = jwt::traits::nlohmann_json;
#include "util/log.h"
#include "util/security_utils.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <sstream>
#include <iomanip>


AccountServiceImpl::AccountServiceImpl(std::shared_ptr<AccountRepository> repository, 
                                      std::shared_ptr<EmailService> emailService,
                                      const std::string& jwtSecret)
    : repository(repository), emailService(emailService), jwtSecret(jwtSecret) {
    Log::info("AccountServiceImpl初始化");
}

std::string AccountServiceImpl::createAccount(const std::string& username, const std::string& password, 
                                             const std::string& email) {
    Log::info("处理账号创建请求: username={}, email={}", username, email);
    try {
        // 参数验证
        validateUsername(username);
        validatePassword(password);
        validateEmail(email);

        // 检查账号是否已存在
        if (repository->getAccountByUsername(username)) {
            Log::warn("用户名已存在: {}", username);
            throw std::invalid_argument("用户名已存在");
        }
        if (repository->getAccountByEmail(email)) {
            Log::warn("邮箱已存在: {}", email);
            throw std::invalid_argument("邮箱已存在");
        }

        // 生成账号ID和密码哈希
        std::string accountId = generateUniqueId();
        std::string passwordHash = hashPassword(password);

        // 创建账号对象
        Account account(
            accountId,
            username,
            passwordHash,
            email,
            false, // 未激活状态
            std::chrono::system_clock::now()
        );

        // 保存账号
        repository->createAccount(account);

        // 生成并发送验证邮件
        std::string verificationCode = repository->createVerificationCode(email, VerificationCodeType::EMAIL_CHANGE);
        emailService->sendVerificationEmail(email, verificationCode);
        Log::info("账号创建成功，验证邮件已发送: id={}", accountId);

        return accountId;
    } catch (const std::exception& e) {
        Log::error("账号创建失败: {}", e.what());
        throw;
    }
}

void AccountServiceImpl::validateUsername(const std::string& username) {
    if (username.empty() || username.size() < 3 || username.size() > 20) {
        throw std::invalid_argument("用户名长度必须在3-20个字符之间");
    }
    if (!std::all_of(username.begin(), username.end(), [](char c) {
        return std::isalnum(c) || c == '_' || c == '-';
    })) {
        throw std::invalid_argument("用户名只能包含字母、数字、下划线和连字符");
    }
}

void AccountServiceImpl::validatePassword(const std::string& password) {
    if (password.size() < 8) {
        throw std::invalid_argument("密码长度不能少于8个字符");
    }
    if (!std::any_of(password.begin(), password.end(), ::isupper) ||
        !std::any_of(password.begin(), password.end(), ::islower) ||
        !std::any_of(password.begin(), password.end(), ::isdigit)) {
        throw std::invalid_argument("密码必须包含大小写字母和数字");
    }
}

void AccountServiceImpl::validateEmail(const std::string& email) {
    const std::regex pattern(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
    if (!std::regex_match(email, pattern)) {
        throw std::invalid_argument("邮箱格式不正确");
    }
}

std::string AccountServiceImpl::generateUniqueId() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::stringstream ss;
    ss << std::hex << ms << std::setw(4) << std::setfill('0') << std::rand() % 0x10000;
    return ss.str();
}

std::string AccountServiceImpl::hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)password.c_str(), password.size(), hash);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

bool AccountServiceImpl::verifyPassword(const std::string& password, const std::string& hash) {
    return hashPassword(password) == hash;
}

// 实现登录功能
bool AccountServiceImpl::verifyEmail(const std::string& email, const std::string& code) {
    Log::info("验证邮箱: {}", email);
    try {
        bool verified = repository->verifyCode(email, code, VerificationCodeType::EMAIL_CHANGE);
        if (verified) {
            auto account = repository->getAccountByEmail(email);
            if (account) {
                account->setActive(true);
                repository->updateAccount(account);
                Log::info("邮箱验证成功，账号已激活: {}", email);
            }
        }
        return verified;
    } catch (const std::exception& e) {
        Log::error("邮箱验证失败: {}", e.what());
        return false;
    }
}

std::string AccountServiceImpl::login(const std::string& usernameOrEmail, const std::string& password) {
    Log::info("用户登录: {}", usernameOrEmail);
    try {
        std::shared_ptr<Account> account;
        if (usernameOrEmail.find('@') != std::string::npos) {
            account = repository->getAccountByEmail(usernameOrEmail);
        } else {
            account = repository->getAccountByUsername(usernameOrEmail);
        }

        if (!account || !account->isActive()) {
            Log::warn("账号不存在或未激活: {}", usernameOrEmail);
            throw std::invalid_argument("账号不存在或未激活");
        }

        if (!verifyPassword(password, account->getPasswordHash())) {
            Log::warn("密码错误: {}", usernameOrEmail);
            throw std::invalid_argument("用户名或密码错误");
        }

        // 生成JWT令牌
        // 生成JWT访问令牌和刷新令牌
        std::string accessToken = generateJwtToken(account->getId());
        std::string refreshToken = security::generateRefreshToken(account->getId());

        // 使用JSON格式返回令牌对
        nlohmann::json tokenResponse;
        tokenResponse["access_token"] = accessToken;
        tokenResponse["refresh_token"] = refreshToken;
        tokenResponse["token_type"] = "bearer";
        tokenResponse["expires_in"] = 86400; // 访问令牌有效期24小时

        Log::info("用户登录成功，生成访问令牌和刷新令牌: {}", account->getId());
        return tokenResponse.dump();
    } catch (const std::exception& e) {
        Log::error("登录失败: {}", e.what());
        throw;
    }
}

std::string AccountServiceImpl::generateJwtToken(const std::string& accountId) {
    auto now = std::chrono::system_clock::now();
    auto expiration = now + std::chrono::hours(24);

    return jwt::create<json_traits>()
        .set_subject(accountId)
        .set_issued_at(now)
        .set_expires_at(expiration)
        .sign(jwt::algorithm::hs256{jwtSecret});
}

std::shared_ptr<Account> AccountServiceImpl::getAccountById(const std::string& id) {
    Log::info("获取账号信息: id={}", id);
    return repository->getAccountById(id);
}

std::shared_ptr<Account> AccountServiceImpl::getAccountByUsername(const std::string& username) {
    Log::info("获取账号信息: username={}", username);
    return repository->getAccountByUsername(username);
}

std::shared_ptr<Account> AccountServiceImpl::getAccountByEmail(const std::string& email) {
    Log::info("获取账号信息: email={}", email);
    return repository->getAccountByEmail(email);
}

bool AccountServiceImpl::updateAccount(const std::string& accountId, const std::string& newUsername, const std::string& newEmail) {
    Log::info("更新账号信息: id={}, newUsername={}, newEmail={}", accountId, newUsername, newEmail);
    try {
        auto account = repository->getAccountById(accountId);
        if (!account) {
            Log::warn("更新失败，账号不存在: id={}", accountId);
            return false;
        }

        bool updated = false;
        if (!newUsername.empty() && newUsername != account->getUsername()) {
            validateUsername(newUsername);
            account->setUsername(newUsername);
            updated = true;
        }

        if (!newEmail.empty() && newEmail != account->getEmail()) {
            validateEmail(newEmail);
            account->setEmail(newEmail);
            updated = true;
        }

        if (updated) {
            repository->updateAccount(account);
            Log::info("账号信息更新成功: id={}", accountId);
        } else {
            Log::info("账号信息未变更: id={}", accountId);
        }

        return updated;
    } catch (const std::exception& e) {
        Log::error("账号更新失败: {}", e.what());
        return false;
    }
}

bool AccountServiceImpl::changePassword(const std::string& accountId, const std::string& oldPassword, const std::string& newPassword) {
    Log::info("修改密码: id={}", accountId);
    try {
        auto account = repository->getAccountById(accountId);
        if (!account) {
            Log::warn("修改密码失败，账号不存在: id={}", accountId);
            return false;
        }

        if (!verifyPassword(oldPassword, account->getPasswordHash())) {
            Log::warn("原密码错误: id={}", accountId);
            return false;
        }

        validatePassword(newPassword);
        account->setPasswordHash(hashPassword(newPassword));
        repository->updateAccount(account);

        Log::info("密码修改成功: id={}", accountId);
        return true;
    } catch (const std::exception& e) {
        Log::error("密码修改失败: {}", e.what());
        return false;
    }
}

bool AccountServiceImpl::deleteAccount(const std::string& accountId) {
    Log::info("删除账号: id={}", accountId);
    try {
        bool deleted = repository->deleteAccount(accountId);
        if (deleted) {
            Log::info("账号删除成功: id={}", accountId);
        } else {
            Log::warn("删除失败，账号不存在: id={}", accountId);
        }
        return deleted;
    } catch (const std::exception& e) {
        Log::error("账号删除失败: {}", e.what());
        return false;
    }
}

bool AccountServiceImpl::validateToken(const std::string& token, std::string& accountId) {
    try {
        auto decoded = jwt::decode<json_traits>(token);
        auto verifier = jwt::verify<jwt::traits::nlohmann_json>()
            .allow_algorithm(jwt::algorithm::hs256{jwtSecret})
            .with_issuer("account-system")
            .expires_at_leeway(60); // 允许60秒的时间偏差

        verifier.verify(decoded);

        accountId = decoded.get_subject();
        Log::debug("Token验证成功: accountId={}", accountId);
        return true;
    } catch (const std::exception& e) {
        Log::error("Token validation failed: {}", e.what());
        return false;
    }
}

void AccountServiceImpl::sendPasswordResetEmail(const std::string& email) {
    Log::info("发送密码重置邮件: {}", email);
    try {
        auto account = repository->getAccountByEmail(email);
        if (!account) {
            Log::warn("密码重置失败，邮箱不存在: {}", email);
            return;
        }

        std::string resetCode = repository->createVerificationCode(email, VerificationCodeType::PASSWORD_RESET);
        emailService->sendPasswordResetEmail(email, resetCode);
        Log::info("密码重置邮件发送成功: {}", email);
    } catch (const std::exception& e) {
        Log::error("发送密码重置邮件失败: {}", e.what());
    }
}

bool AccountServiceImpl::resetPassword(const std::string& email, const std::string& code, const std::string& newPassword) {
    Log::info("重置密码: {}", email);
    try {
        bool verified = repository->verifyCode(email, code, VerificationCodeType::PASSWORD_RESET);
        if (verified) {
            auto account = repository->getAccountByEmail(email);
            if (account) {
                validatePassword(newPassword);
                account->setPasswordHash(hashPassword(newPassword));
                repository->updateAccount(account);
                Log::info("密码重置成功: {}", email);
                return true;
            }
        }
        Log::warn("密码重置失败，验证码无效: {}", email);
        return false;
    } catch (const std::exception& e) {
        Log::error("密码重置失败: {}", e.what());
        return false;
    }
}