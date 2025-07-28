#include "../../thirdlib/jwt-cpp/include/jwt-cpp/jwt.h"
#include "account_service_impl.h"
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <regex>
#include "../util/log.h"
#include "util/security_utils.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <openssl/sha.h>
#include <random>

using json_traits = jwt::traits::nlohmann_json;
using namespace util;
using namespace std;

AccountServiceImpl::AccountServiceImpl(std::shared_ptr<AccountRepository> repository, 
                                      std::shared_ptr<EmailService> emailService,
                                      std::shared_ptr<ConfigService> configService)
    : repository_(std::move(repository)), 
      emailService_(std::move(emailService)), 
      configService_(std::move(configService)) {
    
    if (!repository_) throw std::invalid_argument("AccountRepository cannot be null");
    if (!emailService_) throw std::invalid_argument("EmailService cannot be null");
    if (!configService_) throw std::invalid_argument("ConfigService cannot be null");
    
    jwtSecret_ = configService_->getString("jwt.secret");
    if (jwtSecret_.empty()) {
        throw std::runtime_error("JWT secret is not configured");
    }
    
    // 从配置获取JWT过期时间，默认24小时
    std::string jwtExpirationStr = configService_->getString("jwt.expiration_hours");
    jwtExpirationHours_ = jwtExpirationStr.empty() ? 24 : std::stoi(jwtExpirationStr);
    
    Log::info("AccountServiceImpl initialized successfully");
}

std::string AccountServiceImpl::createAccount(const std::string& username, const std::string& password, 
                                             const std::string& email) {
    Log::info("Processing account creation: username={}, email={}", username, email);
    try {
        // 参数验证
        validateUsername(username);
        validatePassword(password);
        validateEmail(email);

        // 检查账号是否已存在
        if (repository_->getAccountByUsername(username)) {
            throw AccountException(AccountException::USERNAME_EXISTS, "Username already exists");
        }
        if (repository_->getAccountByEmail(email)) {
            throw AccountException(AccountException::EMAIL_EXISTS, "Email already exists");
        }

        // 生成账号ID和密码哈希（带盐值）
        std::string accountId = generateUniqueId();
        std::string salt = security::generateSecureRandomString(16);
        std::string passwordHash = hashPassword(password, salt);

        // 创建账号对象
        Account account(
            accountId,
            username,
            passwordHash,
            salt,
            email,
            false, // 未激活状态
            std::chrono::system_clock::now()
        );

        // 保存账号
        repository_->createAccount(account);

        // 生成并发送验证邮件
        std::string verificationCode = repository_->createVerificationCode(email, VerificationCodeType::REGISTRATION);
        emailService_->sendVerificationEmail(email, verificationCode);
        
        Log::info("Account created successfully, verification email sent: id={}", accountId);
        return accountId;
    } catch (const AccountException& e) {
        Log::warn("Account creation failed: {}", e.what());
        throw;
    } catch (const std::exception& e) {
        Log::error("Account creation error: {}", e.what());
        throw;
    }
}

void AccountServiceImpl::validateUsername(const std::string& username) {
    if (username.empty() || username.size() < 3 || username.size() > 20) {
        throw AccountException(AccountException::INVALID_USERNAME, 
                              "Username must be 3-20 characters long");
    }
    
    const std::regex pattern(R"(^[a-zA-Z0-9_-]+$)");
    if (!std::regex_match(username, pattern)) {
        throw AccountException(AccountException::INVALID_USERNAME, 
                              "Username can only contain letters, numbers, underscores and hyphens");
    }
}

void AccountServiceImpl::validatePassword(const std::string& password) {
    if (password.size() < 8) {
        throw AccountException(AccountException::INVALID_PASSWORD, 
                              "Password must be at least 8 characters long");
    }
    
    bool hasUpper = std::any_of(password.begin(), password.end(), ::isupper);
    bool hasLower = std::any_of(password.begin(), password.end(), ::islower);
    bool hasDigit = std::any_of(password.begin(), password.end(), ::isdigit);
    
    if (!hasUpper || !hasLower || !hasDigit) {
        throw AccountException(AccountException::INVALID_PASSWORD, 
                              "Password must contain uppercase letters, lowercase letters and numbers");
    }
}

void AccountServiceImpl::validateEmail(const std::string& email) {
    const std::regex pattern(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
    if (!std::regex_match(email, pattern)) {
        throw AccountException(AccountException::INVALID_EMAIL, "Invalid email format");
    }
}

std::string AccountServiceImpl::generateUniqueId() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ).count();
    
    // 使用更安全的随机数生成器
    static std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    
    std::stringstream ss;
    ss << std::hex << ms << std::setw(8) << std::setfill('0') << dist(rng);
    return ss.str();
}

std::string AccountServiceImpl::hashPassword(const std::string& password, const std::string& salt) {
    std::string saltedPassword = password + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    SHA256(reinterpret_cast<const unsigned char*>(saltedPassword.c_str()), 
           saltedPassword.size(), 
           hash);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

bool AccountServiceImpl::verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) {
    return hashPassword(password, salt) == hash;
}

bool AccountServiceImpl::verifyEmail(const std::string& email, const std::string& code) {
    Log::info("Verifying email: {}", email);
    try {
        bool verified = repository_->verifyCode(email, code, VerificationCodeType::REGISTRATION);
        if (verified) {
            auto account = repository_->getAccountByEmail(email);
            if (account) {
                account->setActive(true);
                repository_->updateAccount(account);
                Log::info("Email verified successfully, account activated: {}", email);
            } else {
                Log::warn("Email verified but account not found: {}", email);
                return false;
            }
        } else {
            Log::warn("Email verification failed: invalid code for {}", email);
            throw AccountException(AccountException::INVALID_VERIFICATION_CODE, "Invalid verification code");
        }
        return verified;
    } catch (const std::exception& e) {
        Log::error("Email verification error: {}", e.what());
        return false;
    }
}

std::string AccountServiceImpl::login(const std::string& usernameOrEmail, const std::string& password) {
    Log::info("User login attempt: {}", usernameOrEmail);
    try {
        std::shared_ptr<Account> account;
        
        if (usernameOrEmail.find('@') != std::string::npos) {
            account = repository_->getAccountByEmail(usernameOrEmail);
        } else {
            account = repository_->getAccountByUsername(usernameOrEmail);
        }

        if (!account) {
            throw AccountException(AccountException::ACCOUNT_NOT_FOUND, "Account not found");
        }

        if (!account->isActive()) {
            throw AccountException(AccountException::ACCOUNT_NOT_ACTIVATED, "Account not activated");
        }

        if (!verifyPassword(password, account->getPasswordHash(), account->getSalt())) {
            throw AccountException(AccountException::INVALID_CREDENTIALS, "Invalid username or password");
        }

        // 生成JWT令牌
        std::string accessToken = generateJwtToken(account->getId());
        Log::info("User logged in successfully: {}", account->getId());
        return accessToken;
    } catch (const AccountException& e) {
        Log::warn("Login failed: {}", e.what());
        throw;
    } catch (const std::exception& e) {
        Log::error("Login error: {}", e.what());
        throw;
    }
}

std::string AccountServiceImpl::generateJwtToken(const std::string& accountId) {
    auto now = std::chrono::system_clock::now();
    auto expiration = now + std::chrono::hours(jwtExpirationHours_);

    return jwt::create<json_traits>()
        .set_subject(accountId)
        .set_issuer("account-system")
        .set_issued_at(now)
        .set_expires_at(expiration)
        .sign(jwt::algorithm::hs256{jwtSecret_});
}

std::shared_ptr<Account> AccountServiceImpl::getAccountById(const std::string& id) {
    Log::info("Retrieving account: id={}", id);
    return repository_->getAccountById(id);
}

std::shared_ptr<Account> AccountServiceImpl::getAccountByUsername(const std::string& username) {
    Log::info("Retrieving account: username={}", username);
    return repository_->getAccountByUsername(username);
}

std::shared_ptr<Account> AccountServiceImpl::getAccountByEmail(const std::string& email) {
    Log::info("Retrieving account: email={}", email);
    return repository_->getAccountByEmail(email);
}

bool AccountServiceImpl::updateAccount(const std::string& accountId, const std::string& newUsername, const std::string& newEmail) {
    Log::info("Updating account: id={}, newUsername={}, newEmail={}", accountId, newUsername, newEmail);
    try {
        auto account = repository_->getAccountById(accountId);
        if (!account) {
            throw AccountException(AccountException::ACCOUNT_NOT_FOUND, "Account not found");
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
            account->setActive(false);
            updated = true;
            
            // 发送新邮箱验证邮件
            std::string verificationCode = repository_->createVerificationCode(newEmail, VerificationCodeType::REGISTRATION);
            emailService_->sendVerificationEmail(newEmail, verificationCode);
        }

        if (updated) {
            repository_->updateAccount(account);
            Log::info("Account updated successfully: id={}", accountId);
        } else {
            Log::info("No changes made to account: id={}", accountId);
        }

        return updated;
    } catch (const std::exception& e) {
        Log::error("Account update failed: {}", e.what());
        return false;
    }
}

bool AccountServiceImpl::changePassword(const std::string& accountId, const std::string& oldPassword, const std::string& newPassword) {
    Log::info("Changing password: id={}", accountId);
    try {
        auto account = repository_->getAccountById(accountId);
        if (!account) {
            throw AccountException(AccountException::ACCOUNT_NOT_FOUND, "Account not found");
        }

        if (!verifyPassword(oldPassword, account->getPasswordHash(), account->getSalt())) {
            throw AccountException(AccountException::INVALID_CREDENTIALS, "Incorrect old password");
        }

        validatePassword(newPassword);
        
        // 生成新的盐值和哈希
        std::string newSalt = security::generateSecureRandomString(16);
        std::string newPasswordHash = hashPassword(newPassword, newSalt);
        account->setPasswordHash(newPasswordHash);
        account->setSalt(newSalt);

        
        repository_->updateAccount(account);
        Log::info("Password changed successfully: id={}", accountId);
        return true;
    } catch (const AccountException& e) {
        Log::warn("Password change failed: {}", e.what());
        return false;
    } catch (const std::exception& e) {
        Log::error("Password change error: {}", e.what());
        return false;
    }
}

bool AccountServiceImpl::deleteAccount(const std::string& accountId) {
    Log::info("Deleting account: id={}", accountId);
    try {
        bool deleted = repository_->deleteAccount(accountId);
        if (deleted) {
            Log::info("Account deleted successfully: id={}", accountId);
        } else {
            Log::warn("Account deletion failed - account not found: id={}", accountId);
            throw AccountException(AccountException::ACCOUNT_NOT_FOUND, "Account not found");
        }
        return deleted;
    } catch (const std::exception& e) {
        Log::error("Account deletion error: {}", e.what());
        return false;
    }
}

bool AccountServiceImpl::validateToken(const std::string& token, std::string& accountId) {
    try {
        auto decoded = jwt::decode<json_traits>(token);
        auto verifier = jwt::verify<json_traits>()
            .allow_algorithm(jwt::algorithm::hs256{jwtSecret_})
            .with_issuer("account-system")
            .expires_at_leeway(60); // 允许60秒的时间偏差

        verifier.verify(decoded);

        accountId = decoded.get_subject();
        Log::debug("Token validated successfully: accountId={}", accountId);
        return true;
    } catch (const std::exception& e) {
        Log::error("Token validation failed: {}", e.what());
        return false;
    }
}

void AccountServiceImpl::sendPasswordResetEmail(const std::string& email) {
    Log::info("Sending password reset email: {}", email);
    try {
        auto account = repository_->getAccountByEmail(email);
        if (!account) {
            Log::warn("Password reset requested for non-existent email: {}", email);
            return;
        }

        std::string resetCode = repository_->createVerificationCode(email, VerificationCodeType::PASSWORD_RESET);
        emailService_->sendPasswordResetEmail(email, resetCode);
        Log::info("Password reset email sent successfully: {}", email);
    } catch (const std::exception& e) {
        Log::error("Failed to send password reset email: {}", e.what());
    }
}

bool AccountServiceImpl::resetPassword(const std::string& email, const std::string& code, const std::string& newPassword) {
    Log::info("Resetting password: {}", email);
    try {
        bool verified = repository_->verifyCode(email, code, VerificationCodeType::PASSWORD_RESET);
        if (!verified) {
            Log::warn("Password reset failed - invalid code: {}", email);
            throw AccountException(AccountException::INVALID_VERIFICATION_CODE, "Invalid reset code");
        }

        auto account = repository_->getAccountByEmail(email);
        if (!account) {
            Log::warn("Password reset failed - account not found: {}", email);
            throw AccountException(AccountException::ACCOUNT_NOT_FOUND, "Account not found");
        }

        validatePassword(newPassword);
        
        // 生成新的盐值和哈希
        std::string newSalt = security::generateSecureRandomString(16);
        account->setPasswordHash(hashPassword(newPassword, newSalt));
        account->setSalt(newSalt);

        
        repository_->updateAccount(account);
        Log::info("Password reset successfully: {}", email);
        return true;
    } catch (const AccountException& e) {
        Log::warn("Password reset failed: {}", e.what());
        return false;
    } catch (const std::exception& e) {
        Log::error("Password reset error: {}", e.what());
        return false;
    }
}