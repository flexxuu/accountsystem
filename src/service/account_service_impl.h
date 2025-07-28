/**
 * account_service_impl.h
 * 账号服务实现
 */
#ifndef ACCOUNT_SERVICE_IMPL_H
#define ACCOUNT_SERVICE_IMPL_H

#include "account_service.h"
#include "config_service.h"
#include "../repository/account_repository.h"
#include "../model/account.h"
#include "../service/email_service.h"
#include <memory>
#include <string>

// 自定义异常类，用于账号服务相关错误
class AccountException : public std::runtime_error {
public:
    enum ErrorCode {
        INVALID_USERNAME,
        INVALID_PASSWORD,
        INVALID_EMAIL,
        USERNAME_EXISTS,
        EMAIL_EXISTS,
        ACCOUNT_NOT_FOUND,
        ACCOUNT_NOT_ACTIVATED,
        INVALID_CREDENTIALS,
        INVALID_VERIFICATION_CODE
    };

    AccountException(ErrorCode code, const std::string& message)
        : std::runtime_error(message), code_(code) {}

    ErrorCode getCode() const { return code_; }

private:
    ErrorCode code_;
};

class AccountServiceImpl : public AccountService {
public:
    // 构造函数，明确依赖关系
    AccountServiceImpl(std::shared_ptr<AccountRepository> repository,
                       std::shared_ptr<EmailService> emailService,
                       std::shared_ptr<ConfigService> configService);

    // 账号管理
    std::string createAccount(const std::string& username, const std::string& password, 
                             const std::string& email) override;
    bool verifyEmail(const std::string& email, const std::string& code) override;
    std::string login(const std::string& usernameOrEmail, const std::string& password) override;
    bool validateToken(const std::string& token, std::string& accountId) override;
    
    // 账号信息查询
    std::shared_ptr<Account> getAccountById(const std::string& id) override;
    std::shared_ptr<Account> getAccountByUsername(const std::string& username) override;
    std::shared_ptr<Account> getAccountByEmail(const std::string& email) override;

    // 账号更新
    bool updateAccount(const std::string& accountId, const std::string& newUsername, 
                     const std::string& newEmail) override;
    bool changePassword(const std::string& accountId, const std::string& oldPassword, 
                      const std::string& newPassword) override;
    
    // 账号删除
    bool deleteAccount(const std::string& accountId) override;
    
    // 密码重置
    void sendPasswordResetEmail(const std::string& email);
    bool resetPassword(const std::string& email, const std::string& code, const std::string& newPassword);

private:
    // 成员变量，统一添加下划线后缀
    std::shared_ptr<AccountRepository> repository_;
    std::shared_ptr<EmailService> emailService_;
    std::shared_ptr<ConfigService> configService_;
    std::string jwtSecret_;
    int jwtExpirationHours_; // JWT过期时间（小时）
    
    // 辅助方法
    void validateUsername(const std::string& username);
    void validatePassword(const std::string& password);
    void validateEmail(const std::string& email);
    std::string generateUniqueId();
    std::string hashPassword(const std::string& password, const std::string& salt);
    bool verifyPassword(const std::string& password, const std::string& hash, const std::string& salt);
    std::string generateJwtToken(const std::string& accountId);
};

#endif // ACCOUNT_SERVICE_IMPL_H
