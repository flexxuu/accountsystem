/**
 * account_repository.h
 * 账号仓库接口
 */
#ifndef ACCOUNT_REPOSITORY_H
#define ACCOUNT_REPOSITORY_H

#include <memory>
#include <string>
#include <vector>
#include "../model/account.h"

enum class VerificationCodeType {
    REGISTRATION,
    PASSWORD_RESET,
    EMAIL_CHANGE
};

class AccountRepository {
public:
    virtual ~AccountRepository() = default;
    
    // 初始化仓库
    virtual void initialize() = 0;
    
    // 账号操作
    virtual std::string createAccount(const Account& account) = 0;
    virtual std::shared_ptr<Account> getAccountById(const std::string& id) = 0;
    virtual std::shared_ptr<Account> getAccountByUsername(const std::string& username) = 0;
    virtual std::shared_ptr<Account> getAccountByEmail(const std::string& email) = 0;
    virtual std::vector<std::shared_ptr<Account>> getAllAccounts() = 0;
    virtual bool updateAccount(const std::shared_ptr<Account>& account) = 0;
    virtual bool deleteAccount(const std::string& id) = 0;
    
    // 验证码操作
    virtual std::string createVerificationCode(const std::string& email, VerificationCodeType type) = 0;
    virtual bool verifyCode(const std::string& email, const std::string& code, VerificationCodeType type) = 0;
    
    // Token操作
    virtual std::string createAuthToken(const std::string& accountId) = 0;
    virtual bool validateToken(const std::string& token, std::string& accountId) = 0;
};

#endif // ACCOUNT_REPOSITORY_H    