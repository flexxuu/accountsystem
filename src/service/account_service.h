/**
 * account_service.h
 * 账号服务接口
 */
#ifndef ACCOUNT_SERVICE_H
#define ACCOUNT_SERVICE_H

#include <memory>
#include <string>
#include "../model/account.h"

class AccountService {
public:
    virtual ~AccountService() = default;
    // 账号注册
    virtual std::string createAccount(const std::string& username, const std::string& password, 
                                     const std::string& email) = 0;
    virtual bool verifyEmail(const std::string& email, const std::string& code) = 0;
    virtual std::string login(const std::string& usernameOrEmail, const std::string& password) = 0;
    virtual bool validateToken(const std::string& token, std::string& accountId) = 0;
    
    // 账号信息
    virtual std::shared_ptr<Account> getAccountById(const std::string& id) = 0;
    virtual std::shared_ptr<Account> getAccountByUsername(const std::string& username) = 0;
    virtual std::shared_ptr<Account> getAccountByEmail(const std::string& email) = 0;
    
    // 账号更新
    virtual bool updateAccount(const std::string& accountId, const std::string& newUsername, 
                             const std::string& newEmail) = 0;
    virtual bool changePassword(const std::string& accountId, const std::string& oldPassword, 
                              const std::string& newPassword) = 0;
    
    // 账号删除
    virtual bool deleteAccount(const std::string& accountId) = 0;
};

#endif // ACCOUNT_SERVICE_H