/**
 * account_service_impl.h
 * 账号服务实现
 */
#ifndef ACCOUNT_SERVICE_IMPL_H
#define ACCOUNT_SERVICE_IMPL_H

#include "account_service.h"
#include <memory>
#include "../repository/account_repository.h"
#include "../model/account.h"
#include "../service/email_service.h"

class AccountServiceImpl : public AccountService {
public:
    AccountServiceImpl(std::shared_ptr<AccountRepository> repository, 
                      std::shared_ptr<EmailService> emailService,
                      const std::string& jwtSecret);
    
    // 账号管理
    std::string createAccount(const std::string& username, const std::string& password, 
                             const std::string& email) override;
    bool verifyEmail(const std::string& email, const std::string& code) override;
    std::string login(const std::string& usernameOrEmail, const std::string& password) override;
    bool validateToken(const std::string& token, std::string& accountId) override;
    
    // 账号信息
    std::shared_ptr<Account> getAccountById(const std::string& id) override;
    std::shared_ptr<Account> getAccountByUsername(const std::string& username) override;
    
    // 账号更新
    bool updateAccount(const std::string& accountId, const std::string& newUsername, 
                     const std::string& newEmail) override;
    bool changePassword(const std::string& accountId, const std::string& oldPassword, 
                      const std::string& newPassword) override;
    
    // 账号删除
    bool deleteAccount(const std::string& accountId) override;
    
private:
    std::shared_ptr<AccountRepository> repository;
    std::shared_ptr<EmailService> emailService;
    std::string jwtSecret;
    
    // 辅助方法
    void validateUsername(const std::string& username);
    void validatePassword(const std::string& password);
    void validateEmail(const std::string& email);
    std::string generateUniqueId();
    std::string hashPassword(const std::string& password);
    bool verifyPassword(const std::string& password, const std::string& hash);
    std::string generateJwtToken(const std::string& accountId);
};

#endif // ACCOUNT_SERVICE_IMPL_H    