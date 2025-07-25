/**
 * in_memory_account_repository.h
 * 内存账号仓库实现
 */
#ifndef IN_MEMORY_ACCOUNT_REPOSITORY_H
#define IN_MEMORY_ACCOUNT_REPOSITORY_H

#include "account_repository.h"
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>

struct VerificationCode {
    std::string code;
    std::string email;
    VerificationCodeType type;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point expiryTime;
};

struct AuthToken {
    std::string token;
    std::string accountId;
    std::chrono::system_clock::time_point createdAt;
};

class InMemoryAccountRepository : public AccountRepository {
public:
    void initialize() override;
    
    // 账号操作
    std::string createAccount(const Account& account) override;
    std::shared_ptr<Account> getAccountById(const std::string& id) override;
    std::shared_ptr<Account> getAccountByUsername(const std::string& username) override;
    std::shared_ptr<Account> getAccountByEmail(const std::string& email) override;
    std::vector<std::shared_ptr<Account>> getAllAccounts() override;
    bool updateAccount(const std::shared_ptr<Account>& account) override;
    bool deleteAccount(const std::string& id) override;
    
    // 验证码操作
    std::string createVerificationCode(const std::string& email, VerificationCodeType type) override;
    bool verifyCode(const std::string& email, const std::string& code, VerificationCodeType type) override;
    
    // Token操作
    std::string createAuthToken(const std::string& accountId) override;
    bool validateToken(const std::string& token, std::string& accountId) override;
    
private:
    std::unordered_map<std::string, std::shared_ptr<Account>> accountsById;
    std::unordered_map<std::string, std::shared_ptr<Account>> accountsByUsername;
    std::unordered_map<std::string, std::shared_ptr<Account>> accountsByEmail;
    std::unordered_map<std::string, VerificationCode> verificationCodes;
    std::unordered_map<std::string, AuthToken> authTokens;
    std::mutex mutex;
    
    std::string generateRandomCode(int length);
    std::string generateRandomToken(int length);
    void cleanExpiredTokens();
};

#endif // IN_MEMORY_ACCOUNT_REPOSITORY_H