/**
 * in_memory_account_repository.cpp
 * 内存账号仓库实现
 */
#include "in_memory_account_repository.h"
#include <stdexcept>
#include <algorithm>
#include <random>
#include "../util/log.h"
using namespace util;
#include <chrono>
#include <nlohmann/json.hpp>
#define JWT_USE_NLOHMANN_JSON
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <jwt-cpp/jwt.h>
using namespace jwt;

void InMemoryAccountRepository::initialize() {
    // 无需初始化，内存存储自动准备好
}

std::string InMemoryAccountRepository::createAccount(const Account& account) {
    std::lock_guard<std::mutex> lock(mutex);
    Log::debug("创建账号: username={}, email={}", account.getUsername(), account.getEmail());
    
    // 检查用户名是否已存在
    if (accountsByUsername.find(account.getUsername()) != accountsByUsername.end()) {
        throw std::invalid_argument("用户名已存在");
    }
    
    // 检查邮箱是否已存在
    if (accountsByEmail.find(account.getEmail()) != accountsByEmail.end()) {
        throw std::invalid_argument("邮箱已存在");
    }
    
    // 创建新账号
    auto accountPtr = std::make_shared<Account>(
        account.getId(),
        account.getUsername(),
        account.getPasswordHash(),
        account.getEmail(),
        account.isActive(),
        account.getCreatedAt()
    );
    
    // 存储账号
    accountsById[account.getId()] = accountPtr;
    accountsByUsername[account.getUsername()] = accountPtr;
    accountsByEmail[account.getEmail()] = accountPtr;
    
    Log::info("账号存储成功: id={}", account.getId());
    return account.getId();
}

std::shared_ptr<Account> InMemoryAccountRepository::getAccountById(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex);
    
    auto it = accountsById.find(id);
    if (it != accountsById.end()) {
        return it->second;
    }
    
    return nullptr;
}

std::shared_ptr<Account> InMemoryAccountRepository::getAccountByUsername(const std::string& username) {
    std::lock_guard<std::mutex> lock(mutex);
    
    auto it = accountsByUsername.find(username);
    if (it != accountsByUsername.end()) {
        return it->second;
    }
    
    return nullptr;
}

std::shared_ptr<Account> InMemoryAccountRepository::getAccountByEmail(const std::string& email) {
    std::lock_guard<std::mutex> lock(mutex);
    
    auto it = accountsByEmail.find(email);
    if (it != accountsByEmail.end()) {
        return it->second;
    }
    
    return nullptr;
}

std::vector<std::shared_ptr<Account>> InMemoryAccountRepository::getAllAccounts() {
    std::lock_guard<std::mutex> lock(mutex);
    
    std::vector<std::shared_ptr<Account>> result;
    result.reserve(accountsById.size());
    
    for (const auto& pair : accountsById) {
        result.push_back(pair.second);
    }
    
    return result;
}

bool InMemoryAccountRepository::updateAccount(const std::shared_ptr<Account>& account) {
    std::lock_guard<std::mutex> lock(mutex);
    
    auto it = accountsById.find(account->getId());
    if (it == accountsById.end()) {
        return false;
    }
    
    // 检查用户名是否更改
    if (it->second->getUsername() != account->getUsername()) {
        // 从旧用户名映射中移除
        accountsByUsername.erase(it->second->getUsername());
        
        // 检查新用户名是否已存在
        if (accountsByUsername.find(account->getUsername()) != accountsByUsername.end()) {
            // 恢复旧用户名
            accountsByUsername[it->second->getUsername()] = it->second;
            throw std::invalid_argument("用户名已存在");
        }
        
        // 添加新用户名映射
        accountsByUsername[account->getUsername()] = account;
    }
    
    // 检查邮箱是否更改
    if (it->second->getEmail() != account->getEmail()) {
        // 从旧邮箱映射中移除
        accountsByEmail.erase(it->second->getEmail());
        
        // 检查新邮箱是否已存在
        if (accountsByEmail.find(account->getEmail()) != accountsByEmail.end()) {
            // 恢复旧邮箱
            accountsByEmail[it->second->getEmail()] = it->second;
            throw std::invalid_argument("邮箱已存在");
        }
        
        // 添加新邮箱映射
        accountsByEmail[account->getEmail()] = account;
    }
    
    // 更新账号
    it->second = account;
    
    return true;
}

bool InMemoryAccountRepository::deleteAccount(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex);
    
    auto it = accountsById.find(id);
    if (it == accountsById.end()) {
        return false;
    }
    
    // 从用户名映射中移除
    accountsByUsername.erase(it->second->getUsername());
    
    // 从邮箱映射中移除
    accountsByEmail.erase(it->second->getEmail());
    
    // 从ID映射中移除
    accountsById.erase(it);
    
    return true;
}

std::string InMemoryAccountRepository::createVerificationCode(const std::string& email, VerificationCodeType type) {
    std::lock_guard<std::mutex> lock(mutex);
    
    // 生成随机验证码
    std::string code = generateRandomCode(6);
    
    // 存储验证码
    auto now = std::chrono::system_clock::now();
    VerificationCode verificationCode{
        code,
        email,
        type,
        now,
        now + std::chrono::minutes(15) // 15分钟有效期
    };
    
    verificationCodes[email] = verificationCode;
    
    return code;
}

bool InMemoryAccountRepository::validateToken(const std::string& token, std::string& accountId) {
    std::lock_guard<std::mutex> lock(mutex);
    
    auto it = authTokens.find(token);
    if (it == authTokens.end()) {
        return false;
    }
    
    const auto& authToken = it->second;
    
    // 检查token是否过期（1小时有效期）
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::hours>(now - authToken.createdAt);
    if (duration.count() > 1) {
        authTokens.erase(it);
        return false;
    }
    
    accountId = authToken.accountId;
    return true;
}

void InMemoryAccountRepository::cleanExpiredTokens() {
    auto now = std::chrono::system_clock::now();
    
    for (auto it = authTokens.begin(); it != authTokens.end();) {
        auto duration = std::chrono::duration_cast<std::chrono::hours>(now - it->second.createdAt);
        if (duration.count() > 1) {
            it = authTokens.erase(it);
        } else {
            ++it;
        }
    }
}

std::string InMemoryAccountRepository::generateRandomToken(int length) {
    static const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charset.size() - 1);
    
    std::string token(length, ' ');
    for (int i = 0; i < length; ++i) {
        token[i] = charset[dis(gen)];
    }
    
    return token;
}

std::string InMemoryAccountRepository::generateRandomCode(int length) {
    const std::string characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, characters.size() - 1);

    std::string code;
    for (int i = 0; i < length; ++i) {
        code += characters[distribution(generator)];
    }
    return code;
}

bool InMemoryAccountRepository::verifyCode(const std::string& email, const std::string& code, VerificationCodeType type) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = verificationCodes.find(email);
    if (it == verificationCodes.end()) return false;

    auto& codeEntry = it->second;
    if (codeEntry.code != code || codeEntry.type != type) return false;

    auto now = std::chrono::system_clock::now();
    if (codeEntry.expiryTime < now) return false;

    verificationCodes.erase(it);
    return true;
}

std::string InMemoryAccountRepository::createAuthToken(const std::string& userId) {
    auto now = std::chrono::system_clock::now();
    auto expiry = now + std::chrono::hours(24);

    // 确保已定义 JWT_USE_NLOHMANN_JSON 宏
    auto token = jwt::create<jwt::traits::nlohmann_json>(jwt::default_clock{})
        .set_issuer("account-system")
        .set_subject(userId)
        .set_issued_at(now)
        .set_expires_at(expiry)
        .sign(jwt::algorithm::none{});

    return token;
}