/**
 * account.h
 * 账号模型定义
 */
#ifndef ACCOUNT_H
#define ACCOUNT_H

#include <string>
#include <chrono>

class Account {
public:
    Account(
        const std::string& id,
        const std::string& username,
        const std::string& passwordHash,
        const std::string& salt,
        const std::string& email,
        bool active,
        std::chrono::system_clock::time_point createdAt
    );
    
    // Getters
    std::string getId() const;
    std::string getUsername() const;
    std::string getPasswordHash() const;
    std::string getSalt() const;
    std::string getEmail() const;
    bool isActive() const;
    std::chrono::system_clock::time_point getCreatedAt() const;
    
    // Setters
    void setUsername(const std::string& username);
    void setPasswordHash(const std::string& passwordHash);
    void setSalt(const std::string& salt);
    void setEmail(const std::string& email);
    void setActive(bool active);
    
private:
    std::string id;
    std::string username;
    std::string passwordHash;
    std::string salt;
    std::string email;
    bool active;
    std::chrono::system_clock::time_point createdAt;
};

#endif // ACCOUNT_H