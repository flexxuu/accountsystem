/**
 * account.cpp
 * 账号模型实现
 */
#include "account.h"

Account::Account(
    const std::string& id,
    const std::string& username,
    const std::string& passwordHash,
    const std::string& email,
    bool active,
    std::chrono::system_clock::time_point createdAt
) : id(id),
    username(username),
    passwordHash(passwordHash),
    email(email),
    active(active),
    createdAt(createdAt) {}

// Getters
std::string Account::getId() const { return id; }
std::string Account::getUsername() const { return username; }
std::string Account::getPasswordHash() const { return passwordHash; }
std::string Account::getEmail() const { return email; }
bool Account::isActive() const { return active; }
std::chrono::system_clock::time_point Account::getCreatedAt() const { return createdAt; }

// Setters
void Account::setUsername(const std::string& username) { this->username = username; }
void Account::setPasswordHash(const std::string& passwordHash) { this->passwordHash = passwordHash; }
void Account::setEmail(const std::string& email) { this->email = email; }
void Account::setActive(bool active) { this->active = active; }    