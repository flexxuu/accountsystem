/**
 * account_test.cpp
 * 账号系统测试用例
 */
#include <gtest/gtest.h>
#include "model/account.h"
#include "repository/in_memory_account_repository.h"
#include "service/account_service_impl.h"
#include "service/json_config_service.h"
#include <memory>
#include <string>

class AccountSystemTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 初始化配置服务
        configService = std::make_shared<JsonConfigService>("/home/luc/account-system-cpp/config/app.json");
        repository = std::make_shared<InMemoryAccountRepository>();
        repository->initialize();
        
        // 创建模拟的EmailService
        emailService = std::make_shared<MockEmailService>();
        
        service = std::make_shared<AccountServiceImpl>(
            repository, emailService, configService
        );
    }
    
    class MockEmailService : public EmailService {
    public:
        void sendVerificationEmail(const std::string& email, const std::string& verificationCode) override {
            // 模拟发送邮件
            lastSentEmail = email;
            lastVerificationCode = verificationCode;
        }
        
        void sendPasswordResetEmail(const std::string& email, const std::string& resetToken) override {
            // 模拟发送邮件
            lastSentEmail = email;
            lastResetToken = resetToken;
        }
        
        std::string lastSentEmail;
        std::string lastVerificationCode;
        std::string lastResetToken;
    };
    
    std::shared_ptr<InMemoryAccountRepository> repository;
    std::shared_ptr<MockEmailService> emailService;
    std::shared_ptr<AccountServiceImpl> service;
    std::shared_ptr<JsonConfigService> configService;
};

TEST_F(AccountSystemTest, CreateAccount) {
    std::string accountId = service->createAccount("test_user", "Pass123!", "test@example.com");
    EXPECT_FALSE(accountId.empty());
    
    // 验证邮件已发送
    EXPECT_EQ(emailService->lastSentEmail, "test@example.com");
    EXPECT_FALSE(emailService->lastVerificationCode.empty());
    
    // 验证账号存在
    auto account = repository->getAccountById(accountId);
    EXPECT_TRUE(account != nullptr);
    EXPECT_EQ(account->getUsername(), "test_user");
    EXPECT_FALSE(account->isActive());
}

TEST_F(AccountSystemTest, VerifyEmail) {
    std::string accountId = service->createAccount("test_user", "Pass123!", "test@example.com");
    std::string verificationCode = emailService->lastVerificationCode;
    
    // 验证邮箱
    // 确保使用正确的验证类型
    bool result = service->verifyEmail("test@example.com", verificationCode);
    EXPECT_TRUE(result);
    
    // 验证账号已激活
    auto account = repository->getAccountById(accountId);
    EXPECT_TRUE(account->isActive());
}

TEST_F(AccountSystemTest, Login) {
    std::string accountId = service->createAccount("test_user", "Pass123!", "test@example.com");
    std::string verificationCode = emailService->lastVerificationCode;
    
    // 激活账号
    service->verifyEmail("test@example.com", verificationCode);
    
    // 登录
    std::string token = service->login("test_user", "Pass123!");
    EXPECT_FALSE(token.empty());
    
    // 验证token
    std::string extractedAccountId;
    bool valid = service->validateToken(token, extractedAccountId);
    EXPECT_TRUE(valid);
    EXPECT_EQ(extractedAccountId, accountId);
}

TEST_F(AccountSystemTest, UpdateAccount) {
        std::string accountId = service->createAccount("test_user", "Pass123!", "test@example.com");
        std::string verificationCode = emailService->lastVerificationCode;
        
        // 激活账号
        service->verifyEmail("test@example.com", verificationCode);
        
        // 更新账号
        bool result = service->updateAccount(accountId, "new_username", "new@example.com");
        EXPECT_TRUE(result);
        
        // 验证账号信息已更新
        auto account = repository->getAccountById(accountId);
        EXPECT_EQ(account->getUsername(), "new_username");
        EXPECT_EQ(account->getEmail(), "new@example.com");
        // 验证邮箱更改后账号被重置为未激活状态
        EXPECT_FALSE(account->isActive());
        
        // 验证新的验证邮件已发送
        EXPECT_EQ(emailService->lastSentEmail, "new@example.com");
        EXPECT_FALSE(emailService->lastVerificationCode.empty());
    }

TEST_F(AccountSystemTest, ChangePassword) {
    std::string accountId = service->createAccount("test_user", "Pass123!", "test@example.com");
    std::string verificationCode = emailService->lastVerificationCode;
    
    // 激活账号
    service->verifyEmail("test@example.com", verificationCode);
    
    // 更改密码
    bool result = service->changePassword(accountId, "Pass123!", "NewPass456!");
    EXPECT_TRUE(result);
    
    // 验证旧密码不再有效
    EXPECT_THROW(service->login("test_user", "Pass123!"), AccountException);
    
    // 验证新密码有效
    std::string token = service->login("test_user", "NewPass456!");
    EXPECT_FALSE(token.empty());
}

TEST_F(AccountSystemTest, DeleteAccount) {
    std::string accountId = service->createAccount("test_user", "Pass123!", "test@example.com");
    std::string verificationCode = emailService->lastVerificationCode;
    
    // 激活账号
    service->verifyEmail("test@example.com", verificationCode);
    
    // 删除账号
    bool result = service->deleteAccount(accountId);
    EXPECT_TRUE(result);
    
    // 验证账号已不存在
    auto account = repository->getAccountById(accountId);
    EXPECT_TRUE(account == nullptr);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}