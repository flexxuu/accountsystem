#include <gtest/gtest.h>
#include "model/account.h"

TEST(AccountTest, CreateAccount) {
    // 修复参数顺序：验证代码和激活状态位置纠正
    Account account("test_user", "password123", "test@example.com", "123456", true, std::chrono::system_clock::now());
    EXPECT_EQ(account.getUsername(), "test_user");
}

// TEST(AccountTest, PasswordVerification) {
//     Account account("user1", "correct_pass");
//     EXPECT_TRUE(account.verifyPassword("correct_pass"));
//     EXPECT_FALSE(account.verifyPassword("wrong_pass"));
// }

// TEST(AccountTest, AccountBalance) {
//     Account account("user2", "pass");
//     account.deposit(100.0);
//     EXPECT_EQ(account.getBalance(), 100.0);
//     account.withdraw(50.0);
//     EXPECT_EQ(account.getBalance(), 50.0);
// }