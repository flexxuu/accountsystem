/**
 * email_service.h
 * 邮件服务接口
 */
#ifndef EMAIL_SERVICE_H
#define EMAIL_SERVICE_H

#include <string>

class EmailService {
public:
    virtual ~EmailService() = default;
    
    // 发送验证邮件
    virtual void sendVerificationEmail(const std::string& email, const std::string& verificationCode) = 0;
    
    // 发送密码重置邮件
    virtual void sendPasswordResetEmail(const std::string& email, const std::string& resetToken) = 0;
};

#endif // EMAIL_SERVICE_H    