/**
 * smtp_email_service.h
 * SMTP邮件服务实现
 */
#ifndef SMTP_EMAIL_SERVICE_H
#define SMTP_EMAIL_SERVICE_H

#include "email_service.h"
#include <string>
#include <Poco/Net/SMTPClientSession.h>
#include <Poco/Net/MailMessage.h>
#include <Poco/Net/SSLManager.h>
#include <Poco/Net/Context.h>

class SmtpEmailService : public EmailService {
public:
    virtual ~SmtpEmailService() override;
public:
    SmtpEmailService(const std::string& server, int port, 
                    const std::string& username, const std::string& password);
    
    void sendVerificationEmail(const std::string& email, const std::string& verificationCode) override;
    void sendPasswordResetEmail(const std::string& email, const std::string& resetToken) override;
    
private:
    std::string server;
    int port;
    std::string username;
    std::string password;
    
    void sendEmail(const std::string& to, const std::string& subject, const std::string& body);
};

#endif // SMTP_EMAIL_SERVICE_H