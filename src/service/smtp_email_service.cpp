/**
 * smtp_email_service.cpp
 * SMTP邮件服务实现
 */
#include "smtp_email_service.h"
#include <iostream>
#include <stdexcept>
#include <sstream>

#include "util/log.h"
#include <Poco/Net/SecureSMTPClientSession.h>
#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/SecureStreamSocket.h>
#include <Poco/Net/Context.h>

SmtpEmailService::SmtpEmailService(const std::string& server, int port, 
                                   const std::string& username, const std::string& password)
    : server(server), port(port), username(username), password(password) {
    // 初始化Poco SSL环境
    Poco::Net::initializeSSL();
}

SmtpEmailService::~SmtpEmailService() {
    // 清理Poco SSL环境
    Poco::Net::uninitializeSSL();
}

void SmtpEmailService::sendVerificationEmail(const std::string& email, const std::string& verificationCode) {
    std::string subject = "账号验证";
    std::stringstream body;
    body << "您好，\n\n";
    body << "感谢注册我们的服务。请使用以下验证码验证您的邮箱：\n\n";
    body << verificationCode << "\n\n";
    body << "此验证码5分钟内有效。\n\n";
    body << "如果您没有注册此服务，请忽略此邮件。\n";
    
    sendEmail(email, subject, body.str());
}

void SmtpEmailService::sendPasswordResetEmail(const std::string& email, const std::string& resetToken) {
    std::string subject = "重置密码";
    std::stringstream body;
    body << "您好，\n\n";
    body << "我们收到了您重置密码的请求。请使用以下链接重置您的密码：\n\n";
    body << "http://yourwebsite.com/reset-password?token=" << resetToken << "\n\n";
    body << "此链接1小时内有效。\n\n";
    body << "如果您没有请求重置密码，请忽略此邮件。\n";
    
    sendEmail(email, subject, body.str());
}

void SmtpEmailService::sendEmail(const std::string& to, const std::string& subject, const std::string& body) {
    Log::info("准备发送邮件: to={}, subject={}", to, subject);
    
    try {
        // 创建SSL上下文
        Poco::Net::Context::Ptr context = new Poco::Net::Context(
            Poco::Net::Context::CLIENT_USE,
            "", // 无客户端证书
            "", // 无私钥
            "", // 无CA证书路径
            Poco::Net::Context::VERIFY_RELAXED,
            9,
            false,
            "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
        );
        
        // 创建带SSL上下文的安全套接字和会话
        Poco::Net::SocketAddress addr(server, port);
        Poco::NetSSL::SecureStreamSocket socket(context);
        socket.connect(addr);
        Poco::Net::SecureSMTPClientSession session(socket);
        
        // 设置超时
        session.setTimeout(Poco::Timespan(30, 0)); // 30秒
        
        // 登录认证
        session.login(Poco::Net::SMTPClientSession::AUTH_LOGIN, username, password);
        
        // 创建邮件消息
        Poco::Net::MailMessage message;
        message.setSender(username);
        message.addRecipient(Poco::Net::MailRecipient(Poco::Net::MailRecipient::PRIMARY_RECIPIENT, to));
        message.setSubject(subject);
        
        // 设置邮件内容
        message.setContentType("text/plain; charset=UTF-8");
        message.setContent(body, Poco::Net::MailMessage::ENCODING_8BIT);
        
        // 发送邮件
        session.sendMessage(message);
        
        // 关闭会话
        session.close();
        
        Log::info("邮件发送成功: to={}", to);
    } catch (const Poco::Exception& e) {
        std::stringstream error;
        error << "邮件发送失败: " << e.displayText();
        Log::error(error.str());
        throw std::runtime_error(error.str());
    } catch (const std::exception& e) {
        std::stringstream error;
        error << "邮件发送失败: " << e.what();
        Log::error(error.str());
        throw;
    }
}