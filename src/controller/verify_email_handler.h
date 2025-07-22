#ifndef VERIFY_EMAIL_HANDLER_H
#define VERIFY_EMAIL_HANDLER_H

#include "base_request_handler.h"
#include <memory>
#include "../service/account_service.h"

class VerifyEmailHandler : public BaseRequestHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) override;

public:
    explicit VerifyEmailHandler(std::shared_ptr<AccountService> service);
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override;
private:
    std::shared_ptr<AccountService> service;
};

#endif // VERIFY_EMAIL_HANDLER_H