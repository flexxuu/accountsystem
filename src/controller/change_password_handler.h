#ifndef CHANGE_PASSWORD_HANDLER_H
#define CHANGE_PASSWORD_HANDLER_H

#include "base_request_handler.h"
#include <memory>
#include "../service/account_service.h"

class ChangePasswordHandler : public BaseRequestHandler {
public:
    explicit ChangePasswordHandler(std::shared_ptr<AccountService> service);
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override;
private:
    std::shared_ptr<AccountService> service;
    bool validateRequestToken(Poco::Net::HTTPServerRequest& req, std::shared_ptr<AccountService> service, std::string& accountId);
};

#endif // CHANGE_PASSWORD_HANDLER_H