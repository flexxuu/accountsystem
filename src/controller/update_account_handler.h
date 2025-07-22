#ifndef UPDATE_ACCOUNT_HANDLER_H
#define UPDATE_ACCOUNT_HANDLER_H

#include "base_request_handler.h"
#include <memory>
#include "../service/account_service.h"

class UpdateAccountHandler : public BaseRequestHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) override;
public:
    explicit UpdateAccountHandler(std::shared_ptr<AccountService> service);
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override;
private:
    std::shared_ptr<AccountService> service;
    bool validateRequestToken(Poco::Net::HTTPServerRequest& req, std::shared_ptr<AccountService> service, std::string& accountId);
};

#endif // UPDATE_ACCOUNT_HANDLER_H