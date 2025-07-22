#ifndef GET_ACCOUNT_HANDLER_H
#define GET_ACCOUNT_HANDLER_H

#include "base_request_handler.h"
#include <Poco/Net/HTTPRequestHandler.h>
#include <memory>
#include "../service/account_service.h"

class GetAccountHandler : public BaseRequestHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) override;

public:
    explicit GetAccountHandler(std::shared_ptr<AccountService> service);
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override;
private:
    std::shared_ptr<AccountService> service;
    bool validateRequestToken(Poco::Net::HTTPServerRequest& req, std::shared_ptr<AccountService> service, std::string& accountId);
};

#endif // GET_ACCOUNT_HANDLER_H