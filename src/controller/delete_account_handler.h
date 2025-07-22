#ifndef DELETE_ACCOUNT_HANDLER_H
#define DELETE_ACCOUNT_HANDLER_H

#include "base_request_handler.h"
#include <memory>
#include "../service/account_service.h"

class DeleteAccountHandler : public BaseRequestHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) override;
public:
    explicit DeleteAccountHandler(std::shared_ptr<AccountService> service);
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override;
private:
    std::shared_ptr<AccountService> service;
    bool validateRequestToken(Poco::Net::HTTPServerRequest& req, std::shared_ptr<AccountService> service, std::string& accountId);
};

#endif // DELETE_ACCOUNT_HANDLER_H