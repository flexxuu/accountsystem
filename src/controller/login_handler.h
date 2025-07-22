#ifndef LOGIN_HANDLER_H
#define LOGIN_HANDLER_H

#include "base_request_handler.h"
#include <Poco/Net/HTTPRequestHandler.h>
#include <memory>
#include "../service/account_service.h"

class LoginHandler : public BaseRequestHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) override;

public:
    explicit LoginHandler(std::shared_ptr<AccountService> service);
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override;
private:
    std::shared_ptr<AccountService> service;
};

#endif // LOGIN_HANDLER_H