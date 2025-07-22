#ifndef REGISTER_HANDLER_H
#define REGISTER_HANDLER_H

#include "base_request_handler.h"
#include <Poco/Net/HTTPRequestHandler.h>
#include <memory>
#include "../service/account_service.h"

class RegisterHandler : public BaseRequestHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) override;

public:
    explicit RegisterHandler(std::shared_ptr<AccountService> service);
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override;
private:
    std::shared_ptr<AccountService> service;
};

#endif // REGISTER_HANDLER_H