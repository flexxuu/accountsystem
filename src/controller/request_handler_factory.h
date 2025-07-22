#ifndef REQUEST_HANDLER_FACTORY_H
#define REQUEST_HANDLER_FACTORY_H

#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <memory>
#include "../service/account_service.h"
#include "../service/oauth2_service.h"

class RequestHandlerFactory : public Poco::Net::HTTPRequestHandlerFactory {
public:
    RequestHandlerFactory(std::shared_ptr<AccountService> accountService, std::shared_ptr<OAuth2Service> oauth2Service);
    Poco::Net::HTTPRequestHandler* createRequestHandler(const Poco::Net::HTTPServerRequest& req) override;
private:
    std::shared_ptr<AccountService> accountService;
    std::shared_ptr<OAuth2Service> oauth2Service;
};

#endif // REQUEST_HANDLER_FACTORY_H