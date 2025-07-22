#include "request_handler_factory.h"
#include <unordered_map>
#include <functional>
#include "register_handler.h"
#include "login_handler.h"
#include "verify_email_handler.h"
#include "get_account_handler.h"
#include "update_account_handler.h"
#include "delete_account_handler.h"
#include "oauth2_authorize_handler.h"
#include "not_found_handler.h"
#include <unordered_map>
#include <functional>

RequestHandlerFactory::RequestHandlerFactory(std::shared_ptr<AccountService> accountService, std::shared_ptr<OAuth2Service> oauth2Service)
    : accountService(accountService), oauth2Service(oauth2Service) {}

Poco::Net::HTTPRequestHandler* RequestHandlerFactory::createRequestHandler(const Poco::Net::HTTPServerRequest& req) {
    std::unordered_map<std::string, std::function<Poco::Net::HTTPRequestHandler*()>> routes;
    routes["/register"] = [this]() -> Poco::Net::HTTPRequestHandler* { return new RegisterHandler(accountService); };
    routes["/login"] = [this]() -> Poco::Net::HTTPRequestHandler* { return new LoginHandler(accountService); };
    routes["/verify-email"] = [this]() -> Poco::Net::HTTPRequestHandler* { return new VerifyEmailHandler(accountService); };
    routes["/account"] = [this]() -> Poco::Net::HTTPRequestHandler* { return new GetAccountHandler(accountService); };
    routes["/account/update"] = [this]() -> Poco::Net::HTTPRequestHandler* { return new UpdateAccountHandler(accountService); };
    routes["/account/delete"] = [this]() -> Poco::Net::HTTPRequestHandler* { return new DeleteAccountHandler(accountService); };
    routes["/oauth2/authorize"] = [this]() -> Poco::Net::HTTPRequestHandler* { return new OAuth2AuthorizeHandler(oauth2Service); };

    auto it = routes.find(req.getURI());
    if (it != routes.end()) {
        return it->second();
    }
    return new NotFoundHandler();
}