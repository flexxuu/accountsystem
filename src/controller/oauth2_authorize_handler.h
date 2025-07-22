#ifndef OAUTH2_AUTHORIZE_HANDLER_H
#define OAUTH2_AUTHORIZE_HANDLER_H

#include "base_request_handler.h"
#include <memory>
#include "../service/oauth2_service.h"

class OAuth2AuthorizeHandler : public BaseRequestHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) override;
public:
    explicit OAuth2AuthorizeHandler(std::shared_ptr<OAuth2Service> oauth2Service);
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override;
private:
    std::shared_ptr<OAuth2Service> oauth2Service;
};

#endif // OAUTH2_AUTHORIZE_HANDLER_H