#include "oauth2_authorize_handler.h"
#include <Poco/Net/HTTPRequestHandler.h>

OAuth2AuthorizeHandler::OAuth2AuthorizeHandler(std::shared_ptr<OAuth2Service> oauth2Service) : oauth2Service(oauth2Service) {}

void OAuth2AuthorizeHandler::handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    handle(request, response);
}

void OAuth2AuthorizeHandler::handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) {
    // 实现OAuth2授权处理逻辑
    sendErrorResponse(res, 501, "暂未实现");
}