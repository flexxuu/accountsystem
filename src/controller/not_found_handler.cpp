#include "not_found_handler.h"
#include <Poco/Net/HTTPServerResponse.h>

void NotFoundHandler::handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    handle(request, response);
}

void NotFoundHandler::handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) {
    sendErrorResponse(res, 404, "未找到API端点");
}