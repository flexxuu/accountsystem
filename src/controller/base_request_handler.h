#ifndef BASE_REQUEST_HANDLER_H
#define BASE_REQUEST_HANDLER_H

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class BaseRequestHandler : public Poco::Net::HTTPRequestHandler {
protected:
    virtual void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) = 0;
    void sendJsonResponse(Poco::Net::HTTPServerResponse& res, int statusCode, const std::string& json);
    void sendErrorResponse(Poco::Net::HTTPServerResponse& res, int statusCode, const std::string& message);
    json parseRequestBody(Poco::Net::HTTPServerRequest& req);
};

#endif // BASE_REQUEST_HANDLER_H