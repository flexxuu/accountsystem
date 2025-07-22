#include "base_request_handler.h"
#include <Poco/Net/HTTPServerResponse.h>
#include <nlohmann/json.hpp>
#include <sstream>

using json = nlohmann::json;

void BaseRequestHandler::sendJsonResponse(Poco::Net::HTTPServerResponse& res, int statusCode, const std::string& json) {
    res.setStatus(static_cast<Poco::Net::HTTPResponse::HTTPStatus>(statusCode));
    res.setContentType("application/json");
    std::ostream& out = res.send();
    out << json;
    out.flush();
}

void BaseRequestHandler::sendErrorResponse(Poco::Net::HTTPServerResponse& res, int statusCode, const std::string& message) {
    res.setStatus(static_cast<Poco::Net::HTTPResponse::HTTPStatus>(statusCode));
    res.setContentType("application/json");
    json error = {
        {"status", "error"},
        {"message", message}
    };
    std::ostream& out = res.send();
    out << error.dump();
    out.flush();
}

json BaseRequestHandler::parseRequestBody(Poco::Net::HTTPServerRequest& req) {
    std::istream& is = req.stream();
    return json::parse(is);
}