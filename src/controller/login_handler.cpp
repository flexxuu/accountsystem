#include "login_handler.h"
#include <Poco/Net/HTTPRequestHandler.h>
#include <nlohmann/json.hpp>
#include "util/log.h"

using json = nlohmann::json;

LoginHandler::LoginHandler(std::shared_ptr<AccountService> service) : service(service) {}

void LoginHandler::handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    handle(request, response);
}

void LoginHandler::handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) {
    Log::info("收到登录请求");
    auto request = parseRequestBody(req);
    
    if (!request.contains("usernameOrEmail") || !request.contains("password")) {
        sendErrorResponse(res, 400, "缺少必要的参数");
        return;
    }
    
    std::string usernameOrEmail = request["usernameOrEmail"];
    std::string password = request["password"];
    
    std::string token = service->login(usernameOrEmail, password);
    
    json response = {
        {"status", "success"},
        {"message", "登录成功"},
        {"token", token}
    };
    
    sendJsonResponse(res, 200, response.dump());
}