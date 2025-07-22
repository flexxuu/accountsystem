#include "update_account_handler.h"
#include <Poco/Net/HTTPRequestHandler.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

UpdateAccountHandler::UpdateAccountHandler(std::shared_ptr<AccountService> service) : service(service) {}

void UpdateAccountHandler::handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    handle(request, response);
}

void UpdateAccountHandler::handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) {
    std::string accountId;
    if (!validateRequestToken(req, service, accountId)) {
        sendErrorResponse(res, 401, "未授权");
        return;
    }
    
    auto request = parseRequestBody(req);
    std::string newUsername = request.contains("username") ? request["username"] : "";
    std::string newEmail = request.contains("email") ? request["email"] : "";
    
    bool updated = service->updateAccount(accountId, newUsername, newEmail);
    
    if (updated) {
        json response = {
            {"status", "success"},
            {"message", "账号信息已更新"}
        };
        sendJsonResponse(res, 200, response.dump());
    } else {
        sendErrorResponse(res, 404, "账号不存在");
    }
}

bool UpdateAccountHandler::validateRequestToken(Poco::Net::HTTPServerRequest& req, std::shared_ptr<AccountService> service, std::string& accountId) {
    auto it = req.find("Authorization");
    if (it == req.end()) return false;
    
    std::string authHeader = it->second;
    if (authHeader.substr(0, 7) != "Bearer ") return false;
    
    std::string token = authHeader.substr(7);
    return service->validateToken(token, accountId);
}