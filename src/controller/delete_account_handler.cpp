#include "delete_account_handler.h"
#include <Poco/Net/HTTPRequestHandler.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

DeleteAccountHandler::DeleteAccountHandler(std::shared_ptr<AccountService> service) : service(service) {}

void DeleteAccountHandler::handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    handle(request, response);
}

void DeleteAccountHandler::handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) {
    std::string accountId;
    if (!validateRequestToken(req, service, accountId)) {
        sendErrorResponse(res, 401, "未授权");
        return;
    }
    
    bool deleted = service->deleteAccount(accountId);
    
    if (deleted) {
        json response = {
            {"status", "success"},
            {"message", "账号已删除"}
        };
        sendJsonResponse(res, 200, response.dump());
    } else {
        sendErrorResponse(res, 404, "账号不存在");
    }
}

bool DeleteAccountHandler::validateRequestToken(Poco::Net::HTTPServerRequest& req, std::shared_ptr<AccountService> service, std::string& accountId) {
    auto it = req.find("Authorization");
    if (it == req.end()) return false;
    
    std::string authHeader = it->second;
    if (authHeader.substr(0, 7) != "Bearer ") return false;
    
    std::string token = authHeader.substr(7);
    return service->validateToken(token, accountId);
}