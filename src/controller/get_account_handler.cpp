#include "get_account_handler.h"
#include <Poco/Net/HTTPRequestHandler.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <ctime>

using json = nlohmann::json;

GetAccountHandler::GetAccountHandler(std::shared_ptr<AccountService> service) : service(service) {}

void GetAccountHandler::handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    handle(request, response);
}

void GetAccountHandler::handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) {
    std::string accountId;
    if (!validateRequestToken(req, service, accountId)) {
        sendErrorResponse(res, 401, "未授权");
        return;
    }
    
    auto account = service->getAccountById(accountId);
    if (!account) {
        sendErrorResponse(res, 404, "账号不存在");
        return;
    }
    
    json response = {
        {"status", "success"},
        {"account", {
            {"id", account->getId()},
            {"username", account->getUsername()},
            {"email", account->getEmail()},
            {"active", account->isActive()},
            {"createdAt", std::chrono::system_clock::to_time_t(account->getCreatedAt())}
        }}
    };
    
    sendJsonResponse(res, 200, response.dump());
}

bool GetAccountHandler::validateRequestToken(Poco::Net::HTTPServerRequest& req, std::shared_ptr<AccountService> service, std::string& accountId) {
    auto it = req.find("Authorization");
    if (it == req.end()) return false;
    
    std::string authHeader = it->second;
    if (authHeader.substr(0, 7) != "Bearer ") return false;
    
    std::string token = authHeader.substr(7);
    return service->validateToken(token, accountId);
}