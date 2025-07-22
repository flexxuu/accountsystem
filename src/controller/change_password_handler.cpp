#include "change_password_handler.h"
#include <nlohmann/json.hpp>
#include <sstream>

using json = nlohmann::json;

ChangePasswordHandler::ChangePasswordHandler(std::shared_ptr<AccountService> service) : service(service) {}

void ChangePasswordHandler::handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) {
    try {
        std::string accountId;
        if (!validateRequestToken(req, service, accountId)) {
            sendErrorResponse(res, 401, "未授权");
            return;
        }
        
        std::istream& is = req.stream();
        std::string body(std::istreambuf_iterator<char>(is), {});
        json request = json::parse(body);
        
        if (!request.contains("oldPassword") || !request.contains("newPassword")) {
            sendErrorResponse(res, 400, "缺少必要的参数");
            return;
        }
        
        std::string oldPassword = request["oldPassword"];
        std::string newPassword = request["newPassword"];
        
        bool changed = service->changePassword(accountId, oldPassword, newPassword);
        
        if (changed) {
            json response = {
                {"status", "success"},
                {"message", "密码已更改"}
            };
            sendJsonResponse(res, 200, response.dump());
        } else {
            sendErrorResponse(res, 400, "旧密码不正确");
        }
    } catch (const std::exception& e) {
        sendErrorResponse(res, 400, e.what());
    } catch (...) {
        sendErrorResponse(res, 500, "未知错误");
    }
}

bool ChangePasswordHandler::validateRequestToken(Poco::Net::HTTPServerRequest& req, std::shared_ptr<AccountService> service, std::string& accountId) {
    auto it = req.find("Authorization");
    if (it == req.end()) return false;
    
    std::string authHeader = it->second;
    if (authHeader.substr(0, 7) != "Bearer ") return false;
    
    std::string token = authHeader.substr(7);
    return service->validateToken(token, accountId);
}