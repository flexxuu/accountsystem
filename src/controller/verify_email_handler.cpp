#include "verify_email_handler.h"
#include <Poco/Net/HTTPRequestHandler.h>
#include <nlohmann/json.hpp>
#include "util/log.h"

using json = nlohmann::json;

VerifyEmailHandler::VerifyEmailHandler(std::shared_ptr<AccountService> service) : service(service) {}

void VerifyEmailHandler::handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    handle(request, response);
}

void VerifyEmailHandler::handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) {
    Log::info("收到邮箱验证请求");
    auto request = parseRequestBody(req);
    
    if (!request.contains("email") || !request.contains("code")) {
        sendErrorResponse(res, 400, "缺少必要的参数");
        return;
    }
    
    std::string email = request["email"];
    std::string code = request["code"];
    
    bool verified = service->verifyEmail(email, code);
    
    if (verified) {
        json response = {
            {"status", "success"},
            {"message", "邮箱验证成功"}
        };
        sendJsonResponse(res, 200, response.dump());
    } else {
        sendErrorResponse(res, 400, "无效的验证码");
    }
}