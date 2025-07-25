#include "register_handler.h"
#include <Poco/Net/HTTPRequestHandler.h>
#include <nlohmann/json.hpp>
#include "util/log.h"
using namespace util;
using namespace util;

using json = nlohmann::json;

RegisterHandler::RegisterHandler(std::shared_ptr<AccountService> service) : service(service) {}

void RegisterHandler::handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    handle(request, response);
}

void RegisterHandler::handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) {
    Log::info("收到注册请求");
    json request;
    try {
        request = parseRequestBody(req);
    } catch (const json::parse_error& e) {
        sendErrorResponse(res, 400, "无效的JSON格式: " + std::string(e.what()));
        return;
    } catch (...) {
        sendErrorResponse(res, 400, "请求体解析失败");
        return;
    }

    if (!request.contains("username") || !request.contains("password") || !request.contains("email")) {
        sendErrorResponse(res, 400, "缺少必要的参数");
        return;
    }

    std::string username = request["username"];
    std::string password = request["password"];
    std::string email = request["email"];

    std::string accountId = service->createAccount(username, password, email);
    Log::info("账号创建成功: username={}, email={}, accountId={}", username, email, accountId);

    json response = {
        {"status", "success"},
        {"message", "账号创建成功，请检查邮箱进行验证"},
        {"accountId", accountId}
    };

    sendJsonResponse(res, 201, response.dump());
}