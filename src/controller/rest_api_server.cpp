/**
 * rest_api_server.cpp
 * REST API服务器实现
 */
#include "rest_api_server.h"
#include <iostream>
#include <memory>
#include <string>
#include <nlohmann/json.hpp>
#include "util/log.h"
#include "util/security_utils.h"
#include "util/config_utils.h"

using json = nlohmann::json;

RestApiServer::RestApiServer(std::shared_ptr<AccountService> service, std::shared_ptr<OAuth2Service> oauth2Service, int port)
    : service(service), oauth2Service(oauth2Service), port(port), running(false) {}

RestApiServer::~RestApiServer() {
    if (running) {
        stop();
    }
}

class RequestHandlerFactory : public Poco::Net::HTTPRequestHandlerFactory {
public:
    RequestHandlerFactory(RestApiServer* server) : server(server) {}
    
    Poco::Net::HTTPRequestHandler* createRequestHandler(const Poco::Net::HTTPServerRequest& request) override {
        const std::string& uri = request.getURI();
        
        if (uri == "/api/register") return new RegisterHandler(server->service);
        else if (uri == "/api/verify-email") return new VerifyEmailHandler(server->service);
        else if (uri == "/api/login") return new LoginHandler(server->service);
        else if (uri == "/api/account") return new GetAccountHandler(server->service);
        else if (uri == "/api/account/update") return new UpdateAccountHandler(server->service);
        else if (uri == "/api/account/password") return new ChangePasswordHandler(server->service);
        else if (uri == "/api/account/delete") return new DeleteAccountHandler(server->service);
        else if (uri.find("/api/oauth2/") != std::string::npos && uri.find("/authorize") != std::string::npos) 
            return new OAuth2AuthorizeHandler(server->oauth2Service);
        else if (uri.find("/api/oauth2/") != std::string::npos && uri.find("/callback") != std::string::npos) 
            return new OAuth2CallbackHandler(server->oauth2Service);
        
        return new NotFoundHandler();
    }
private:
    RestApiServer* server;
};

void RestApiServer::start() {
    try {
        serverSocket = Poco::Net::ServerSocket(port);
        Poco::Net::HTTPServerParams* params = new Poco::Net::HTTPServerParams();
        params->setKeepAlive(false);
        
        httpServer = std::make_unique<Poco::Net::HTTPServer>(
            new RequestHandlerFactory(this),
            serverSocket,
            params
        );
        
        httpServer->start();
        running = true;
        std::cout << "服务器已启动，监听端口 " << port << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "启动服务器失败: " << e.what() << std::endl;
        throw;
    }
}

void RestApiServer::stop() {
    if (httpServer && running) {
        std::cout << "正在停止服务器..." << std::endl;
        httpServer->stop();
        running = false;
        std::cout << "服务器已停止" << std::endl;
    }
}

// Poco请求处理器基类
class BaseRequestHandler : public Poco::Net::HTTPRequestHandler {
public:
    void handleRequest(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override {
        res.setChunkedTransferEncoding(false);
        res.setContentType("application/json");
        try {
            handle(req, res);
        } catch (const std::exception& e) {
            sendErrorResponse(res, 500, e.what());
        } catch (...) {
            sendErrorResponse(res, 500, "未知错误");
        }
    }
protected:
    virtual void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) = 0;
    
    void sendJsonResponse(Poco::Net::HTTPServerResponse& res, int statusCode, const std::string& json) {
        res.setStatus(static_cast<Poco::Net::HTTPResponse::HTTPStatus>(statusCode));
        std::ostream& out = res.send();
        out << json;
        out.flush();
    }
    
    void sendErrorResponse(Poco::Net::HTTPServerResponse& res, int statusCode, const std::string& message) {
        nlohmann::json error = {
            {"status", "error"},
            {"message", message}
        };
        sendJsonResponse(res, statusCode, error.dump());
    }
    
    nlohmann::json parseRequestBody(Poco::Net::HTTPServerRequest& req) {
        std::istream& is = req.stream();
        return nlohmann::json::parse(is);
    }
};

// 注册请求处理器
class RegisterHandler : public BaseRequestHandler {
public:
    RegisterHandler(std::shared_ptr<AccountService> service) : service(service) {}
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override {
        Log::info("收到注册请求");
        auto request = parseRequestBody(req);
        
        if (!request.contains("username") || !request.contains("password") || !request.contains("email")) {
            sendErrorResponse(res, 400, "缺少必要的参数");
            return;
        }
        
        std::string username = request["username"];
        std::string password = request["password"];
        std::string email = request["email"];
        
        std::string accountId = service->createAccount(username, password, email);
        Log::info("账号创建成功: username={}, email={}, accountId={}", username, email, accountId);
        
        nlohmann::json response = {
            {"status", "success"},
            {"message", "账号创建成功，请检查邮箱进行验证"},
            {"accountId", accountId}
        };
        
        sendJsonResponse(res, 201, response.dump());
    }
private:
    std::shared_ptr<AccountService> service;
};

// 404处理器
class NotFoundHandler : public BaseRequestHandler {
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override {
        sendErrorResponse(res, 404, "未找到API端点");
    }
};

// 其他处理器实现将在后续步骤中添加...

// 邮箱验证请求处理器
class VerifyEmailHandler : public BaseRequestHandler {
public:
    VerifyEmailHandler(std::shared_ptr<AccountService> service) : service(service) {}
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override {
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
            nlohmann::json response = {
                {"status", "success"},
                {"message", "邮箱验证成功"}
            };
            sendJsonResponse(res, 200, response.dump());
        } else {
            sendErrorResponse(res, 400, "无效的验证码");
        }
    }
private:
    std::shared_ptr<AccountService> service;
};

// 登录请求处理器
class LoginHandler : public BaseRequestHandler {
public:
    LoginHandler(std::shared_ptr<AccountService> service) : service(service) {}
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override {
        Log::info("收到登录请求");
        auto request = parseRequestBody(req);
        
        if (!request.contains("usernameOrEmail") || !request.contains("password")) {
            sendErrorResponse(res, 400, "缺少必要的参数");
            return;
        }
        
        std::string usernameOrEmail = request["usernameOrEmail"];
        std::string password = request["password"];
        
        std::string token = service->login(usernameOrEmail, password);
        
        nlohmann::json response = {
            {"status", "success"},
            {"message", "登录成功"},
            {"token", token}
        };
        
        sendJsonResponse(res, 200, response.dump());
    }
private:
    std::shared_ptr<AccountService> service;
};

// 获取账号信息请求处理器
class GetAccountHandler : public BaseRequestHandler {
public:
    GetAccountHandler(std::shared_ptr<AccountService> service) : service(service) {}
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override {
        std::string accountId;
        if (!validateRequestToken(req, accountId)) {
            sendErrorResponse(res, 401, "未授权");
            return;
        }
        
        auto account = service->getAccountById(accountId);
        if (!account) {
            sendErrorResponse(res, 404, "账号不存在");
            return;
        }
        
        nlohmann::json response = {
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
private:
    std::shared_ptr<AccountService> service;
    
    bool validateRequestToken(Poco::Net::HTTPServerRequest& req, std::string& accountId) {
        auto it = req.find("Authorization");
        if (it == req.end()) return false;
        
        std::string authHeader = it->second;
        if (authHeader.substr(0, 7) != "Bearer ") return false;
        
        std::string token = authHeader.substr(7);
        return service->validateToken(token, accountId);
    }
};

// 更新账号信息请求处理器
class UpdateAccountHandler : public BaseRequestHandler {
public:
    UpdateAccountHandler(std::shared_ptr<AccountService> service) : service(service) {}
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override {
        std::string accountId;
        if (!validateRequestToken(req, accountId)) {
            sendErrorResponse(res, 401, "未授权");
            return;
        }
        
        auto request = parseRequestBody(req);
        std::string newUsername = request.contains("username") ? request["username"] : "";
        std::string newEmail = request.contains("email") ? request["email"] : "";
        
        bool updated = service->updateAccount(accountId, newUsername, newEmail);
        
        if (updated) {
            nlohmann::json response = {
                {"status", "success"},
                {"message", "账号信息已更新"}
            };
            sendJsonResponse(res, 200, response.dump());
        } else {
            sendErrorResponse(res, 404, "账号不存在");
        }
    }
private:
    std::shared_ptr<AccountService> service;
    
    bool validateRequestToken(Poco::Net::HTTPServerRequest& req, std::string& accountId) {
        auto it = req.find("Authorization");
        if (it == req.end()) return false;
        
        std::string authHeader = it->second;
        if (authHeader.substr(0, 7) != "Bearer ") return false;
        
        std::string token = authHeader.substr(7);
        return service->validateToken(token, accountId);
    }
};

// 修改密码请求处理器
class ChangePasswordHandler : public BaseRequestHandler {
public:
    ChangePasswordHandler(std::shared_ptr<AccountService> service) : service(service) {}
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override {
        std::string accountId;
        if (!validateRequestToken(req, accountId)) {
            sendErrorResponse(res, 401, "未授权");
            return;
        }
        
        auto request = parseRequestBody(req);
        if (!request.contains("oldPassword") || !request.contains("newPassword")) {
            sendErrorResponse(res, 400, "缺少必要的参数");
            return;
        }
        
        std::string oldPassword = request["oldPassword"];
        std::string newPassword = request["newPassword"];
        
        bool changed = service->changePassword(accountId, oldPassword, newPassword);
        
        if (changed) {
            nlohmann::json response = {
                {"status", "success"},
                {"message", "密码已更改"}
            };
            sendJsonResponse(res, 200, response.dump());
        } else {
            sendErrorResponse(res, 400, "旧密码不正确");
        }
    }
private:
    std::shared_ptr<AccountService> service;
    
    bool validateRequestToken(Poco::Net::HTTPServerRequest& req, std::string& accountId) {
        auto it = req.find("Authorization");
        if (it == req.end()) return false;
        
        std::string authHeader = it->second;
        if (authHeader.substr(0, 7) != "Bearer ") return false;
        
        std::string token = authHeader.substr(7);
        return service->validateToken(token, accountId);
    }
};

void RestApiServer::handleUpdateAccount(struct mg_connection *c, struct mg_http_message *hm, 
                                      std::shared_ptr<AccountService> service) {
    try {
        // 验证token
        std::string accountId;
        if (!validateRequestToken(hm, service, accountId)) {
            sendErrorResponse(c, 401, "未授权");
            return;
        }
        
        // 解析请求JSON
        std::string body(hm->body.ptr, hm->body.len);
        json request = json::parse(body);
        
        // 获取更新参数
        std::string newUsername = request.contains("username") ? request["username"].get<std::string>() : "";
        std::string newEmail = request.contains("email") ? request["email"].get<std::string>() : "";
        
        // 更新账号
        bool updated = service->updateAccount(accountId, newUsername, newEmail);
        
        if (updated) {
            json response = {
                {"status", "success"},
                {"message", "账号信息已更新"}
            };
            sendJsonResponse(c, 200, response.dump());
        } else {
            sendErrorResponse(c, 404, "账号不存在");
        }
    } catch (const std::exception& e) {
        sendErrorResponse(c, 400, e.what());
    } catch (...) {
        sendErrorResponse(c, 500, "未知错误");
    }
}

void RestApiServer::handleChangePassword(struct mg_connection *c, struct mg_http_message *hm, 
                                       std::shared_ptr<AccountService> service) {
    try {
        // 验证token
        std::string accountId;
        if (!validateRequestToken(hm, service, accountId)) {
            sendErrorResponse(c, 401, "未授权");
            return;
        }
        
        // 解析请求JSON
        std::string body(hm->body.ptr, hm->body.len);
        json request = json::parse(body);
        
        // 验证请求参数
        if (!request.contains("oldPassword") || !request.contains("newPassword")) {
            sendErrorResponse(c, 400, "缺少必要的参数");
            return;
        }
        
        std::string oldPassword = request["oldPassword"].get<std::string>();
        std::string newPassword = request["newPassword"].get<std::string>();
        
        // 更改密码
        bool changed = service->changePassword(accountId, oldPassword, newPassword);
        
        if (changed) {
            json response = {
                {"status", "success"},
                {"message", "密码已更改"}
            };
            sendJsonResponse(c, 200, response.dump());
        } else {
            sendErrorResponse(c, 400, "旧密码不正确");
        }
    } catch (const std::exception& e) {
        sendErrorResponse(c, 400, e.what());
    } catch (...) {
        sendErrorResponse(c, 500, "未知错误");
    }
}

// 删除账号请求处理器
class DeleteAccountHandler : public BaseRequestHandler {
public:
    DeleteAccountHandler(std::shared_ptr<AccountService> service) : service(service) {}
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override {
        std::string accountId;
        if (!validateRequestToken(req, accountId)) {
            sendErrorResponse(res, 401, "未授权");
            return;
        }
        
        bool deleted = service->deleteAccount(accountId);
        
        if (deleted) {
            nlohmann::json response = {
                {"status", "success"},
                {"message", "账号已删除"}
            };
            sendJsonResponse(res, 200, response.dump());
        } else {
            sendErrorResponse(res, 404, "账号不存在");
        }
    }
private:
    std::shared_ptr<AccountService> service;
    
    bool validateRequestToken(Poco::Net::HTTPServerRequest& req, std::string& accountId) {
        auto it = req.find("Authorization");
        if (it == req.end()) return false;
        
        std::string authHeader = it->second;
        if (authHeader.substr(0, 7) != "Bearer ") return false;
        
        std::string token = authHeader.substr(7);
        return service->validateToken(token, accountId);
    }
};

// OAuth2授权请求处理器
class OAuth2AuthorizeHandler : public BaseRequestHandler {
public:
    OAuth2AuthorizeHandler(std::shared_ptr<OAuth2Service> oauth2Service) : oauth2Service(oauth2Service) {}
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override {
        Log::info("OAuth2授权请求");
        
        const std::string& uri = req.getURI();
        size_t providerStart = uri.find("/oauth2/") + 8;
        size_t providerEnd = uri.find("/authorize", providerStart);
        
        if (providerEnd == std::string::npos) {
            sendErrorResponse(res, 400, "无效的请求路径");
            return;
        }
        
        std::string provider = uri.substr(providerStart, providerEnd - providerStart);
        std::string state = SecurityUtils::generateRandomString(32);
        std::string redirectUri = ConfigUtils::getServerConfig().base_url + "/api/oauth2/" + provider + "/callback";
        
        std::string authUrl = oauth2Service->getAuthorizationUrl(provider, redirectUri, state);
        
        if (authUrl.empty()) {
            sendErrorResponse(res, 400, "不支持的OAuth2提供商");
            return;
        }
        
        res.setStatus(Poco::Net::HTTPResponse::HTTPStatus::HTTP_FOUND);
        res.add("Location", authUrl);
        res.send().flush();
    }
private:
    std::shared_ptr<OAuth2Service> oauth2Service;
};

// OAuth2回调请求处理器
class OAuth2CallbackHandler : public BaseRequestHandler {
public:
    OAuth2CallbackHandler(std::shared_ptr<OAuth2Service> oauth2Service) : oauth2Service(oauth2Service) {}
protected:
    void handle(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res) override {
        Log::info("OAuth2回调请求");
        
        const std::string& uri = req.getURI();
        size_t providerStart = uri.find("/oauth2/") + 8;
        size_t providerEnd = uri.find("/callback", providerStart);
        
        if (providerEnd == std::string::npos) {
            sendErrorResponse(res, 400, "无效的请求路径");
            return;
        }
        
        std::string provider = uri.substr(providerStart, providerEnd - providerStart);
        std::string code = req.get("code", "");
        std::string state = req.get("state", "");
        
        if (code.empty()) {
            sendErrorResponse(res, 400, "缺少授权码");
            return;
        }
        
        OAuth2AuthResult result = oauth2Service->authenticate(provider, code, state);
        
        if (!result.success) {
            sendErrorResponse(res, 401, result.error_message);
            return;
        }
        
        std::string accessToken = SecurityUtils::generateJwtToken(result.account_id);
        std::string refreshToken = SecurityUtils::generateRefreshToken(result.account_id);
        
        nlohmann::json response = {
            {"status", "success"},
            {"access_token", accessToken},
            {"refresh_token", refreshToken},
            {"token_type", "Bearer"},
            {"expires_in", ConfigUtils::getJwtConfig().expiration_seconds}
        };
        
        sendJsonResponse(res, 200, response.dump());
    }
private:
    std::shared_ptr<OAuth2Service> oauth2Service;
};