/**
 * rest_api_server.h
 * REST API服务器
 */
#ifndef REST_API_SERVER_H
#define REST_API_SERVER_H

#include <memory>
#include <string>
#include <Poco/Net/HTTPServer.h>
#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Net/HTTPServerParams.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Util/ServerApplication.h>
#include "../service/account_service.h"
#include "../service/oauth2_service.h"

class RestApiServer {
public:
    RestApiServer(std::shared_ptr<AccountService> service, std::shared_ptr<OAuth2Service> oauth2Service, int port);
    ~RestApiServer();
    
    // 启动服务器
    void start();
    
    // 停止服务器
    void stop();
    
private:
    std::shared_ptr<AccountService> service;
    std::shared_ptr<OAuth2Service> oauth2Service;
    int port;
    std::unique_ptr<Poco::Net::HTTPServer> httpServer;
    Poco::Net::ServerSocket serverSocket;
    bool running;
    
    // HTTP请求处理
    // 路由处理
    static void handleRegister(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res, 
                              std::shared_ptr<AccountService> service);
    void handleVerifyEmail(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res, 
                                 std::shared_ptr<AccountService> service);
    void handleLogin(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res, 
                           std::shared_ptr<AccountService> service);
    void handleGetAccount(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res, 
                                std::shared_ptr<AccountService> service);
    void handleUpdateAccount(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res, 
                                   std::shared_ptr<AccountService> service);
    void handleChangePassword(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res, 
                                    std::shared_ptr<AccountService> service);
    void handleDeleteAccount(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res, 
                                   std::shared_ptr<AccountService> service);
    
    // OAuth2处理方法
    void handleOAuth2Authorize(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res, 
                                     std::shared_ptr<OAuth2Service> oauth2Service);
    void handleOAuth2Callback(Poco::Net::HTTPServerRequest& req, Poco::Net::HTTPServerResponse& res, 
                                    std::shared_ptr<OAuth2Service> oauth2Service);
    
    // 辅助方法
    void sendJsonResponse(Poco::Net::HTTPServerResponse& res, int statusCode, const std::string& json);
    void sendErrorResponse(Poco::Net::HTTPServerResponse& res, int statusCode, const std::string& message);
    bool validateRequestToken(Poco::Net::HTTPServerRequest& req, std::shared_ptr<AccountService> service,
                                      std::string& accountId);
    
public:
    // 获取OAuth2服务
    std::shared_ptr<OAuth2Service> getOAuth2Service() { return oauth2Service; }
    
    // 获取账号服务
    std::shared_ptr<AccountService> getAccountService() { return service; }
};

#endif // REST_API_SERVER_H