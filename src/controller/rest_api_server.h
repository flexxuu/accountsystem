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
    static void handleHttpEvent(struct mg_connection *c, int ev, void *ev_data, void *fn_data);
    
    // 路由处理
    static void handleRegister(struct mg_connection *c, struct mg_http_message *hm, 
                              std::shared_ptr<AccountService> service);
    static void handleVerifyEmail(struct mg_connection *c, struct mg_http_message *hm, 
                                 std::shared_ptr<AccountService> service);
    static void handleLogin(struct mg_connection *c, struct mg_http_message *hm, 
                           std::shared_ptr<AccountService> service);
    static void handleGetAccount(struct mg_connection *c, struct mg_http_message *hm, 
                                std::shared_ptr<AccountService> service);
    static void handleUpdateAccount(struct mg_connection *c, struct mg_http_message *hm, 
                                   std::shared_ptr<AccountService> service);
    static void handleChangePassword(struct mg_connection *c, struct mg_http_message *hm, 
                                    std::shared_ptr<AccountService> service);
    static void handleDeleteAccount(struct mg_connection *c, struct mg_http_message *hm, 
                                   std::shared_ptr<AccountService> service);
    
    // OAuth2处理方法
    static void handleOAuth2Authorize(struct mg_connection *c, struct mg_http_message *hm, 
                                     std::shared_ptr<OAuth2Service> oauth2Service);
    static void handleOAuth2Callback(struct mg_connection *c, struct mg_http_message *hm, 
                                    std::shared_ptr<OAuth2Service> oauth2Service);
    
    // 辅助方法
    static void sendJsonResponse(struct mg_connection *c, int statusCode, const std::string& json);
    static void sendErrorResponse(struct mg_connection *c, int statusCode, const std::string& message);
    static bool validateRequestToken(struct mg_http_message *hm, std::shared_ptr<AccountService> service, 
                                    std::string& accountId);
};

#endif // REST_API_SERVER_H