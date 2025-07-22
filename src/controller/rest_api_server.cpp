/**
 * rest_api_server.cpp
 * REST API服务器实现
 */

#include "rest_api_server.h"
#include "base_request_handler.h"
#include "register_handler.h"
#include "login_handler.h"
#include "verify_email_handler.h"
#include "get_account_handler.h"
#include "update_account_handler.h"
#include "delete_account_handler.h"
#include "change_password_handler.h"
#include "oauth2_authorize_handler.h"
#include "not_found_handler.h"
#include "request_handler_factory.h"
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
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




































void RestApiServer::start() {
    try {
        serverSocket = Poco::Net::ServerSocket(port);
        Poco::Net::HTTPServerParams* params = new Poco::Net::HTTPServerParams();
        params->setKeepAlive(false);
        
        httpServer = std::make_unique<Poco::Net::HTTPServer>(
            new RequestHandlerFactory(service, oauth2Service),
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
