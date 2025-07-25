#include <Poco/Net/PrivateKeyPassphraseHandler.h>
#include "poco_http_client.h"
#include "util/log.h"
#include <Poco/Net/PrivateKeyPassphraseHandler.h>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/URI.h>

#include <Poco/Net/Context.h>
#include <Poco/Exception.h>
#include <sstream>
#include <iostream>
#include "util/log.h"

PocoHttpClient::PocoHttpClient() {
    // 初始化SSL环境
    Poco::Net::SSLManager::instance().initializeClient(nullptr, nullptr, nullptr);
}

PocoHttpClient::~PocoHttpClient() {
}

std::string PocoHttpClient::get(const std::string& url, const std::map<std::string, std::string>& headers) {
    // 实现GET请求逻辑
    return performRequest(url, "GET", "", headers);
}

std::string PocoHttpClient::post(const std::string& url, const std::string& data, const std::map<std::string, std::string>& headers) {
    // 实现POST请求逻辑
    return performRequest(url, "POST", data, headers);
}

void PocoHttpClient::setTimeout(int seconds) {
    _timeout = seconds;
}

void PocoHttpClient::setSSLVerification(bool enable) {
    _sslVerification = enable;
}

// 辅助方法：执行HTTP请求
std::string PocoHttpClient::performRequest(const std::string& url, const std::string& method, const std::string& data, const std::map<std::string, std::string>& headers) {
    try {
        Poco::URI uri(url);
        Poco::Net::HTTPClientSession session(uri.getHost(), uri.getPort());
        
        std::string path(uri.getPathAndQuery());
        if (path.empty()) path = "/";

        Poco::Net::HTTPRequest request(method, path);
        
        for (const auto& header : headers) {
            request.set(header.first, header.second);
        }

        if (method == "POST") {
            request.setContentLength(data.length());
            std::ostream& requestStream = session.sendRequest(request);
            requestStream << data;
        }

        Poco::Net::HTTPResponse response;
        std::istream& responseStream = session.receiveResponse(response);
        
        std::stringstream ss;
        ss << responseStream.rdbuf();
        return ss.str();
    } catch (Poco::Exception& e) {
        util::Log::error("HTTP请求失败: {}", e.displayText());
        return "";
    }
}