#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <string>
#include <map>
#include <memory>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>

#include <Poco/Net/Context.h>
#include <Poco/Util/Application.h>

class HttpClient {
  public:
      virtual ~HttpClient() = default;

    // 发送GET请求
    virtual std::string get(const std::string& url, const std::map<std::string, std::string>& headers = {}) = 0;

    // 发送POST请求
    virtual std::string post(const std::string& url, const std::string& data, const std::map<std::string, std::string>& headers = {}) = 0;

    // 设置超时时间（秒）
    virtual void setTimeout(int seconds) = 0;

    // 启用/禁用SSL验证
    virtual void setSSLVerification(bool enable) = 0;

protected:
    HttpClient() = default;
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;
};
#endif // HTTP_CLIENT_H
