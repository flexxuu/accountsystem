#ifndef POCO_HTTP_CLIENT_H
#define POCO_HTTP_CLIENT_H

#include "http_client.h"
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/SSLManager.h>
#include <Poco/Util/Application.h>
#include <string>
#include <map>

class PocoHttpClient : public HttpClient {
public:
    PocoHttpClient();
    ~PocoHttpClient() override;

    std::string get(const std::string& url, const std::map<std::string, std::string>& headers = {}) override;
    std::string post(const std::string& url, const std::string& data, const std::map<std::string, std::string>& headers = {}) override;
    void setTimeout(int seconds) override;
    void setSSLVerification(bool enable) override;

private:
    std::string performRequest(const std::string& url, const std::string& method, const std::string& data, const std::map<std::string, std::string>& headers);
    int _timeout = 30;
    bool _sslVerification = true;
};

#endif // POCO_HTTP_CLIENT_H