#include "http_client.h"
#include "log.h"
#include <Poco/URI.h>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/SSLManager.h>
#include <Poco/Net/Context.h>
#include <Poco/Exception.h>
#include <stdexcept>
#include <sstream>
#include <memory>

// HTTP客户端实现（基于Poco）
class PocoHttpClient : public HttpClient {
public:
    PocoHttpClient() : ssl_verification_(true), timeout_seconds_(10) {
        Poco::Net::SSLManager::instance().initializeClient(
            "", "", "", Poco::Net::Context::CLIENT_USE_OS_CERTS
        );
    }

    ~PocoHttpClient() override = default;

    std::string get(const std::string& url, const std::map<std::string, std::string>& headers) override {
        return performRequest(url, "", headers, false);
    }

    std::string post(const std::string& url, const std::string& data, const std::map<std::string, std::string>& headers) override {
        return performRequest(url, data, headers, true);
    }

    void setTimeout(int seconds) override {
        timeout_seconds_ = seconds;
    }

    void setSSLVerification(bool enable) override {
        ssl_verification_ = enable;
    }

private:
    bool ssl_verification_;
    int timeout_seconds_;

    std::string performRequest(const std::string& url, const std::string& data, 
                              const std::map<std::string, std::string>& headers, bool is_post) {
        try {
            Poco::URI uri(url);
            std::string path = uri.getPathAndQuery();
            if (path.empty()) path = "/";

            std::unique_ptr<Poco::Net::HTTPClientSession> session;

            if (uri.getScheme() == "https") {
                Poco::Net::Context::Ptr context = new Poco::Net::Context(
                    Poco::Net::Context::CLIENT_USE_OS_CERTS, "", "", 
                    ssl_verification_ ? Poco::Net::Context::VERIFY_RELAXED : Poco::Net::Context::VERIFY_NONE
                );
                auto https_session = new Poco::Net::HTTPSClientSession(uri.getHost(), uri.getPort(), context);
                https_session->setTimeout(Poco::Timespan(timeout_seconds_, 0));
                session.reset(https_session);
            } else {
                session = std::make_unique<Poco::Net::HTTPClientSession>(uri.getHost(), uri.getPort());
                session->setTimeout(Poco::Timespan(timeout_seconds_, 0));
            }

            Poco::Net::HTTPRequest req(
                is_post ? Poco::Net::HTTPRequest::HTTP_POST : Poco::Net::HTTPRequest::HTTP_GET,
                path,
                Poco::Net::HTTPMessage::HTTP_1_1
            );
            req.setHost(uri.getHost());

            for (const auto& [key, value] : headers) {
                req.addField(key, value);
            }

            if (is_post) {
                req.setContentLength(data.size());
                std::ostream& os = session->sendRequest(req);
                os << data;
            } else {
                session->sendRequest(req);
            }

            Poco::Net::HTTPResponse res;
            std::istream& is = session->receiveResponse(res);

            if (res.getStatus() != Poco::Net::HTTPResponse::HTTP_OK) {
                Log::error("HTTP请求失败: {} (URL: {})", res.getReason(), url);
                throw std::runtime_error("HTTP请求失败: " + res.getReason());
            }

            std::stringstream ss;
            ss << is.rdbuf();
            return ss.str();
        } catch (const Poco::Exception& e) {
            Log::error("Poco HTTP错误: {} (URL: {})", e.displayText(), url);
            throw std::runtime_error("HTTP请求失败: " + std::string(e.what()));
        } catch (const std::exception& e) {
            Log::error("HTTP请求错误: {} (URL: {})", e.what(), url);
            throw;
        }
    }

};

std::unique_ptr<HttpClient> HttpClient::create() {
    return std::make_unique<PocoHttpClient>();
}