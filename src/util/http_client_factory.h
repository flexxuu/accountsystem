#ifndef HTTP_CLIENT_FACTORY_H
#define HTTP_CLIENT_FACTORY_H

#include <memory>
#include "http_client.h"


// HTTP客户端工厂接口
class HttpClientFactory {
public:
    virtual ~HttpClientFactory() = default;
    virtual std::unique_ptr<HttpClient> createClient() = 0;
    static std::unique_ptr<HttpClientFactory> createDefaultFactory();
};
#endif // HTTP_CLIENT_FACTORY_H
