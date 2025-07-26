#ifndef POCO_HTTP_CLIENT_FACTORY_H
#define POCO_HTTP_CLIENT_FACTORY_H

#include "http_client_factory.h"
#include "http_client.h"

class PocoHttpClientFactory : public HttpClientFactory {
public:
    std::unique_ptr<HttpClient> createClient() override;
};

#endif // POCO_HTTP_CLIENT_FACTORY_H