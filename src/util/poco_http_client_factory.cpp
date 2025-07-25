#include "poco_http_client_factory.h"
#include "poco_http_client.h"

std::unique_ptr<HttpClient> PocoHttpClientFactory::createHttpClient() {
    return std::make_unique<PocoHttpClient>();
}

std::unique_ptr<HttpClientFactory> HttpClientFactory::createDefaultFactory() {
    return std::make_unique<PocoHttpClientFactory>();
}