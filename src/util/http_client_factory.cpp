#include "http_client_factory.h"
#include "poco_http_client.h"

std::unique_ptr<HttpClientFactory> HttpClientFactory::createDefaultFactory() {
    return std::make_unique<HttpClientFactory>();
}

std::unique_ptr<HttpClient> HttpClientFactory::createClient() {
    return std::make_unique<PocoHttpClient>();
}