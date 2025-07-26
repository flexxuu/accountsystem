#include "poco_http_client_factory.h"
#include "poco_http_client.h"
#include "http_client_factory.h"

std::unique_ptr<HttpClient> PocoHttpClientFactory::createClient() {
    return std::make_unique<PocoHttpClient>();
}

std::unique_ptr<HttpClientFactory> HttpClientFactory::createDefaultFactory() {
    return std::make_unique<PocoHttpClientFactory>();
}