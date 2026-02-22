#ifndef KALSHI_CLIENT_H
#define KALSHI_CLIENT_H

#include <string>
#include <memory>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <curl/curl.h>

class KalshiClient {
public:
    KalshiClient(const std::string& access_key, const std::string& private_key_path);
    ~KalshiClient();

    // Load private key from PEM file
    bool loadPrivateKey(const std::string& key_path);

    // Sign text using RSA-PSS with SHA256
    std::string signPSS(const std::string& text);

    // Send authenticated request to Kalshi API
    std::string sendRequest(const std::string& method, const std::string& path, const std::string& base_url = "https://demo-api.kalshi.co");

    // Get current timestamp in milliseconds
    static long long getCurrentTimestamp();

private:
    std::string access_key_;
    EVP_PKEY* private_key_;
    CURL* curl_;
    
    // Callback function for writing response data
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response);
    
    // Helper function to base64 encode
    std::string base64Encode(const unsigned char* data, size_t length);
};

#endif // KALSHI_CLIENT_H
