#include "kalshi_client.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

KalshiClient::KalshiClient(const std::string& access_key, const std::string& private_key_path)
    : access_key_(access_key), private_key_(nullptr), curl_(nullptr) {
    
    // Initialize curl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_ = curl_easy_init();
    
    // Load private key
    if (!loadPrivateKey(private_key_path)) {
        throw std::runtime_error("Failed to load private key");
    }
}

KalshiClient::~KalshiClient() {
    if (private_key_) {
        EVP_PKEY_free(private_key_);
    }
    if (curl_) {
        curl_easy_cleanup(curl_);
    }
    curl_global_cleanup();
}

bool KalshiClient::loadPrivateKey(const std::string& key_path) {
    FILE* key_file = fopen(key_path.c_str(), "rb");
    if (!key_file) {
        return false;
    }

    private_key_ = PEM_read_PrivateKey(key_file, nullptr, nullptr, nullptr);
    fclose(key_file);

    return private_key_ != nullptr;
}

std::string KalshiClient::signPSS(const std::string& text) {
    if (!private_key_) {
        throw std::runtime_error("Private key not loaded");
    }

    // Create PKEY context
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(private_key_, nullptr);
    if (!pkey_ctx) {
        throw std::runtime_error("Failed to create PKEY context");
    }

    // Initialize for signing
    if (EVP_PKEY_sign_init(pkey_ctx) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        throw std::runtime_error("Failed to initialize signing");
    }

    // Set PSS parameters
    if (EVP_PKEY_CTX_set_signature_md(pkey_ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        throw std::runtime_error("Failed to set PSS parameters");
    }

    // Create message digest
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(text.c_str()), text.length(), hash);

    // Get signature length
    size_t sig_len;
    if (EVP_PKEY_sign(pkey_ctx, nullptr, &sig_len, hash, SHA256_DIGEST_LENGTH) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        throw std::runtime_error("Failed to get signature length");
    }

    // Create signature buffer
    std::vector<unsigned char> signature(sig_len);
    if (EVP_PKEY_sign(pkey_ctx, signature.data(), &sig_len, hash, SHA256_DIGEST_LENGTH) <= 0) {
        EVP_PKEY_CTX_free(pkey_ctx);
        throw std::runtime_error("Failed to create signature");
    }

    EVP_PKEY_CTX_free(pkey_ctx);

    // Base64 encode the signature
    return base64Encode(signature.data(), sig_len);
}

std::string KalshiClient::base64Encode(const unsigned char* data, size_t length) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, length);
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return result;
}

long long KalshiClient::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
    return millis.count();
}

std::string KalshiClient::sendRequest(const std::string& method, const std::string& path, const std::string& base_url) {
    if (!curl_) {
        throw std::runtime_error("CURL not initialized");
    }

    // Get current timestamp
    long long timestamp = getCurrentTimestamp();
    std::string timestamp_str = std::to_string(timestamp);

    // Strip query parameters from path before signing
    std::string path_without_query = path;
    size_t query_pos = path.find('?');
    if (query_pos != std::string::npos) {
        path_without_query = path.substr(0, query_pos);
    }

    // Create message string to sign
    std::string msg_string = timestamp_str + method + path_without_query;

    // Sign the message
    std::string signature = signPSS(msg_string);

    // Build URL
    std::string url = base_url + path;

    // Set up headers
    struct curl_slist* headers = nullptr;
    std::string access_key_header = "KALSHI-ACCESS-KEY: " + access_key_;
    std::string signature_header = "KALSHI-ACCESS-SIGNATURE: " + signature;
    std::string timestamp_header = "KALSHI-ACCESS-TIMESTAMP: " + timestamp_str;

    headers = curl_slist_append(headers, access_key_header.c_str());
    headers = curl_slist_append(headers, signature_header.c_str());
    headers = curl_slist_append(headers, timestamp_header.c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");

    // Set CURL options
    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);

    std::string response;
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);

    // Set method
    if (method == "GET") {
        curl_easy_setopt(curl_, CURLOPT_HTTPGET, 1L);
    } else if (method == "POST") {
        curl_easy_setopt(curl_, CURLOPT_POST, 1L);
    } else if (method == "PUT") {
        curl_easy_setopt(curl_, CURLOPT_CUSTOMREQUEST, "PUT");
    } else if (method == "DELETE") {
        curl_easy_setopt(curl_, CURLOPT_CUSTOMREQUEST, "DELETE");
    }

    // Perform request
    CURLcode res = curl_easy_perform(curl_);

    // Clean up headers
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
    }

    // Check HTTP response code
    long response_code;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &response_code);

    if (response_code >= 400) {
        throw std::runtime_error("HTTP error: " + std::to_string(response_code) + " - " + response);
    }

    return response;
}

size_t KalshiClient::WriteCallback(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t total_size = size * nmemb;
    response->append((char*)contents, total_size);
    return total_size;
}
