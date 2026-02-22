#include "kalshi_client.h"
#include <iostream>
#include <stdexcept>

int main() {
    try {
        // Configuration - replace with your actual values
        const std::string access_key = "7a6c9ef1-7b94-4d51-bb4f-0b9adc5d3d20";
        const std::string private_key_path = "/home/rohan/Projects/esports-orderbook-pinner/esports-orderbook-pinner.txt";
        
        // Create Kalshi client
        KalshiClient client(access_key, private_key_path);
        
        // Example request - get portfolio balance
        std::string method = "GET";
        std::string path = "/trade-api/v2/portfolio/balance";
        
        std::cout << "Sending request to Kalshi API..." << std::endl;
        std::cout << "Method: " << method << std::endl;
        std::cout << "Path: " << path << std::endl;
        std::cout << "Access Key: " << access_key << std::endl;
        std::cout << "Private Key Path: " << private_key_path << std::endl;
        std::cout << std::endl;
        
        // Send the request
        std::string response = client.sendRequest(method, path);
        
        std::cout << "Response:" << std::endl;
        std::cout << response << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
