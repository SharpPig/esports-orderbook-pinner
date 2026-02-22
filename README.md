# Kalshi API C++ Client

A C++ implementation of the Kalshi API authentication and request functionality, equivalent to the Python example provided in the Kalshi documentation.

## Features

- RSA-PSS signing with SHA256
- Private key loading from PEM files
- HTTP requests with proper Kalshi authentication headers
- Base64 encoding for signatures
- Timestamp generation

## Dependencies

- OpenSSL (for cryptographic operations)
- libcurl (for HTTP requests)
- CMake (for building)

## Installation

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install libssl-dev libcurl4-openssl-dev cmake build-essential
```

### CentOS/RHEL
```bash
sudo yum install openssl-devel libcurl-devel cmake gcc-c++
```

### macOS
```bash
brew install openssl curl cmake
```

## Building

1. Clone or download this repository
2. Make the build script executable:
   ```bash
   chmod +x build.sh
   ```
3. Run the build script:
   ```bash
   ./build.sh
   ```

Or manually:
```bash
mkdir -p build
cd build
cmake ..
make
```

## Usage

1. Place your Kalshi private key file (e.g., `kalshi-key-2.key`) in the project directory
2. Update the `access_key` and `private_key_path` variables in `main.cpp` with your actual credentials
3. Run the executable:
   ```bash
   ./build/kalshi_client
   ```

## Example Output

The program will send a GET request to `/trade-api/v2/portfolio/balance` and display the response from the Kalshi API.

## Code Structure

- `kalshi_client.h` - Header file with class declaration
- `kalshi_client.cpp` - Implementation of the KalshiClient class
- `main.cpp` - Example usage and main function
- `CMakeLists.txt` - CMake configuration for building the project

## Key Functions

- `loadPrivateKey()` - Loads RSA private key from PEM file
- `signPSS()` - Signs text using RSA-PSS with SHA256
- `sendRequest()` - Sends authenticated HTTP requests to Kalshi API
- `getCurrentTimestamp()` - Generates current timestamp in milliseconds

## Error Handling

The implementation includes comprehensive error handling for:
- Private key loading failures
- Cryptographic operation failures
- HTTP request failures
- API error responses
