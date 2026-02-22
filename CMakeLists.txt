cmake_minimum_required(VERSION 3.10)
project(kalshi-api)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${CURL_INCLUDE_DIRS})

# Add executable
add_executable(kalshi_client main.cpp kalshi_client.cpp)

# Link libraries
target_link_libraries(kalshi_client ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})

# Compiler flags
target_compile_options(kalshi_client PRIVATE -Wall -Wextra)
