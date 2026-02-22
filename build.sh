#!/bin/bash

# Create build directory
mkdir -p build
cd build

# Configure with CMake
cmake ..

# Build the project
make

echo "Build complete. Run the executable with:"
echo "./build/kalshi_client"
