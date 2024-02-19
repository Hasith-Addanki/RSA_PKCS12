cmake_minimum_required(VERSION 3.27.2)
project(openss1)

set(CMAKE_CXX_STANDARD 17)  # Use C++17 for modern features

set(OPENSSL_INCLUDE_DIR "C:/Program Files/OpenSSL-Win64/include")
set(OPENSSL_LIBRARIES "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MT/libcrypto.lib")

# Find OpenSSL libraries (adjust paths as needed)
include_directories(${OPENSSL_INCLUDE_DIR})
link_libraries(${OPENSSL_LIBRARIES})

add_executable(openssl1 openssl1.cpp)  # Replace with your file names
