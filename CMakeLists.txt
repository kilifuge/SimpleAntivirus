cmake_minimum_required(VERSION 3.10)

project(hash_analyze)

add_executable(hash_analyze 
    utils.cpp
    main.cpp
)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

target_link_libraries(hash_analyze
    OpenSSL::SSL   
    OpenSSL::Crypto
    ${CURL_LIBRARIES}
)