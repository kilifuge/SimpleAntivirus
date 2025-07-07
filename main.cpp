#include "hash_analyze.hpp"

int main(int argc, char** argv) {
    std::string auth_key{""};

    if (argc <= 1) { 
        std::cout << "./hash_analyzer <path to file> <Auth-Key>" << std::endl;
        return 1;
    }
    if (argc > 3) {
        std::cout << "Too many arguments" << std::endl;
        return 1;
    }
   
    std::string hash{};
    try {
        hash = calc_sha256(argv[1]);
    } catch (std::runtime_error ex) {
        std::cout << ex.what() << std::endl;
        return 1;
    }

    CURLcode res;
    res = curl_global_init(CURL_GLOBAL_ALL);
    if (res != CURLE_OK) {
        std::cerr << "curl_global_init() failed: " << curl_easy_strerror(res) << std::endl;
        return 1;
    }

    if (argc == 2) {
        if (auth_key.empty())
            std::cout << "Auth-Key Empty" << std::endl;
        else
            check_hash(&res, hash, auth_key);
    } else {
        check_hash(&res, hash, argv[2]);
    }

    curl_global_cleanup();
    return 0;
}