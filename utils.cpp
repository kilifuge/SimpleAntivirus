#include "hash_analyze.hpp"

size_t Write_data (void* bufptr, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)bufptr, size * nmemb);
    return size * nmemb; 
}

void check_hash(CURLcode *res, const std::string& hash, const std::string& auth_key) {
    CURL* curl;
    std::string readBuffer;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://mb-api.abuse.ch/api/v1/");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        struct curl_slist* headers = nullptr;
        std::string api_header = "Auth-Key: " + auth_key;
        headers = curl_slist_append(headers, api_header.c_str());
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        std::string post_data = "query=get_info&hash=" + hash;
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        *res = curl_easy_perform(curl);

        if (*res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(*res) << std::endl;
        } else {
            if (readBuffer.find("hash_not_found") != std::string::npos) {
                std::cout << "File is clean" << std::endl;
            } else if (readBuffer.find("\"query_status\": \"ok\"") != std::string::npos) {
                std::cout << "File is infected" << std::endl;
                std::cout << "Show all information? y/n" << std::endl;
                if (getchar() == 'y')
                    std::cout << readBuffer << std::endl;
            } else if (readBuffer.find("wrong_auth_key") != std::string::npos) {
                std::cout << "Wrong Auth-Key" << std::endl;
            } else {
                std::cout << "Unknown Error, show all information? y/n: " << std::endl;
                if (getchar() == 'y')
                    std::cout << readBuffer << std::endl;
            }
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
}

std::string calc_sha256(std::string fileName) {
    std::ifstream ifs(fileName, std::ios::binary);
    unsigned char hash[SHA256_DIGEST_LENGTH];

    if (!ifs.is_open()) 
        throw std::runtime_error("Can't open that file, maybe he is not exist");

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();

    auto emer_shut_down = [&mdctx, &ifs](std::string message = "calc_sha256 Error") {
        EVP_MD_CTX_free(mdctx);
        ifs.close();
        throw std::runtime_error(message);
    };

    if (!mdctx || !md)
        emer_shut_down("Error with opening EVP_MD_CTX or EVP_MD");

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
        emer_shut_down("Error with initialising EVP");

    std::vector<char> buffer(4096);
    while (ifs.read(buffer.data(), buffer.size()))
        if (EVP_DigestUpdate(mdctx, buffer.data(), ifs.gcount()) != 1)
            emer_shut_down("Error with writing file into EVP");

    if (ifs.gcount() > 0)
        if (EVP_DigestUpdate(mdctx, buffer.data(), ifs.gcount()) != 1)
            emer_shut_down("Error with writing file into EVP");

    if (EVP_DigestFinal_ex(mdctx, hash, nullptr) != 1)
        emer_shut_down("Error with writing hash to string");

    EVP_MD_CTX_free(mdctx);
    ifs.close();

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    return oss.str();
}