#include <openssl/evp.h>
#include <openssl/sha.h>

#include <curl/curl.h>

#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <iomanip>

std::string calc_sha256(std::string fileName);
void check_hash(CURLcode *res, const std::string& hash, const std::string& auth_key);