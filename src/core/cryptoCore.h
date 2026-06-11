#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H
#include <string>

struct KeyPair {
    std::string openKey;
    std::string privateKey;
};

void process();

#endif