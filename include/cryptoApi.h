#ifndef CRYPTO_API_H
#define CRYPTO_API_H

#include <cstddef>
#include <cstdint>

using GetAlgorithmNameFunc = const char* (*)();
using GetKeyInfoFunc = const char* (*)();
using GetMinKeySizeFunc = size_t (*)();
using GetMaxKeySizeFunc = size_t (*)();

using EncryptFunc = int (*)(const uint8_t* data, size_t dataSize,
                            const uint8_t* key, size_t keySize,
                            uint8_t* output, size_t* outputSize);

using DecryptFunc = int (*)(const uint8_t* data, size_t dataSize,
                            const uint8_t* key, size_t keySize,
                            uint8_t* output, size_t* outputSize);

using GenerateKeyFunc = int (*)(uint8_t* keyBuffer, size_t* keyBufferSize, int param);

#endif