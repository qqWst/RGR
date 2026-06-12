#ifndef CRYPTO_API_H
#define CRYPTO_API_H

#include <cstddef>
#include <cstdint>

// Унифицированный интерфейс для всех криптографических плагинов.

using GetAlgorithmNameFunc = const char* (*)();

using EncryptFunc = int (*)(const uint8_t* data, size_t dataSize,
                            const uint8_t* key, size_t keySize,
                            uint8_t* output, size_t* outputSize);

using DecryptFunc = int (*)(const uint8_t* data, size_t dataSize,
                            const uint8_t* key, size_t keySize,
                            uint8_t* output, size_t* outputSize);

// param — для разных алгоритмов имеет разный смысл (длина, опции и т.п.)
using GenerateKeyFunc = int (*)(uint8_t* keyBuffer, size_t* keyBufferSize, int param);

using GetMinKeySizeFunc = size_t (*)();
using GetMaxKeySizeFunc = size_t (*)();

// Возвращает справочный текст по формату ключа алгоритма
using GetKeyInfoFunc = const char* (*)();

#endif