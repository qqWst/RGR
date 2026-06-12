#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <ctime>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

extern "C" {

EXPORT const char* getAlgorithmName() { return "XOR (Гаммирование)"; }

EXPORT const char* getKeyInfo() {
    return "Симметричный шифр. Ключ — произвольная строка байт (1-256).\n"
           "Используется циклический XOR данных с ключом.";
}

EXPORT size_t getMinKeySize() { return 1; }
EXPORT size_t getMaxKeySize() { return 256; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;
    if (keySize < 1) return -2;
    if (*outputSize < dataSize) return -3;

    for (size_t i = 0; i < dataSize; ++i) {
        output[i] = data[i] ^ key[i % keySize];
    }
    *outputSize = dataSize;
    return 0;
}

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    return encrypt(data, dataSize, key, keySize, output, outputSize);
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    size_t keyLen = (param > 0 && param <= 256) ? static_cast<size_t>(param) : 16;
    if (*keyBufferSize < keyLen) return -3;

    srand(static_cast<unsigned>(time(nullptr)));
    for (size_t i = 0; i < keyLen; ++i) {
        keyBuffer[i] = static_cast<uint8_t>('!' + (rand() % 93));
    }
    *keyBufferSize = keyLen;
    return 0;
}

}