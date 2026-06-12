#include "../include/keyGenerator.h"
#include <stdexcept>

std::vector<uint8_t> generateKeyForPlugin(const CryptoPlugin& plugin, int param) {
    size_t bufferSize = plugin.getMaxKeySize();
    std::vector<uint8_t> buffer(bufferSize);

    int result = plugin.generateKey(buffer.data(), &bufferSize, param);
    if (result != 0) {
        throw std::runtime_error("Ошибка генерации ключа (код: " + std::to_string(result) + ")");
    }

    buffer.resize(bufferSize);
    return buffer;
}