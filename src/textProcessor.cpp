#include "../include/textProcessor.h"
#include "utils.h"
#include <stdexcept>

std::vector<uint8_t> encryptText(const CryptoPlugin& plugin,
                                  const std::string& plainText,
                                  const std::vector<uint8_t>& key) {
    std::vector<uint8_t> inputData = stringToBytes(plainText);

    // Для RSA/Rabin/Шамира выход в 2 раза больше входа
    size_t outputSize = inputData.size() * 16 + 256;
    std::vector<uint8_t> output(outputSize);

    int result = plugin.encrypt(inputData.data(), inputData.size(),
                                key.data(), key.size(),
                                output.data(), &outputSize);

    if (result != 0) {
        throw std::runtime_error("Ошибка шифрования (код: " + std::to_string(result) + ")");
    }

    output.resize(outputSize);
    return output;
}

std::string decryptText(const CryptoPlugin& plugin,
                        const std::vector<uint8_t>& cipherData,
                        const std::vector<uint8_t>& key) {
    size_t outputSize = cipherData.size() * 16 + 256;
    std::vector<uint8_t> output(outputSize);

    int result = plugin.decrypt(cipherData.data(), cipherData.size(),
                                key.data(), key.size(),
                                output.data(), &outputSize);

    if (result != 0) {
        throw std::runtime_error("Ошибка дешифрования (код: " + std::to_string(result) + ")");
    }

    output.resize(outputSize);
    return bytesToString(output);
}

std::vector<uint8_t> decryptToBytes(const CryptoPlugin& plugin,
                                     const std::vector<uint8_t>& cipherData,
                                     const std::vector<uint8_t>& key) {
    size_t outputSize = cipherData.size() * 2 + 256;
    std::vector<uint8_t> output(outputSize);

    int result = plugin.decrypt(cipherData.data(), cipherData.size(),
                                key.data(), key.size(),
                                output.data(), &outputSize);

    if (result != 0) {
        throw std::runtime_error("Ошибка дешифрования (код: " + std::to_string(result) + ")");
    }

    output.resize(outputSize);
    return output;
}