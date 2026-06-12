#include "fileProcessor.h"
#include "utils.h"
#include <iostream>
#include <fstream>

static bool processFile(const CryptoPlugin& plugin,
                        const std::string& inputPath,
                        const std::string& outputPath,
                        const std::vector<uint8_t>& key,
                        bool isEncrypt) {
    try {
        if (!fileExists(inputPath)) {
            std::cerr << "Файл не найден: " << inputPath << std::endl;
            return false;
        }
        if (!ensureDirectoryExists(outputPath)) return false;

        std::ifstream inFile(inputPath, std::ios::binary);
        if (!inFile.is_open()) {
            std::cerr << "Не открыть для чтения: " << inputPath << std::endl;
            return false;
        }

        std::vector<uint8_t> inputData((std::istreambuf_iterator<char>(inFile)),
                                        std::istreambuf_iterator<char>());
        inFile.close();

        size_t outputSize = inputData.size() * 4 + 256;
        std::vector<uint8_t> outputData(outputSize);

        int result = isEncrypt
            ? plugin.encrypt(inputData.data(), inputData.size(), key.data(), key.size(),
                             outputData.data(), &outputSize)
            : plugin.decrypt(inputData.data(), inputData.size(), key.data(), key.size(),
                             outputData.data(), &outputSize);

        if (result != 0) {
            std::cerr << "Ошибка операции (код: " << result << ")" << std::endl;
            return false;
        }

        outputData.resize(outputSize);

        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile.is_open()) {
            std::cerr << "Не создать файл: " << outputPath << std::endl;
            return false;
        }

        outFile.write(reinterpret_cast<const char*>(outputData.data()), outputData.size());
        outFile.close();

        std::cout << (isEncrypt ? "Зашифровано: " : "Дешифровано: ") << outputPath << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Исключение: " << e.what() << std::endl;
        return false;
    }
}

bool encryptFile(const CryptoPlugin& plugin,
                 const std::string& inputPath,
                 const std::string& outputPath,
                 const std::vector<uint8_t>& key) {
    return processFile(plugin, inputPath, outputPath, key, true);
}

bool decryptFile(const CryptoPlugin& plugin,
                 const std::string& inputPath,
                 const std::string& outputPath,
                 const std::vector<uint8_t>& key) {
    return processFile(plugin, inputPath, outputPath, key, false);
}