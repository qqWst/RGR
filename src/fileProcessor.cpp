#include "../include/fileProcessor.h"
#include "../include/utils.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>

static size_t getFileSize(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return 0;
    return static_cast<size_t>(file.tellg());
}

static void printProgress(size_t processed, size_t total) {
    if (total == 0) return;

    int percent = static_cast<int>((processed * 100) / total);
    int barWidth = 30;
    int filled = (percent * barWidth) / 100;

    std::cout << "\r[";
    for (int i = 0; i < barWidth; ++i) {
        std::cout << (i < filled ? '#' : '.');
    }
    std::cout << "] " << std::setw(3) << percent << "% ("
              << processed << " / " << total << " байт)" << std::flush;
}

static bool confirmLargeFile(const std::string& algorithmName, size_t fileSize) {
    if (algorithmName.find("XOR") != std::string::npos) return true;

    if (fileSize < WARN_FILE_SIZE) return true;

    double sizeMb = static_cast<double>(fileSize) / (1024.0 * 1024.0);
    std::cout << "\nВНИМАНИЕ!" << std::endl;
    std::cout << "Размер файла: " << std::fixed << std::setprecision(2)
              << sizeMb << " МБ." << std::endl;
    std::cout << "Алгоритмы RSA/Rabin/Шамир медленные — операция может занять"
              << " длительное время." << std::endl;
    std::cout << "Размер выходного файла будет примерно в 2 раза больше." << std::endl;
    std::cout << "Продолжить? (1 - да, 0 - нет): ";

    int choice = 0;
    std::cin >> choice;
    std::cin.ignore();
    return choice == 1;
}

static bool processFileStream(const CryptoPlugin& plugin,
                              const std::string& inputPath,
                              const std::string& outputPath,
                              const std::vector<uint8_t>& key,
                              bool isEncrypt) {
    try {
        if (!fileExists(inputPath)) {
            std::cerr << "Файл не найден, создайте файл для дальнейшей работы с ним: " << inputPath << std::endl;
            return false;
        }
        if (!ensureDirectoryExists(outputPath)) return false;

        size_t totalSize = getFileSize(inputPath);
        if (!confirmLargeFile(plugin.algorithmName, totalSize)) {
            std::cout << "Операция отменена." << std::endl;
            return false;
        }

        std::ifstream inFile(inputPath, std::ios::binary);
        if (!inFile.is_open()) {
            std::cerr << "Не открыть файл для чтения: " << inputPath << std::endl;
            return false;
        }

        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile.is_open()) {
            std::cerr << "Не создать выходной файл: " << outputPath << std::endl;
            return false;
        }

        std::vector<uint8_t> blockIn(BLOCK_SIZE);
        std::vector<uint8_t> blockOut(BLOCK_SIZE * 16 + 256);

        size_t processed = 0;
        bool firstBlock = true;

        std::cout << (isEncrypt ? "Шифрование..." : "Дешифрование...") << std::endl;

        while (inFile.good()) {
            inFile.read(reinterpret_cast<char*>(blockIn.data()), BLOCK_SIZE);
            std::streamsize bytesRead = inFile.gcount();
            if (bytesRead <= 0) break;

            size_t outSize = blockOut.size();
            int result = isEncrypt
                ? plugin.encrypt(blockIn.data(), static_cast<size_t>(bytesRead),
                                 key.data(), key.size(),
                                 blockOut.data(), &outSize)
                : plugin.decrypt(blockIn.data(), static_cast<size_t>(bytesRead),
                                 key.data(), key.size(), blockOut.data(), &outSize);

            if (result != 0) {
                std::cerr << "\nОшибка обработки файла. " << errorToMessage(result) << std::endl;
                return false;
            }

            outFile.write(reinterpret_cast<const char*>(blockOut.data()),
                          static_cast<std::streamsize>(outSize));

            processed += static_cast<size_t>(bytesRead);

            if (firstBlock || processed == totalSize ||
                (processed % (BLOCK_SIZE * 16) == 0)) {
                printProgress(processed, totalSize);
                firstBlock = false;
            }
        }

        printProgress(totalSize, totalSize);
        std::cout << std::endl;

        inFile.close();
        outFile.close();

        std::cout << (isEncrypt ? "Файл зашифрован: " : "Файл дешифрован: ")
                  << outputPath << std::endl;
        return true;

    } catch (const std::exception& e) {
        std::cerr << "\nИсключение: " << e.what() << std::endl;
        return false;
    }
}

bool encryptFile(const CryptoPlugin& plugin,
                 const std::string& inputPath,
                 const std::string& outputPath,
                 const std::vector<uint8_t>& key) {
    return processFileStream(plugin, inputPath, outputPath, key, true);
}

bool decryptFile(const CryptoPlugin& plugin,
                 const std::string& inputPath,
                 const std::string& outputPath,
                 const std::vector<uint8_t>& key) {
    return processFileStream(plugin, inputPath, outputPath, key, false);
}