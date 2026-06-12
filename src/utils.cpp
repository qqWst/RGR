#include "utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(dir) _mkdir(dir)
#else
#define MKDIR(dir) mkdir(dir, 0755)
#endif

bool fileExists(const std::string& path) {
    std::ifstream file(path);
    return file.good();
}

bool ensureDirectoryExists(const std::string& filePath) {
    size_t lastSlash = filePath.find_last_of("/\\");
    if (lastSlash == std::string::npos) return true;

    std::string dirPath = filePath.substr(0, lastSlash);
    if (dirPath.empty()) return true;

    struct stat info;
    if (stat(dirPath.c_str(), &info) == 0) return true;

    std::cout << "Директория \"" << dirPath << "\" не существует." << std::endl;
    std::cout << "Создать? (1 - да, 0 - нет): ";
    int choice = 0;
    std::cin >> choice;
    std::cin.ignore();

    if (choice == 1) {
        if (MKDIR(dirPath.c_str()) == 0) {
            std::cout << "Директория создана." << std::endl;
            return true;
        } else {
            std::cerr << "Ошибка создания директории." << std::endl;
            return false;
        }
    }
    return false;
}

bool validatePath(const std::string& path) {
    if (path.empty()) {
        std::cerr << "Путь не может быть пустым." << std::endl;
        return false;
    }
    const std::string forbidden = "<>|\"";
    for (char ch : path) {
        for (char f : forbidden) {
            if (ch == f) {
                std::cerr << "Недопустимый символ: '" << ch << "'" << std::endl;
                return false;
            }
        }
    }
    return true;
}

std::vector<uint8_t> stringToBytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string bytesToString(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

std::string bytesToHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.length() % 2 != 0) {
        std::cerr << "Hex-строка должна быть чётной длины." << std::endl;
        return bytes;
    }
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
            bytes.push_back(byte);
        } catch (const std::exception& e) {
            std::cerr << "Ошибка hex: " << e.what() << std::endl;
            return {};
        }
    }
    return bytes;
}

int readInt(const std::string& prompt) {
    std::cout << prompt;
    int value = 0;
    while (!(std::cin >> value)) {
        std::cin.clear();
        std::cin.ignore(10000, '\n');
        std::cout << "Введите целое число: ";
    }
    std::cin.ignore(10000, '\n');
    return value;
}

std::string readLine(const std::string& prompt) {
    std::cout << prompt;
    std::string line;
    std::getline(std::cin, line);
    return line;
}

bool login(const std::string& expectedPassword) {
    std::cout << "========================================" << std::endl;
    std::cout << "       Авторизация пользователя" << std::endl;
    std::cout << "========================================" << std::endl;

    std::string entered = readLine("Введите пароль: ");

    switch (entered == expectedPassword ? 1 : 0) {
        case 1:
            std::cout << "Доступ разрешён." << std::endl;
            std::cout << "========================================" << std::endl;
            return true;
        case 0:
        default:
            std::cerr << "Неверный пароль! Доступ запрещён." << std::endl;
            return false;
    }
}