# Полный код проекта «Криптографический практикум»

## Структура проекта

```
crypto_app/
├── Makefile
├── include/
│   ├── cryptoApi.h
│   ├── libraryLoader.h
│   ├── textProcessor.h
│   ├── fileProcessor.h
│   ├── keyGenerator.h
│   ├── menu.h
│   └── utils.h
├── src/
│   ├── main.cpp
│   ├── libraryLoader.cpp
│   ├── textProcessor.cpp
│   ├── fileProcessor.cpp
│   ├── keyGenerator.cpp
│   ├── menu.cpp
│   └── utils.cpp
└── plugins/
    ├── xorCipher.cpp
    ├── rsaCipher.cpp
    ├── rabinCipher.cpp
    ├── shamirCipher.cpp
    ├── fiatShamirAuth.cpp
    └── diffieHellmanKE.cpp
```

---

## Makefile

```makefile
# ============================================================
# Makefile для криптографического практикума
# ============================================================

CXX        := g++
CXXFLAGS   := -std=c++17 -Wall -Wextra -O2 -Iinclude
LDFLAGS    := -ldl
SOFLAGS    := -shared -fPIC

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    LIB_EXT := so
endif
ifeq ($(UNAME_S),Darwin)
    LIB_EXT := dylib
    LDFLAGS :=
endif
ifeq ($(OS),Windows_NT)
    LIB_EXT := dll
    LDFLAGS :=
endif

SRC_DIR     := src
INC_DIR     := include
PLUGIN_DIR  := plugins
BUILD_DIR   := build
OBJ_DIR     := $(BUILD_DIR)/obj
BIN_DIR     := $(BUILD_DIR)
PLUGIN_OUT  := $(BUILD_DIR)/plugins

APP_SOURCES := $(wildcard $(SRC_DIR)/*.cpp)
APP_OBJECTS := $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(APP_SOURCES))
APP_TARGET  := $(BIN_DIR)/cryptoApp

PLUGIN_SOURCES := $(wildcard $(PLUGIN_DIR)/*.cpp)
PLUGIN_TARGETS := $(patsubst $(PLUGIN_DIR)/%.cpp, $(PLUGIN_OUT)/%.$(LIB_EXT), $(PLUGIN_SOURCES))

.PHONY: all clean run app plugins dirs help

all: dirs app plugins

dirs:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(PLUGIN_OUT)

app: $(APP_TARGET)

$(APP_TARGET): $(APP_OBJECTS)
	@echo "==> Линковка приложения: $@"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@echo "==> Компиляция: $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

plugins: $(PLUGIN_TARGETS)

$(PLUGIN_OUT)/%.$(LIB_EXT): $(PLUGIN_DIR)/%.cpp
	@echo "==> Сборка плагина: $@"
	$(CXX) $(CXXFLAGS) $(SOFLAGS) -o $@ $<

run: all
	@echo "==> Запуск приложения"
	@cd $(BIN_DIR) && ./cryptoApp

clean:
	@echo "==> Очистка"
	rm -rf $(BUILD_DIR)

help:
	@echo "Цели:"
	@echo "  all      - собрать всё"
	@echo "  app      - только приложение"
	@echo "  plugins  - только плагины"
	@echo "  run      - собрать и запустить"
	@echo "  clean    - удалить артефакты"
```

---

## include/cryptoApi.h

```cpp
#ifndef CRYPTO_API_H
#define CRYPTO_API_H

#include <cstddef>
#include <cstdint>

// Унифицированный C-интерфейс для всех криптографических плагинов.

using GetAlgorithmNameFunc = const char* (*)();
using GetKeyInfoFunc       = const char* (*)();
using GetMinKeySizeFunc    = size_t (*)();
using GetMaxKeySizeFunc    = size_t (*)();

using EncryptFunc = int (*)(const uint8_t* data, size_t dataSize,
                            const uint8_t* key, size_t keySize,
                            uint8_t* output, size_t* outputSize);

using DecryptFunc = int (*)(const uint8_t* data, size_t dataSize,
                            const uint8_t* key, size_t keySize,
                            uint8_t* output, size_t* outputSize);

using GenerateKeyFunc = int (*)(uint8_t* keyBuffer, size_t* keyBufferSize, int param);

#endif
```

---

## include/libraryLoader.h

```cpp
#ifndef LIBRARY_LOADER_H
#define LIBRARY_LOADER_H

#include "cryptoApi.h"
#include <string>
#include <vector>

struct CryptoPlugin {
    std::string filePath;
    std::string algorithmName;
    void* handle = nullptr;

    GetAlgorithmNameFunc getAlgorithmName = nullptr;
    GetKeyInfoFunc       getKeyInfo       = nullptr;
    GetMinKeySizeFunc    getMinKeySize    = nullptr;
    GetMaxKeySizeFunc    getMaxKeySize    = nullptr;
    EncryptFunc          encrypt          = nullptr;
    DecryptFunc          decrypt          = nullptr;
    GenerateKeyFunc      generateKey      = nullptr;
};

bool loadPlugin(const std::string& path, CryptoPlugin& plugin);
void unloadPlugin(CryptoPlugin& plugin);
std::vector<CryptoPlugin> loadAllPlugins(const std::string& directory);
void unloadAllPlugins(std::vector<CryptoPlugin>& plugins);

#endif
```

---

## include/textProcessor.h

```cpp
#ifndef TEXT_PROCESSOR_H
#define TEXT_PROCESSOR_H

#include "libraryLoader.h"
#include <string>
#include <vector>

std::vector<uint8_t> encryptText(const CryptoPlugin& plugin,
                                  const std::string& plainText,
                                  const std::vector<uint8_t>& key);

std::string decryptText(const CryptoPlugin& plugin,
                        const std::vector<uint8_t>& cipherData,
                        const std::vector<uint8_t>& key);

#endif
```

---

## include/fileProcessor.h

```cpp
#ifndef FILE_PROCESSOR_H
#define FILE_PROCESSOR_H

#include "libraryLoader.h"
#include <string>
#include <vector>

constexpr size_t BLOCK_SIZE = 4096;
constexpr size_t WARN_FILE_SIZE = 1024 * 1024;

bool encryptFile(const CryptoPlugin& plugin,
                 const std::string& inputPath,
                 const std::string& outputPath,
                 const std::vector<uint8_t>& key);

bool decryptFile(const CryptoPlugin& plugin,
                 const std::string& inputPath,
                 const std::string& outputPath,
                 const std::vector<uint8_t>& key);

#endif
```

---

## include/keyGenerator.h

```cpp
#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include "libraryLoader.h"
#include <vector>

std::vector<uint8_t> generateKeyForPlugin(const CryptoPlugin& plugin, int param);

#endif
```

---

## include/menu.h

```cpp
#ifndef MENU_H
#define MENU_H

#include "libraryLoader.h"
#include <vector>

enum class MainMenuOption {
    EncryptDecryptText = 1,
    EncryptDecryptFile = 2,
    KeyGenerator       = 3,
    ShowKeyInfo        = 4,
    Exit               = 0
};

enum class CryptoAction {
    Encrypt = 1,
    Decrypt = 2,
    Back    = 0
};

void runMainMenu(std::vector<CryptoPlugin>& plugins);

#endif
```

---

## include/utils.h

```cpp
#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <cstdint>

bool fileExists(const std::string& path);
bool ensureDirectoryExists(const std::string& filePath);
bool validatePath(const std::string& path);

std::vector<uint8_t> stringToBytes(const std::string& str);
std::string bytesToString(const std::vector<uint8_t>& data);
std::string bytesToHex(const std::vector<uint8_t>& data);
std::vector<uint8_t> hexToBytes(const std::string& hex);

int readInt(const std::string& prompt);
std::string readLine(const std::string& prompt);

bool login(const std::string& expectedPassword);

enum class CryptoError : int {
    Ok              =   0,
    NullPointer     =  -1,
    InvalidKey      =  -2,
    BufferTooSmall  =  -3,
    KeyTooSmall     =  -4,
    InvalidDataSize =  -5,
    KeygenFailed    = -10,
    NoInverse       = -11
};

std::string errorToMessage(int code);

#endif
```

---

## src/utils.cpp

```cpp
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
            std::cerr << "Не удалось создать директорию." << std::endl;
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
                std::cerr << "Путь содержит недопустимый символ '" << ch << "'." << std::endl;
                std::cerr << "В пути нельзя использовать: < > | \"" << std::endl;
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
        std::cerr << "Шифротекст имеет некорректный формат: длина должна быть чётной." << std::endl;
        return bytes;
    }
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
            bytes.push_back(byte);
        } catch (const std::exception&) {
            std::cerr << "Шифротекст содержит недопустимые символы (только 0-9, a-f)." << std::endl;
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

std::string errorToMessage(int code) {
    switch (static_cast<CryptoError>(code)) {
        case CryptoError::Ok:
            return "Операция выполнена успешно.";
        case CryptoError::NullPointer:
            return "Внутренняя ошибка программы. Сообщите разработчику.";
        case CryptoError::InvalidKey:
            return "Неверный формат ключа. Проверьте формат через "
                   "пункт меню \"Информация о формате ключей\".";
        case CryptoError::BufferTooSmall:
            return "Недостаточно памяти для результата.";
        case CryptoError::KeyTooSmall:
            return "Ключ слишком короткий для безопасного шифрования. "
                   "Сгенерируйте новый ключ с большей битностью.";
        case CryptoError::InvalidDataSize:
            return "Повреждены входные данные. "
                   "Проверьте, что вы скопировали данные полностью.";
        case CryptoError::KeygenFailed:
            return "Не удалось сгенерировать ключ. "
                   "Попробуйте указать другое значение параметра битности.";
        case CryptoError::NoInverse:
            return "Не удалось вычислить обратный элемент. Повторите генерацию ключа.";
        default:
            return "Неизвестная ошибка (код: " + std::to_string(code) + ").";
    }
}
```

---

## src/libraryLoader.cpp

```cpp
#include "libraryLoader.h"
#include <iostream>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

void* openLibrary(const std::string& path) {
#ifdef _WIN32
    return LoadLibraryA(path.c_str());
#else
    return dlopen(path.c_str(), RTLD_LAZY);
#endif
}

void* getSymbol(void* handle, const std::string& name) {
#ifdef _WIN32
    return reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(handle), name.c_str()));
#else
    return dlsym(handle, name.c_str());
#endif
}

void closeLibrary(void* handle) {
#ifdef _WIN32
    FreeLibrary(static_cast<HMODULE>(handle));
#else
    dlclose(handle);
#endif
}

std::string getLastErrorString() {
#ifdef _WIN32
    return "Windows error " + std::to_string(GetLastError());
#else
    const char* err = dlerror();
    return err ? std::string(err) : "Неизвестная ошибка";
#endif
}

} // namespace

bool loadPlugin(const std::string& path, CryptoPlugin& plugin) {
    plugin.handle = openLibrary(path);
    if (!plugin.handle) {
        std::cerr << "Не удалось загрузить библиотеку: " << path << std::endl;
        std::cerr << "Причина: " << getLastErrorString() << std::endl;
        return false;
    }

    plugin.filePath = path;
    plugin.getAlgorithmName = reinterpret_cast<GetAlgorithmNameFunc>(getSymbol(plugin.handle, "getAlgorithmName"));
    plugin.getKeyInfo       = reinterpret_cast<GetKeyInfoFunc>(getSymbol(plugin.handle, "getKeyInfo"));
    plugin.getMinKeySize    = reinterpret_cast<GetMinKeySizeFunc>(getSymbol(plugin.handle, "getMinKeySize"));
    plugin.getMaxKeySize    = reinterpret_cast<GetMaxKeySizeFunc>(getSymbol(plugin.handle, "getMaxKeySize"));
    plugin.encrypt          = reinterpret_cast<EncryptFunc>(getSymbol(plugin.handle, "encrypt"));
    plugin.decrypt          = reinterpret_cast<DecryptFunc>(getSymbol(plugin.handle, "decrypt"));
    plugin.generateKey      = reinterpret_cast<GenerateKeyFunc>(getSymbol(plugin.handle, "generateKey"));

    if (!plugin.getAlgorithmName || !plugin.encrypt || !plugin.decrypt ||
        !plugin.generateKey || !plugin.getMinKeySize || !plugin.getMaxKeySize ||
        !plugin.getKeyInfo) {
        std::cerr << "Библиотека " << path << " не реализует все необходимые функции." << std::endl;
        closeLibrary(plugin.handle);
        plugin.handle = nullptr;
        return false;
    }

    plugin.algorithmName = plugin.getAlgorithmName();
    std::cout << "Загружен плагин: " << plugin.algorithmName << std::endl;
    return true;
}

void unloadPlugin(CryptoPlugin& plugin) {
    if (plugin.handle) {
        closeLibrary(plugin.handle);
        plugin.handle = nullptr;
    }
}

std::vector<CryptoPlugin> loadAllPlugins(const std::string& directory) {
    std::vector<CryptoPlugin> plugins;
    try {
        if (!std::filesystem::exists(directory)) {
            std::cerr << "Директория плагинов не найдена: " << directory << std::endl;
            return plugins;
        }

        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            std::string ext = entry.path().extension().string();
#ifdef _WIN32
            if (ext == ".dll") {
#else
            if (ext == ".so" || ext == ".dylib") {
#endif
                CryptoPlugin plugin;
                if (loadPlugin(entry.path().string(), plugin)) {
                    plugins.push_back(plugin);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Ошибка сканирования: " << e.what() << std::endl;
    }
    return plugins;
}

void unloadAllPlugins(std::vector<CryptoPlugin>& plugins) {
    for (auto& p : plugins) unloadPlugin(p);
    plugins.clear();
}
```

---

## src/textProcessor.cpp

```cpp
#include "textProcessor.h"
#include "utils.h"
#include <stdexcept>

std::vector<uint8_t> encryptText(const CryptoPlugin& plugin,
                                  const std::string& plainText,
                                  const std::vector<uint8_t>& key) {
    std::vector<uint8_t> inputData = stringToBytes(plainText);

    size_t outputSize = inputData.size() * 16 + 1024;
    std::vector<uint8_t> output(outputSize);

    int result = plugin.encrypt(inputData.data(), inputData.size(),
                                key.data(), key.size(),
                                output.data(), &outputSize);

    if (result != 0) {
        throw std::runtime_error("Ошибка операции. " + errorToMessage(result));
    }

    output.resize(outputSize);
    return output;
}

std::string decryptText(const CryptoPlugin& plugin,
                        const std::vector<uint8_t>& cipherData,
                        const std::vector<uint8_t>& key) {
    size_t outputSize = cipherData.size() * 4 + 1024;
    std::vector<uint8_t> output(outputSize);

    int result = plugin.decrypt(cipherData.data(), cipherData.size(),
                                key.data(), key.size(),
                                output.data(), &outputSize);

    if (result != 0) {
        throw std::runtime_error("Ошибка операции. " + errorToMessage(result));
    }

    output.resize(outputSize);
    return bytesToString(output);
}
```

---

## src/fileProcessor.cpp

```cpp
#include "fileProcessor.h"
#include "utils.h"
#include <iostream>
#include <fstream>
#include <iomanip>

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
    std::cout << "Асимметричные алгоритмы медленные — операция займёт время." << std::endl;
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
            std::cerr << "Не удалось найти входной файл: \"" << inputPath << "\"" << std::endl;
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
            std::cerr << "Не удалось открыть файл для чтения." << std::endl;
            return false;
        }

        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile.is_open()) {
            std::cerr << "Не удалось создать выходной файл." << std::endl;
            return false;
        }

        std::vector<uint8_t> blockIn(BLOCK_SIZE);
        std::vector<uint8_t> blockOut(BLOCK_SIZE * 16 + 1024);

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
                                 key.data(), key.size(),
                                 blockOut.data(), &outSize);

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
```

---

## src/keyGenerator.cpp

```cpp
#include "keyGenerator.h"
#include "utils.h"
#include <stdexcept>

std::vector<uint8_t> generateKeyForPlugin(const CryptoPlugin& plugin, int param) {
    size_t bufferSize = 512;
    std::vector<uint8_t> buffer(bufferSize);

    int result = plugin.generateKey(buffer.data(), &bufferSize, param);
    if (result != 0) {
        throw std::runtime_error("Ошибка генерации ключа. " + errorToMessage(result));
    }

    buffer.resize(bufferSize);
    return buffer;
}
```

---

## src/menu.cpp

```cpp
#include "menu.h"
#include "textProcessor.h"
#include "fileProcessor.h"
#include "keyGenerator.h"
#include "utils.h"
#include <iostream>

static int selectPlugin(const std::vector<CryptoPlugin>& plugins) {
    std::cout << "\n=== Доступные алгоритмы ===" << std::endl;
    for (size_t i = 0; i < plugins.size(); ++i) {
        std::cout << "  " << (i + 1) << ". " << plugins[i].algorithmName << std::endl;
    }
    std::cout << "  0. Назад" << std::endl;

    int choice = readInt("Выбор: ");
    if (choice == 0) return -1;
    if (choice < 1 || choice > static_cast<int>(plugins.size())) {
        std::cerr << "Введён неверный номер." << std::endl;
        return -1;
    }
    return choice - 1;
}

static CryptoAction selectAction() {
    std::cout << "\n  1. Шифрование" << std::endl;
    std::cout << "  2. Дешифрование" << std::endl;
    std::cout << "  0. Назад" << std::endl;

    int choice = readInt("Выбор: ");
    switch (choice) {
        case 1:  return CryptoAction::Encrypt;
        case 2:  return CryptoAction::Decrypt;
        case 0:  return CryptoAction::Back;
        default:
            std::cerr << "Неверный выбор." << std::endl;
            return CryptoAction::Back;
    }
}

static void handleText(std::vector<CryptoPlugin>& plugins) {
    int idx = selectPlugin(plugins);
    if (idx < 0) return;
    CryptoAction action = selectAction();
    if (action == CryptoAction::Back) return;

    const CryptoPlugin& plugin = plugins[idx];
    std::cout << "Формат ключа:\n" << plugin.getKeyInfo() << std::endl;

    std::string keyStr = readLine("Ключ: ");
    std::vector<uint8_t> key = stringToBytes(keyStr);

    try {
        switch (action) {
            case CryptoAction::Encrypt: {
                std::string text = readLine("Текст: ");
                std::vector<uint8_t> result = encryptText(plugin, text, key);
                std::cout << "Результат (hex): " << bytesToHex(result) << std::endl;
                break;
            }
            case CryptoAction::Decrypt: {
                std::string hexStr = readLine("Шифротекст (hex): ");
                std::vector<uint8_t> cipher = hexToBytes(hexStr);
                if (cipher.empty()) return;
                std::string result = decryptText(plugin, cipher, key);
                std::cout << "Результат: " << result << std::endl;
                break;
            }
            case CryptoAction::Back:
                break;
        }
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

static void handleFile(std::vector<CryptoPlugin>& plugins) {
    int idx = selectPlugin(plugins);
    if (idx < 0) return;
    CryptoAction action = selectAction();
    if (action == CryptoAction::Back) return;

    const CryptoPlugin& plugin = plugins[idx];
    std::cout << "Формат ключа:\n" << plugin.getKeyInfo() << std::endl;

    std::string keyStr = readLine("Ключ: ");
    std::vector<uint8_t> key = stringToBytes(keyStr);

    std::string inPath = readLine("Входной файл: ");
    if (!validatePath(inPath)) return;
    if (!fileExists(inPath)) {
        std::cerr << "Файл не найден: " << inPath << std::endl;
        return;
    }

    std::string outPath = readLine("Выходной файл: ");
    if (!validatePath(outPath)) return;

    try {
        switch (action) {
            case CryptoAction::Encrypt: encryptFile(plugin, inPath, outPath, key); break;
            case CryptoAction::Decrypt: decryptFile(plugin, inPath, outPath, key); break;
            case CryptoAction::Back: break;
        }
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

static void handleKeyGenerator(std::vector<CryptoPlugin>& plugins) {
    int idx = selectPlugin(plugins);
    if (idx < 0) return;

    const CryptoPlugin& plugin = plugins[idx];
    std::cout << "Информация:\n" << plugin.getKeyInfo() << std::endl;

    int param = readInt("Параметр генерации (0 — режим по умолчанию): ");

    try {
        std::vector<uint8_t> key = generateKeyForPlugin(plugin, param);
        std::cout << "\nРезультат:\n" << bytesToString(key) << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

static void handleShowKeyInfo(std::vector<CryptoPlugin>& plugins) {
    int idx = selectPlugin(plugins);
    if (idx < 0) return;
    std::cout << "\n=== " << plugins[idx].algorithmName << " ===" << std::endl;
    std::cout << plugins[idx].getKeyInfo() << std::endl;
}

void runMainMenu(std::vector<CryptoPlugin>& plugins) {
    if (plugins.empty()) {
        std::cerr << "Нет загруженных плагинов." << std::endl;
        return;
    }

    bool running = true;
    while (running) {
        std::cout << "\n========================================" << std::endl;
        std::cout << "  Криптографическое приложение" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "  1. Шифрование/дешифрование текста" << std::endl;
        std::cout << "  2. Шифрование/дешифрование файла" << std::endl;
        std::cout << "  3. Генератор ключей" << std::endl;
        std::cout << "  4. Информация о формате ключей" << std::endl;
        std::cout << "  0. Выход" << std::endl;
        std::cout << "========================================" << std::endl;

        int choice = readInt("Выбор: ");
        MainMenuOption option = static_cast<MainMenuOption>(choice);

        switch (option) {
            case MainMenuOption::EncryptDecryptText: handleText(plugins); break;
            case MainMenuOption::EncryptDecryptFile: handleFile(plugins); break;
            case MainMenuOption::KeyGenerator:       handleKeyGenerator(plugins); break;
            case MainMenuOption::ShowKeyInfo:        handleShowKeyInfo(plugins); break;
            case MainMenuOption::Exit:
                std::cout << "Завершение работы." << std::endl;
                running = false;
                break;
            default:
                std::cerr << "Неверный пункт меню." << std::endl;
                break;
        }
    }
}
```

---

## src/main.cpp

```cpp
#include "libraryLoader.h"
#include "menu.h"
#include "utils.h"
#include <iostream>
#include <clocale>
#include <exception>

int main() {
    setlocale(LC_ALL, "");

    try {
        const std::string appPassword = "qqww2233";

        if (!login(appPassword)) {
            std::cerr << "Программа завершает работу." << std::endl;
            return 1;
        }

        std::cout << "\nЗагрузка плагинов..." << std::endl;
        std::vector<CryptoPlugin> plugins = loadAllPlugins("plugins");
        std::cout << "Всего загружено: " << plugins.size() << std::endl;

        runMainMenu(plugins);

        unloadAllPlugins(plugins);

    } catch (const std::bad_alloc&) {
        std::cerr << "\nКРИТИЧЕСКАЯ ОШИБКА: недостаточно оперативной памяти." << std::endl;
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "\nКРИТИЧЕСКАЯ ОШИБКА: " << e.what() << std::endl;
        return 3;
    } catch (...) {
        std::cerr << "\nНеизвестная критическая ошибка." << std::endl;
        return 4;
    }

    return 0;
}
```

---

## plugins/xorCipher.cpp

```cpp
// Плагин: симметричное шифрование XOR (гаммирование)

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
```

---

## plugins/rsaCipher.cpp

```cpp
// Плагин: RSA (асимметричный шифр)
// Формат ключа: "n,e" для шифрования, "n,d" для дешифрования

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

namespace {

uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) { uint64_t t = b; b = a % b; a = t; }
    return a;
}

uint64_t binMod(uint64_t base, uint64_t power, uint64_t modulo) {
    base %= modulo;
    if (modulo > 1) power %= modulo - 1;
    uint64_t result = 1;
    while (power > 0) {
        if (power & 1) result = (result * base) % modulo;
        base = (base * base) % modulo;
        power >>= 1;
    }
    return result;
}

uint64_t modNegative(uint64_t base, uint64_t modulo) {
    base = base % modulo;
    uint64_t m0 = modulo;
    int64_t u1 = 0, u2 = 1, u3;
    uint64_t q = modulo / base;
    uint64_t r = modulo % base;
    uint64_t r0;
    while (r > 0) {
        r0 = r;
        u3 = u1 - u2 * q;
        modulo = base; base = r;
        u1 = u2; u2 = u3;
        q = modulo / base;
        r = modulo % base;
    }
    if (r0 != 1) return 0;
    return (u3 > 0) ? u3 : u3 + m0;
}

bool millerRabinTest(uint64_t n, uint64_t a) {
    if (n % a == 0) return n == a;
    uint64_t d = n - 1; int r = 0;
    while ((d & 1) == 0) { d >>= 1; r++; }
    uint64_t x = binMod(a, d, n);
    if (x == 1 || x == n - 1) return true;
    for (int i = 0; i < r - 1; ++i) {
        x = (x * x) % n;
        if (x == n - 1) return true;
    }
    return false;
}

bool isPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;
    uint64_t witnesses[] = {2, 3, 5, 7, 11, 13};
    for (uint64_t a : witnesses) {
        if (a >= n) break;
        if (!millerRabinTest(n, a)) return false;
    }
    return true;
}

uint64_t rand32() {
    uint64_t r = 0;
    for (int i = 0; i < 2; ++i) r = (r << 16) | (static_cast<uint64_t>(rand()) & 0xFFFF);
    return r;
}

uint64_t generatePrime(int bits) {
    if (bits < 8) bits = 8;
    if (bits > 16) bits = 16;
    uint64_t low  = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;
    while (true) {
        uint64_t range = high - low + 1;
        uint64_t c = low + (rand32() % range);
        if (c % 2 == 0) c |= 1;
        if (c <= high && isPrime(c)) return c;
    }
}

bool parseKey(const uint8_t* key, size_t keySize, uint64_t& n, uint64_t& exp) {
    char buf[64] = {0};
    if (keySize >= sizeof(buf)) return false;
    memcpy(buf, key, keySize);
    char* comma = strchr(buf, ',');
    if (!comma) return false;
    *comma = '\0';
    n = strtoull(buf, nullptr, 10);
    exp = strtoull(comma + 1, nullptr, 10);
    return n > 0 && exp > 0;
}

}

extern "C" {

EXPORT const char* getAlgorithmName() { return "RSA"; }

EXPORT const char* getKeyInfo() {
    return "Асимметричный шифр.\n"
           "Шифрование: \"n,e\" (открытый ключ).\n"
           "Дешифрование: \"n,d\" (закрытый ключ).\n"
           "Каждый байт шифруется в 4 байта.";
}

EXPORT size_t getMinKeySize() { return 3; }
EXPORT size_t getMaxKeySize() { return 64; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;
    uint64_t n = 0, e = 0;
    if (!parseKey(key, keySize, n, e)) return -2;
    if (n <= 255) return -4;
    if (*outputSize < dataSize * 4) return -3;

    for (size_t i = 0; i < dataSize; ++i) {
        uint64_t c = binMod(data[i], e, n);
        for (int b = 3; b >= 0; --b) {
            output[i * 4 + (3 - b)] = static_cast<uint8_t>((c >> (b * 8)) & 0xFF);
        }
    }
    *outputSize = dataSize * 4;
    return 0;
}

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;
    if (dataSize % 4 != 0) return -5;
    uint64_t n = 0, d = 0;
    if (!parseKey(key, keySize, n, d)) return -2;

    size_t outCount = dataSize / 4;
    if (*outputSize < outCount) return -3;

    for (size_t i = 0; i < outCount; ++i) {
        uint64_t c = 0;
        for (int b = 0; b < 4; ++b) c = (c << 8) | data[i * 4 + b];
        output[i] = static_cast<uint8_t>(binMod(c, d, n) & 0xFF);
    }
    *outputSize = outCount;
    return 0;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    srand(static_cast<unsigned>(time(nullptr)));

    int bits = (param >= 8 && param <= 16) ? param : 14;
    uint64_t p = generatePrime(bits);
    uint64_t q;
    do { q = generatePrime(bits); } while (q == p);

    uint64_t n = p * q;
    if (n <= 255) return -10;
    uint64_t phi = (p - 1) * (q - 1);

    uint64_t e = 17;
    if (e >= phi || gcd(e, phi) != 1) {
        e = 3;
        while (e < phi && gcd(e, phi) != 1) e += 2;
    }

    uint64_t d = modNegative(e, phi);
    if (d == 0) return -11;

    char buf[128];
    int w = snprintf(buf, sizeof(buf), "PUB:%llu,%llu PRIV:%llu,%llu",
                     (unsigned long long)n, (unsigned long long)e,
                     (unsigned long long)n, (unsigned long long)d);
    if (w < 0 || static_cast<size_t>(w) >= *keyBufferSize) return -3;
    memcpy(keyBuffer, buf, w);
    *keyBufferSize = static_cast<size_t>(w);
    return 0;
}

}
```

---

## plugins/rabinCipher.cpp

```cpp
// ============================================================
// Реализация криптосистемы Рабина для системы шифрования.
// ============================================================
// Алгоритм основан на сложности задачи факторизации числа n = p*q,
// где p, q — большие простые числа, удовлетворяющие условию p ≡ q ≡ 3 (mod 4).
//
// Шифрование: c = m^2 mod n (возведение в квадрат по модулю n).
// Дешифрование: нахождение квадратного корня из c по модулю n
// с использованием знания множителей p и q (китайская теорема об остатках).
//
// Для устранения неоднозначности (дешифрование даёт 4 корня)
// используется padding: каждый байт m дублируется в виде m' = (m << 8) | m.
// Это позволяет однозначно выбрать правильный корень из четырёх.
// ============================================================

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>

#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

using namespace std;

// ============================================================
// РАЗДЕЛ 1: Базовые криптоматематические функции (cryptoUtils)
// ============================================================

uint64_t gcd(uint64_t a, uint64_t b)
{
    while (b != 0)
    {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t binMod(uint64_t base, uint64_t power, uint64_t modulo) {
    base %= modulo;
    power %= modulo - 1;
    uint64_t result = 1;

    while (power > 0) {
        if (power & 1) {result = (result * base) % modulo;}

        base = (base * base) % modulo;
        power >>= 1;
    }
    return result;
}

uint64_t modNegative(uint64_t base, uint64_t modulo) {
    base = base % modulo;

    uint64_t m0 = modulo;
    int64_t u1 = 0, u2 = 1, u3;

    uint64_t q = modulo / base;
    uint64_t r = modulo % base;
    uint64_t r0;

    while (r > 0) {
        r0 = r;
        u3 = u1 - u2 * q;

        modulo = base; base = r;
        u1 = u2; u2 = u3;

        q = modulo / base;
        r = modulo % base;
    }

    if (r0 != 1) {
        return 0;
    }

    uint64_t result = (u3 > 0)? u3 : u3 + m0;

    return result;
}

// ============================================================
// РАЗДЕЛ 2: Вспомогательные структуры и типы
// ============================================================

struct KeyPair {
    std::string openKey;
    std::string privateKey;
};

// ============================================================
// РАЗДЕЛ 3: Тест простоты и генерация простых чисел
// ============================================================

static bool millerRabinTest(uint64_t n, uint64_t a) {
    if (n % a == 0) return n == a;

    uint64_t d = n - 1;
    int r = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        r++;
    }

    uint64_t x = binMod(a, d, n);

    if (x == 1 || x == n - 1) return true;

    for (int i = 0; i < r - 1; ++i) {
        x = (x * x) % n;
        if (x == n - 1) return true;
    }

    return false;
}

static bool isPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;

    uint64_t witnesses[] = {2, 3, 5, 7, 11, 13};

    for (uint64_t a : witnesses) {
        if (a >= n) break;
        if (!millerRabinTest(n, a)) return false;
    }

    return true;
}

static uint64_t rand32() {
    uint64_t r = 0;
    for (int i = 0; i < 2; ++i) {
        r = (r << 16) | (static_cast<uint64_t>(rand()) & 0xFFFF);
    }
    return r;
}

uint64_t generatePrime(int bits) {
    if (bits < 4) bits = 4;
    if (bits > 30) bits = 30;

    uint64_t low  = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;

    while (true) {
        uint64_t range = high - low + 1;
        uint64_t candidate = low + (rand32() % range);
        if (candidate % 2 == 0) candidate |= 1;

        if (candidate <= high && isPrime(candidate)) {
            return candidate;
        }
    }
}

// ============================================================
// РАЗДЕЛ 4: Основные функции криптосистемы Рабина
// ============================================================

bool parseRabinKey(const std::string& keyString, uint64_t& n, uint64_t& e) {
    size_t pos = keyString.find('|');

    if (pos == std::string::npos) {
        return false;
    }

    if (pos == 0 || pos == keyString.length() - 1) {
        return false;
    }

    try {
        std::string pString = keyString.substr(0, pos);
        std::string qString = keyString.substr(pos + 1);

        n = std::stoull(pString);
        e = std::stoull(qString);

        return (n > 1 && e > 1);

    } catch (const std::exception&) {
        return false;
    }
}

uint64_t sqrtModPrime(uint64_t a, uint64_t p) {
    if (a % p == 0) return 0;
    return binMod(a, (p + 1) / 4, p);
}

uint64_t generatePrimeRubin(int bits) {
    while (true) {
        uint64_t candidate = generatePrime(bits);
        if (candidate % 4 == 3) {
            return candidate;
        }
    }
}

KeyPair keyGeneration() {
    KeyPair keys;

    uint64_t p = generatePrimeRubin(16);
    uint64_t q = generatePrimeRubin(16);

    while (p == q) {
        q = generatePrimeRubin(16);
    }

    uint64_t n = p * q;

    keys.openKey = to_string(n);
    keys.privateKey = to_string(p) + '|' + to_string(q);

    return keys;
}

bool checkRabinPadding(uint64_t value, uint64_t& originalChar) {
    if (value > 0xFFFF) {
        return false;
    }

    uint64_t highByte = (value >> 8) & 0xFF;
    uint64_t lowByte = value & 0xFF;

    if (highByte != lowByte) {
        return false;
    }

    originalChar = lowByte;
    return true;
}

vector<uint64_t> encryptRabin(const std::string& text, KeyPair keys) {
    vector<uint64_t> cipherText;

    uint64_t n = stoull(keys.openKey);

    for (size_t i = 0; i < text.size(); i++) {
        uint64_t m = static_cast<unsigned char>(text[i]);

        uint64_t m_padded = (m << 8) | m;

        uint64_t c = binMod(m_padded, 2, n);

        cipherText.push_back(c);
    }

    return cipherText;
}

string decryption(const vector<uint64_t>& cipherText, KeyPair keys) {
    string plaintext;

    uint64_t p, q;
    uint64_t n = stoull(keys.openKey);
    parseRabinKey(keys.privateKey, p, q);

    uint64_t yp = modNegative(p, q);
    uint64_t yq = modNegative(q, p);

    for (size_t i = 0; i < cipherText.size(); i++) {
        uint64_t c = cipherText[i];

        uint64_t mp = sqrtModPrime(c, p);
        uint64_t mq = sqrtModPrime(c, q);

        uint64_t term1 = ((yp * p) % n * mq) % n;
        uint64_t term2 = ((yq * q) % n * mp) % n;

        uint64_t r1 = (term1 + term2) % n;

        uint64_t r2 = (r1 == 0) ? 0 : n - r1;

        uint64_t r3;
        if (term1 >= term2) {
            r3 = term1 - term2;
        } else {
            r3 = n - (term2 - term1);
        }

        uint64_t r4 = (r3 == 0) ? 0 : n - r3;

        uint64_t decrypted = 0;
        bool found = false;

        if (checkRabinPadding(r1, decrypted)) {
            found = true;
        }
        else if (checkRabinPadding(r2, decrypted)) {
            found = true;
        }
        else if (checkRabinPadding(r3, decrypted)) {
            found = true;
        }
        else if (checkRabinPadding(r4, decrypted)) {
            found = true;
        }

        if (!found) {
            throw runtime_error("Rabin decryption failed: no root passes padding check");
        }

        plaintext.push_back(static_cast<char>(decrypted));
    }

    return plaintext;
}

// ============================================================
// РАЗДЕЛ 5: Обёртки для унифицированного C-интерфейса плагина
// ============================================================

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Rabin (асимметричный шифр с padding)";
}

EXPORT const char* getKeyInfo() {
    return "Шифрование: \"n\" (n = p*q, p≡q≡3 mod 4).\n"
           "Дешифрование: \"p|q\" (через символ '|').\n"
           "Padding: m_padded = (m << 8) | m для однозначного выбора корня.\n"
           "Каждый исходный байт шифруется в 8 байт (uint64_t).\n"
           "Используются 16-битные простые числа Блюма.";
}

EXPORT size_t getMinKeySize() { return 1; }
EXPORT size_t getMaxKeySize() { return 64; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    if (*outputSize < dataSize * 8) return -3;

    try {
        KeyPair keys;
        keys.openKey = std::string(reinterpret_cast<const char*>(key), keySize);

        try {
            uint64_t n = std::stoull(keys.openKey);
            if (n <= 0xFFFF) return -4;
        } catch (...) {
            return -2;
        }

        std::string text(reinterpret_cast<const char*>(data), dataSize);

        std::vector<uint64_t> cipher = encryptRabin(text, keys);

        for (size_t i = 0; i < cipher.size(); ++i) {
            uint64_t c = cipher[i];
            for (int b = 7; b >= 0; --b) {
                output[i * 8 + (7 - b)] = static_cast<uint8_t>((c >> (b * 8)) & 0xFF);
            }
        }
        *outputSize = cipher.size() * 8;
        return 0;

    } catch (const std::exception&) {
        return -2;
    }
}

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    if (dataSize % 8 != 0) return -5;

    try {
        KeyPair keys;
        keys.privateKey = std::string(reinterpret_cast<const char*>(key), keySize);

        uint64_t p = 0, q = 0;
        if (!parseRabinKey(keys.privateKey, p, q)) return -2;

        uint64_t n = p * q;
        keys.openKey = std::to_string(n);

        size_t outCount = dataSize / 8;
        if (*outputSize < outCount) return -3;

        std::vector<uint64_t> cipher(outCount);
        for (size_t i = 0; i < outCount; ++i) {
            uint64_t c = 0;
            for (int b = 0; b < 8; ++b) {
                c = (c << 8) | data[i * 8 + b];
            }
            cipher[i] = c;
        }

        std::string plaintext = decryption(cipher, keys);

        std::memcpy(output, plaintext.data(), plaintext.size());
        *outputSize = plaintext.size();
        return 0;

    } catch (const std::exception&) {
        return -2;
    }
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    (void)param;

    srand(static_cast<unsigned>(time(nullptr)));

    try {
        KeyPair keys = keyGeneration();

        std::string output = "PUB:" + keys.openKey + " PRIV:" + keys.privateKey;

        if (output.size() >= *keyBufferSize) return -3;

        std::memcpy(keyBuffer, output.data(), output.size());
        *keyBufferSize = output.size();
        return 0;

    } catch (const std::exception&) {
        return -10;
    }
}

} // extern "C"
```

---

## plugins/shamirCipher.cpp

```cpp
// ============================================================
// Реализация бесключевого протокола Шамира для системы шифрования.
// ============================================================
// Протокол Шамира — это трёхпроходный протокол, позволяющий передать
// сообщение между двумя сторонами (Алиса и Боб) без обмена ключами.
//
// Принцип работы:
// 1. Обе стороны договариваются о большом простом числе p.
// 2. Каждая сторона выбирает секретную пару (C, D), где C*D ≡ 1 (mod p-1).
// 3. Шифрование: c = m^C mod p (возведение в степень по модулю).
// 4. Дешифрование: m = c^D mod p (обратное возведение).
//
// В данном плагине реализован «один шаг» протокола:
// - шифрование с ключом (p, C)
// - дешифрование с ключом (p, D)
// Полный трёхпроходный протокол требует двух сторон;
// для учебной демонстрации используем одну пару (C, D).
//
// Формат ключей:
//   Шифрование:  "p,C" — простое число p и экспонента C
//   Дешифрование: "p,D" — простое число p и экспонента D (C*D ≡ 1 mod p-1)
// ============================================================

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>

#include <string>
#include <vector>
#include <stdexcept>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

using namespace std;

// ============================================================
// РАЗДЕЛ 1: Базовые криптоматематические функции (cryptoUtils)
// ============================================================

uint64_t gcd(uint64_t a, uint64_t b)
{
    while (b != 0)
    {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t binMod(uint64_t base, uint64_t power, uint64_t modulo) {
    base %= modulo;

    power %= modulo - 1;

    uint64_t result = 1;

    while (power > 0) {
        if (power & 1) {
            result = (result * base) % modulo;
        }

        base = (base * base) % modulo;

        power >>= 1;
    }

    return result;
}

uint64_t modNegative(uint64_t base, uint64_t modulo) {
    base = base % modulo;

    uint64_t m0 = modulo;

    int64_t u1 = 0, u2 = 1, u3;

    uint64_t q = modulo / base;
    uint64_t r = modulo % base;
    uint64_t r0;

    while (r > 0) {
        r0 = r;

        u3 = u1 - u2 * q;

        modulo = base;
        base = r;

        u1 = u2;
        u2 = u3;

        q = modulo / base;
        r = modulo % base;
    }

    if (r0 != 1) {
        return 0;
    }

    uint64_t result = (u3 > 0) ? u3 : u3 + m0;

    return result;
}

// ============================================================
// РАЗДЕЛ 2: Тест простоты и генерация простых чисел
// ============================================================

static bool millerRabinTest(uint64_t n, uint64_t a) {
    if (n % a == 0) return n == a;

    uint64_t d = n - 1;
    int r = 0;

    while ((d & 1) == 0) {
        d >>= 1;
        r++;
    }

    uint64_t x = binMod(a, d, n);

    if (x == 1 || x == n - 1) return true;

    for (int i = 0; i < r - 1; ++i) {
        x = (x * x) % n;

        if (x == n - 1) return true;
    }

    return false;
}

static bool isPrime(uint64_t n) {
    if (n < 2) return false;

    if (n < 4) return true;

    if (n % 2 == 0) return false;

    uint64_t witnesses[] = {2, 3, 5, 7, 11, 13};

    for (uint64_t a : witnesses) {
        if (a >= n) break;

        if (!millerRabinTest(n, a)) return false;
    }

    return true;
}

static uint64_t rand32() {
    uint64_t r = 0;

    for (int i = 0; i < 2; ++i) {
        r = (r << 16) | (static_cast<uint64_t>(rand()) & 0xFFFF);
    }

    return r;
}

static uint64_t randomPrime(int bits) {
    if (bits < 10) bits = 10;
    if (bits > 30) bits = 30;

    uint64_t low  = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;

    if (low <= 256) low = 257;

    while (true) {
        uint64_t range = high - low + 1;
        uint64_t candidate = low + (rand32() % range);

        if (candidate % 2 == 0) candidate |= 1;

        if (candidate <= high && isPrime(candidate)) {
            return candidate;
        }
    }
}

// ============================================================
// РАЗДЕЛ 3: Вспомогательные функции протокола Шамира
// ============================================================

static bool parsePair(const uint8_t* key, size_t keySize, uint64_t& p, uint64_t& exp) {
    char buf[64] = {0};

    if (keySize >= sizeof(buf)) return false;

    memcpy(buf, key, keySize);

    char* comma = strchr(buf, ',');

    if (!comma) return false;

    *comma = '\0';

    p   = strtoull(buf, nullptr, 10);

    exp = strtoull(comma + 1, nullptr, 10);

    return p > 0 && exp > 0;
}

// ============================================================
// РАЗДЕЛ 4: Обёртки для унифицированного C-интерфейса плагина
// ============================================================

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Shamir (бесключевой протокол)";
}

EXPORT const char* getKeyInfo() {
    return "Простое p (p > 255) — общий параметр протокола.\n"
           "Шифрование: \"p,C\" — c = m^C mod p.\n"
           "Дешифрование: \"p,D\" — m = c^D mod p, где C*D ≡ 1 (mod p-1).\n"
           "Базовые функции: binMod() для возведения в степень,\n"
           "modNegative() для вычисления D = C^(-1) mod (p-1).\n"
           "При генерации param = битность p (10-30, рекомендуется 28).";
}

EXPORT size_t getMinKeySize() { return 3; }

EXPORT size_t getMaxKeySize() { return 128; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    uint64_t p = 0, C = 0;
    if (!parsePair(key, keySize, p, C)) return -2;

    if (p <= 255) return -4;

    if (*outputSize < dataSize * 8) return -3;

    for (size_t i = 0; i < dataSize; ++i) {
        uint64_t m = data[i];

        uint64_t c = binMod(m, C, p);

        for (int b = 7; b >= 0; --b) {
            output[i * 8 + (7 - b)] = static_cast<uint8_t>((c >> (b * 8)) & 0xFF);
        }
    }

    *outputSize = dataSize * 8;

    return 0;
}

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    if (dataSize % 8 != 0) return -5;

    uint64_t p = 0, D = 0;
    if (!parsePair(key, keySize, p, D)) return -2;

    size_t outCount = dataSize / 8;

    if (*outputSize < outCount) return -3;

    for (size_t i = 0; i < outCount; ++i) {
        uint64_t c = 0;
        for (int b = 0; b < 8; ++b) {
            c = (c << 8) | data[i * 8 + b];
        }

        uint64_t m = binMod(c, D, p);

        output[i] = static_cast<uint8_t>(m & 0xFF);
    }

    *outputSize = outCount;

    return 0;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;

    srand(static_cast<unsigned>(time(nullptr)));

    int bits = (param >= 10 && param <= 30) ? param : 28;

    uint64_t p = randomPrime(bits);

    uint64_t phi = p - 1;

    uint64_t C = 0;
    uint64_t start = phi / 2;

    if ((start & 1) == 0) start++;

    for (uint64_t cand = start; cand < phi; cand += 2) {
        if (gcd(cand, phi) == 1) {
            C = cand;
            break;
        }
    }

    if (C == 0) {
        for (uint64_t cand = 3; cand < phi; cand += 2) {
            if (gcd(cand, phi) == 1) {
                C = cand;
                break;
            }
        }
    }

    if (C == 0) return -11;

    uint64_t D = modNegative(C, phi);

    if (D == 0) return -11;

    char buf[128];
    int w = snprintf(buf, sizeof(buf), "ENC:%llu,%llu DEC:%llu,%llu",
                     (unsigned long long)p, (unsigned long long)C,
                     (unsigned long long)p, (unsigned long long)D);

    if (w < 0 || static_cast<size_t>(w) >= *keyBufferSize) return -3;

    memcpy(keyBuffer, buf, w);

    *keyBufferSize = static_cast<size_t>(w);

    return 0;
}

} // extern "C"
// ============================================================
// Конец файла shamirCipher.cpp
// ============================================================
```

---

## plugins/fiatShamirAuth.cpp

```cpp
// Плагин: протокол Фиат-Шамир (доказательство с нулевым разглашением).
// Адаптирован под обычный интерфейс шифр/дешифр:
//   encrypt(message, private_key) → доказательство в виде байт
//   decrypt(proof,   public_key)  → "VERIFIED" или "FAILED"

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>
#include <sstream>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

using namespace std;

static const int FIAT_SHAMIR_ROUNDS = 20;

namespace {

uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) { uint64_t t = b; b = a % b; a = t; }
    return a;
}

uint64_t binMod(uint64_t base, uint64_t power, uint64_t modulo) {
    base %= modulo;
    if (modulo > 1) power %= modulo - 1;
    uint64_t result = 1;
    while (power > 0) {
        if (power & 1) result = (result * base) % modulo;
        base = (base * base) % modulo;
        power >>= 1;
    }
    return result;
}

bool millerRabinTest(uint64_t n, uint64_t a) {
    if (n % a == 0) return n == a;
    uint64_t d = n - 1; int r = 0;
    while ((d & 1) == 0) { d >>= 1; r++; }
    uint64_t x = binMod(a, d, n);
    if (x == 1 || x == n - 1) return true;
    for (int i = 0; i < r - 1; ++i) {
        x = (x * x) % n;
        if (x == n - 1) return true;
    }
    return false;
}

bool isPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;
    uint64_t witnesses[] = {2, 3, 5, 7, 11, 13};
    for (uint64_t a : witnesses) {
        if (a >= n) break;
        if (!millerRabinTest(n, a)) return false;
    }
    return true;
}

uint64_t rand32() {
    uint64_t r = 0;
    for (int i = 0; i < 2; ++i) r = (r << 16) | (static_cast<uint64_t>(rand()) & 0xFFFF);
    return r;
}

uint64_t generatePrime(int bits) {
    if (bits < 8) bits = 8;
    if (bits > 16) bits = 16;
    uint64_t low  = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;
    while (true) {
        uint64_t range = high - low + 1;
        uint64_t c = low + (rand32() % range);
        if (c % 2 == 0) c |= 1;
        if (c <= high && isPrime(c)) return c;
    }
}

bool parseKey(const uint8_t* key, size_t keySize, uint64_t& a, uint64_t& b) {
    char buf[64] = {0};
    if (keySize >= sizeof(buf)) return false;
    memcpy(buf, key, keySize);
    char* comma = strchr(buf, ',');
    if (!comma) return false;
    *comma = '\0';
    a = strtoull(buf, nullptr, 10);
    b = strtoull(comma + 1, nullptr, 10);
    return a > 1 && b > 0;
}

int hashToBit(uint64_t x, int round) {
    uint64_t h = 0xCAFEBABE;
    h = h * 31 + x;
    h = h * 31 + static_cast<uint64_t>(round);
    return static_cast<int>(h & 1);
}

}

extern "C" {

EXPORT const char* getAlgorithmName() { return "Fiat-Shamir (доказательство знания секрета)"; }

EXPORT const char* getKeyInfo() {
    return "Протокол доказательства с нулевым разглашением (ZKP).\n"
           "\n"
           "В отличие от обычных шифров, Fiat-Shamir НЕ скрывает сообщение,\n"
           "а позволяет доказать знание секрета без его раскрытия.\n"
           "\n"
           "СЦЕНАРИЙ работы через стандартное меню:\n"
           "\n"
           "1. Генерация ключей (пункт 3 главного меню):\n"
           "     Получите пару: PUB:n,V и PRIV:n,S\n"
           "\n"
           "2. \"Шифрование\" текста (пункт 1, режим 1):\n"
           "     Введите любое сообщение и закрытый ключ \"n,S\".\n"
           "     Результат (hex) — это ваше ДОКАЗАТЕЛЬСТВО знания S.\n"
           "     Передайте его проверяющей стороне.\n"
           "\n"
           "3. \"Дешифрование\" доказательства (пункт 1, режим 2):\n"
           "     Введите доказательство (hex) и открытый ключ \"n,V\".\n"
           "     Результат: VERIFIED или FAILED\n"
           "\n"
           "Шифрование (создание доказательства): ключ \"n,S\".\n"
           "Дешифрование (проверка):              ключ \"n,V\".";
}

EXPORT size_t getMinKeySize() { return 3; }
EXPORT size_t getMaxKeySize() { return 128; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;
    (void)data; (void)dataSize;

    uint64_t n = 0, S = 0;
    if (!parseKey(key, keySize, n, S)) return -2;
    if (S == 0 || S >= n) return -4;

    uint64_t V = (S * S) % n;
    srand(static_cast<unsigned>(time(nullptr)));

    std::ostringstream proof;
    proof << "FS|" << n << "|" << V;

    for (int round = 0; round < FIAT_SHAMIR_ROUNDS; ++round) {
        uint64_t r = 2 + (rand32() % (n - 3));
        uint64_t x = (r * r) % n;
        int e = hashToBit(x, round);
        uint64_t y = (e == 0) ? r : (r * S) % n;
        proof << "|" << x << "," << y;
    }

    std::string s = proof.str();
    if (s.size() >= *outputSize) return -3;
    memcpy(output, s.data(), s.size());
    *outputSize = s.size();
    return 0;
}

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    uint64_t n = 0, V = 0;
    if (!parseKey(key, keySize, n, V)) return -2;

    std::string proofStr(reinterpret_cast<const char*>(data), dataSize);

    auto writeResult = [&](const std::string& s) -> int {
        if (s.size() >= *outputSize) return -3;
        memcpy(output, s.data(), s.size());
        *outputSize = s.size();
        return 0;
    };

    if (proofStr.substr(0, 3) != "FS|") {
        return writeResult("FAILED: неверный формат доказательства");
    }

    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos < proofStr.size()) {
        size_t next = proofStr.find('|', pos);
        if (next == std::string::npos) {
            parts.push_back(proofStr.substr(pos));
            break;
        }
        parts.push_back(proofStr.substr(pos, next - pos));
        pos = next + 1;
    }

    if (parts.size() < 4) return writeResult("FAILED: доказательство неполное");

    uint64_t nProof = strtoull(parts[1].c_str(), nullptr, 10);
    uint64_t VProof = strtoull(parts[2].c_str(), nullptr, 10);

    if (nProof != n || VProof != V) {
        return writeResult("FAILED: ключ не соответствует доказательству");
    }

    int numRounds = static_cast<int>(parts.size()) - 3;
    int passed = 0;

    for (int round = 0; round < numRounds; ++round) {
        const std::string& rd = parts[3 + round];
        size_t comma = rd.find(',');
        if (comma == std::string::npos) break;

        uint64_t x = strtoull(rd.substr(0, comma).c_str(), nullptr, 10);
        uint64_t y = strtoull(rd.substr(comma + 1).c_str(), nullptr, 10);

        int e = hashToBit(x, round);
        uint64_t left = (y * y) % n;
        uint64_t right = (e == 0) ? x : (x * V) % n;
        if (left == right) passed++;
    }

    std::ostringstream result;
    if (passed == numRounds) {
        result << "VERIFIED: доказательство верно ("
               << passed << "/" << numRounds << " раундов)";
    } else {
        result << "FAILED: доказательство неверно ("
               << passed << "/" << numRounds << " раундов)";
    }
    return writeResult(result.str());
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    (void)param;
    srand(static_cast<unsigned>(time(nullptr)));

    uint64_t p = generatePrime(14);
    uint64_t q;
    do { q = generatePrime(14); } while (q == p);
    uint64_t n = p * q;

    uint64_t S = 0;
    for (int i = 0; i < 100; ++i) {
        uint64_t c = 2 + (rand32() % (n - 3));
        if (gcd(c, n) == 1) { S = c; break; }
    }
    if (S == 0) return -10;

    uint64_t V = (S * S) % n;

    char buf[256];
    int w = snprintf(buf, sizeof(buf),
                     "PUB:%llu,%llu PRIV:%llu,%llu",
                     (unsigned long long)n, (unsigned long long)V,
                     (unsigned long long)n, (unsigned long long)S);
    if (w < 0 || static_cast<size_t>(w) >= *keyBufferSize) return -3;
    memcpy(keyBuffer, buf, w);
    *keyBufferSize = static_cast<size_t>(w);
    return 0;
}

}
```

---

## plugins/diffieHellmanKE.cpp

```cpp
// Плагин: протокол Диффи-Хеллмана
// Работает ТОЛЬКО через генератор ключей.
// Шифрование/дешифрование не поддерживаются (это не шифр, а протокол обмена ключами).

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <string>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

namespace {

uint64_t binMod(uint64_t base, uint64_t power, uint64_t modulo) {
    base %= modulo;
    if (modulo > 1) power %= modulo - 1;
    uint64_t result = 1;
    while (power > 0) {
        if (power & 1) result = (result * base) % modulo;
        base = (base * base) % modulo;
        power >>= 1;
    }
    return result;
}

bool millerRabinTest(uint64_t n, uint64_t a) {
    if (n % a == 0) return n == a;
    uint64_t d = n - 1; int r = 0;
    while ((d & 1) == 0) { d >>= 1; r++; }
    uint64_t x = binMod(a, d, n);
    if (x == 1 || x == n - 1) return true;
    for (int i = 0; i < r - 1; ++i) {
        x = (x * x) % n;
        if (x == n - 1) return true;
    }
    return false;
}

bool isPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;
    uint64_t witnesses[] = {2, 3, 5, 7, 11, 13};
    for (uint64_t a : witnesses) {
        if (a >= n) break;
        if (!millerRabinTest(n, a)) return false;
    }
    return true;
}

uint64_t rand32() {
    uint64_t r = 0;
    for (int i = 0; i < 2; ++i) r = (r << 16) | (static_cast<uint64_t>(rand()) & 0xFFFF);
    return r;
}

uint64_t generateSafePrime(int bits) {
    if (bits < 10) bits = 10;
    if (bits > 24) bits = 24;
    uint64_t low  = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;
    while (true) {
        uint64_t range = high - low + 1;
        uint64_t c = low + (rand32() % range);
        if (c % 4 != 3) c += (3 - c % 4 + 4) % 4;
        if (c > high) continue;
        if (isPrime(c) && isPrime((c - 1) / 2)) return c;
    }
}

uint64_t findGenerator(uint64_t p) {
    uint64_t q = (p - 1) / 2;
    for (uint64_t g = 2; g < p; ++g) {
        if (binMod(g, 2, p) == 1) continue;
        if (binMod(g, q, p) == 1) continue;
        return g;
    }
    return 2;
}

bool parsePrivateKey(const std::string& s, uint64_t& p, uint64_t& g, uint64_t& a) {
    size_t c1 = s.find(',');
    if (c1 == std::string::npos) return false;
    size_t c2 = s.find(',', c1 + 1);
    if (c2 == std::string::npos) return false;
    try {
        p = std::stoull(s.substr(0, c1));
        g = std::stoull(s.substr(c1 + 1, c2 - c1 - 1));
        a = std::stoull(s.substr(c2 + 1));
        return p > 1 && g > 1 && a > 0;
    } catch (...) { return false; }
}

} // namespace

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Diffie-Hellman (обмен ключами)";
}

EXPORT const char* getKeyInfo() {
    return "Протокол согласования общего секретного ключа.\n"
           "\n"
           "Этот алгоритм НЕ шифрует данные.\n"
           "Работает ТОЛЬКО через пункт меню \"Генератор ключей\".\n"
           "\n"
           "Параметр генерации:\n"
           "  0 — сгенерировать свою пару (PUBLIC + PRIVATE)\n"
           "  1 — вычислить общий ключ (нужно ввести публичное значение\n"
           "      партнёра и свой закрытый ключ)\n";
}

EXPORT size_t getMinKeySize() { return 1; }
EXPORT size_t getMaxKeySize() { return 128; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    (void)data; (void)dataSize; (void)key; (void)keySize;
    (void)output; (void)outputSize;
    return -2;
}

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    (void)data; (void)dataSize; (void)key; (void)keySize;
    (void)output; (void)outputSize;
    return -2;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;

    srand(static_cast<unsigned>(time(nullptr)));

    // РЕЖИМ 1: Сгенерировать новую пару
    if (param == 0) {
        int bits = 20;
        uint64_t p = generateSafePrime(bits);
        uint64_t g = findGenerator(p);
        uint64_t a = 2 + (rand32() % (p - 3));
        uint64_t A = binMod(g, a, p);

        char buf[256];
        int w = snprintf(buf, sizeof(buf),
                         "Сгенерирована новая пара ключей:\n"
                         "  PUBLIC (передайте партнёру): %llu\n"
                         "  PRIVATE (сохраните в тайне): %llu,%llu,%llu\n"
                         "\n"
                         "Для вычисления общего ключа выберите этот алгоритм\n"
                         "снова в генераторе с параметром 1.",
                         (unsigned long long)A,
                         (unsigned long long)p, (unsigned long long)g, (unsigned long long)a);

        if (w < 0 || static_cast<size_t>(w) >= *keyBufferSize) return -3;
        memcpy(keyBuffer, buf, w);
        *keyBufferSize = static_cast<size_t>(w);
        return 0;
    }

    // РЕЖИМ 2: Вычислить общий ключ
    std::cout << "\nВведите публичное значение партнёра (число): ";
    std::string partnerStr;
    std::getline(std::cin, partnerStr);

    std::cout << "Введите ваш закрытый ключ (формат \"p,g,a\"): ";
    std::string privateStr;
    std::getline(std::cin, privateStr);

    uint64_t p = 0, g = 0, a = 0;
    if (!parsePrivateKey(privateStr, p, g, a)) {
        const char* err = "Ошибка: неверный формат закрытого ключа (нужно \"p,g,a\")";
        size_t len = strlen(err);
        if (len >= *keyBufferSize) return -3;
        memcpy(keyBuffer, err, len);
        *keyBufferSize = len;
        return 0;
    }

    uint64_t partnerPublic = 0;
    try {
        partnerPublic = std::stoull(partnerStr);
    } catch (...) {
        const char* err = "Ошибка: публичное значение должно быть числом";
        size_t len = strlen(err);
        if (len >= *keyBufferSize) return -3;
        memcpy(keyBuffer, err, len);
        *keyBufferSize = len;
        return 0;
    }

    if (partnerPublic < 2 || partnerPublic >= p) {
        const char* err = "Ошибка: публичное значение должно быть в диапазоне [2, p-1]";
        size_t len = strlen(err);
        if (len >= *keyBufferSize) return -3;
        memcpy(keyBuffer, err, len);
        *keyBufferSize = len;
        return 0;
    }

    uint64_t sharedKey = binMod(partnerPublic, a, p);

    char buf[256];
    int w = snprintf(buf, sizeof(buf),
                     "Общий секретный ключ: %llu\n"
                     "\n"
                     "Этот же ключ получит ваш партнёр, используя ваше\n"
                     "публичное значение и свой закрытый ключ.\n"
                     "Используйте его как ключ для XOR-шифрования.",
                     (unsigned long long)sharedKey);

    if (w < 0 || static_cast<size_t>(w) >= *keyBufferSize) return -3;
    memcpy(keyBuffer, buf, w);
    *keyBufferSize = static_cast<size_t>(w);
    return 0;
}

}
```

---

## Сборка и запуск

```bash
make clean
make
make run
```

Пароль для входа: `qqww2233`

---

## Структура после сборки

```
build/
├── cryptoApp
├── obj/
│   ├── main.o
│   ├── menu.o
│   ├── libraryLoader.o
│   ├── textProcessor.o
│   ├── fileProcessor.o
│   ├── keyGenerator.o
│   └── utils.o
└── plugins/
    ├── xorCipher.so
    ├── rsaCipher.so
    ├── rabinCipher.so
    ├── shamirCipher.so
    ├── fiatShamirAuth.so
    └── diffieHellmanKE.so
```

---

## Сводная таблица плагинов

| Плагин | Назначение | Где работает |
|---|---|---|
| **XOR** | Симметричное шифрование (гаммирование) | Пункты 1, 2, 3 |
| **RSA** | Асимметричное шифрование | Пункты 1, 2, 3 |
| **Rabin** | Асимметричное шифрование на квадратичных вычетах | Пункты 1, 2, 3 |
| **Shamir** | Бесключевой протокол шифрования | Пункты 1, 2, 3 |
| **Fiat-Shamir** | Доказательство знания секрета (ZKP) | Пункты 1 (создание/проверка), 3 |
| **Diffie-Hellman** | Согласование общего ключа | Только пункт 3 |