#include "../include/menu.h"
#include "../include/textProcessor.h"
#include "../include/fileProcessor.h"
#include "../include/keyGenerator.h"
#include "../include/utils.h"
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
        std::cerr << "Неверный выбор." << std::endl;
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
    std::cout << "Формат ключа: " << plugin.getKeyInfo() << std::endl;

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
                if (cipher.empty()) {
                    std::cerr << "Некорректный hex." << std::endl;
                    return;
                }
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
    std::cout << "Формат ключа: " << plugin.getKeyInfo() << std::endl;

    std::string keyStr = readLine("Ключ: ");
    std::vector<uint8_t> key = stringToBytes(keyStr);

    std::string inPath = readLine("Входной файл: ");
    if (!validatePath(inPath)) return;
    if (!fileExists(inPath)) {
        std::cerr << "Файл не найден, создайте файл для дальнейшей работы с ним: " << inPath << std::endl;
        return;
    }

    std::string outPath = readLine("Выходной файл: ");
    if (!validatePath(outPath)) return;

    try {
        switch (action) {
            case CryptoAction::Encrypt:
                encryptFile(plugin, inPath, outPath, key);
                break;
            case CryptoAction::Decrypt:
                decryptFile(plugin, inPath, outPath, key);
                break;
            case CryptoAction::Back:
                break;
        }
    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
    }
}

static void handleKeyGenerator(std::vector<CryptoPlugin>& plugins) {
    int idx = selectPlugin(plugins);
    if (idx < 0) return;

    const CryptoPlugin& plugin = plugins[idx];
    std::cout << "Информация о ключе: " << plugin.getKeyInfo() << std::endl;
    int param = readInt("Параметр генерации (0 - по умолчанию): ");

    try {
        std::vector<uint8_t> key = generateKeyForPlugin(plugin, param);
        std::cout << "Сгенерировано (текст): " << bytesToString(key) << std::endl;
        std::cout << "Сгенерировано (hex):   " << bytesToHex(key) << std::endl;
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
        std::cerr << "Нет плагинов." << std::endl;
        return;
    }

    bool running = true;
    while (running) {
        std::cout << "\n========================================" << std::endl;
        std::cout << "  Sentinel (Часовой): Crypto algorithm" << std::endl;
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
            case MainMenuOption::EncryptDecryptText:
                handleText(plugins);
                break;
            case MainMenuOption::EncryptDecryptFile:
                handleFile(plugins);
                break;
            case MainMenuOption::KeyGenerator:
                handleKeyGenerator(plugins);
                break;
            case MainMenuOption::ShowKeyInfo:
                handleShowKeyInfo(plugins);
                break;
            case MainMenuOption::Exit:
                std::cout << "Завершение." << std::endl;
                running = false;
                break;
            default:
                std::cerr << "Неверный пункт меню." << std::endl;
                break;
        }
    }
}