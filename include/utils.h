#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <cstdint>

bool fileExists(const std::string& path); //проверка существования файла
bool ensureDirectoryExists(const std::string& filePath); //проверка существования директория
bool validatePath(const std::string& path); //проверка валидности пути

std::vector<uint8_t> stringToBytes(const std::string& str);
std::string bytesToString(const std::vector<uint8_t>& data);
std::string bytesToHex(const std::vector<uint8_t>& data);
std::vector<uint8_t> hexToBytes(const std::string& hex);

int readInt(const std::string& prompt);
std::string readLine(const std::string& prompt);

//функция авторизации
bool login(const std::string& expectedPassword);

// Коды ошибок криптографических операций.
// Возвращаются плагинами из функций encrypt/decrypt/generateKey.
enum class CryptoError : int {
    Ok              =   0,   // Успешное выполнение
    NullPointer     =  -1,   // Передан нулевой указатель
    InvalidKey      =  -2,   // Некорректный формат ключа
    BufferTooSmall  =  -3,   // Недостаточный размер буфера
    KeyTooSmall     =  -4,   // Модуль ключа слишком мал
    InvalidDataSize =  -5,   // Некорректный размер входных данных
    KeygenFailed    = -10,   // Ошибка генерации ключа
    NoInverse       = -11    // Не существует модульного обратного
};

// Преобразует код ошибки в понятное пользователю сообщение.
std::string errorToMessage(int code);

#endif