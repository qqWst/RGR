#ifndef AES_CFB_H
#define AES_CFB_H

#include <vector>
#include <string>

// Вспомогательные функции
void AddPKCS7Padding(std::vector<unsigned char>& data, int blockSize = 16);
void RemovePKCS7Padding(std::vector<unsigned char>& data, int blockSize = 16);
void printHex(const unsigned char* data, int len);

// Генерация ключа и вектора инициализации
void generateRandomKey(unsigned char* key);
void GenerateIV(unsigned char* iv);

// Конвертация
void StringToBytes(const std::string& str, std::vector<unsigned char>& bytes);
void BytesToString(const std::vector<unsigned char>& bytes, std::string& str);

// Основные функции шифрования и расшифрования
// Флаг verbose включает пошаговый вывод в консоль (использовать только для коротких текстов)
void EncryptCFB(const std::vector<unsigned char>& textOrig,
                std::vector<unsigned char>& textCript,
                unsigned char* key,
                unsigned char* iv,
                bool verbose = false);

void DecryptCFB(const std::vector<unsigned char>& textCript,
                std::vector<unsigned char>& textOrig,
                unsigned char* key);

#endif // AES_CFB_H