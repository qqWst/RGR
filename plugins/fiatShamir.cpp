// Учебная реализация протокола идентификации Фиата-Шамира.
// Принцип: Сторона A доказывает знание секрета S, не раскрывая его.
// Открытый ключ: v = s^2 mod n (где s - секрет)

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <cmath>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

namespace {

uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) { uint64_t t = b; b = a % b; a = t; }
    return a;
}

bool isPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;
    for (uint64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return false;
    }
    return true;
}

uint64_t randomPrime(uint64_t low, uint64_t high) {
    while (true) {
        uint64_t candidate = low + (rand() % (high - low + 1));
        if (candidate % 2 == 0) candidate++;
        if (candidate <= high && isPrime(candidate)) return candidate;
    }
}

// Разбор ключа 
bool parseKeyPair(const uint8_t* key, size_t keySize, uint64_t& n, uint64_t& value) {
    char buf[128] = {0};
    if (keySize >= sizeof(buf)) return false;
    memcpy(buf, key, keySize);
    buf[keySize] = '\0';

    char* comma = strchr(buf, ',');
    if (!comma) return false;
    *comma = '\0';

    n = static_cast<uint64_t>(strtoull(buf, nullptr, 10));
    value = static_cast<uint64_t>(strtoull(comma + 1, nullptr, 10));
    return (n > 0 && value > 0);
}

// Генерация случайного секрета
uint64_t generateSecret(uint64_t n) {
    // Секрет должен быть взаимно прост с n и < n
    while (true) {
        uint64_t s = 2 + (rand() % (n - 3));
        if (gcd(s, n) == 1) return s;
    }
}

}

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Fiat-Shamir (протокол идентификации)";
}

EXPORT const char* getKeyInfo() {
    return "Формат:\n"
           "  Для верификации (шифрование): \"n,v\"\n"
           "  Для доказательства (дешифрование): \"n,s\"\n"
           "  v = s^2 mod n - открытый ключ\n"
           "Протокол: Доказывающий доказывает знание s, не раскрывая его.\n"
           "При генерации param = битность n (10-16).";
}

EXPORT size_t getMinKeySize() { return 5; }
EXPORT size_t getMaxKeySize() { return 128; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    // В роли шифрования - верификация доказательства
    if (!data || !key || !output || !outputSize) return -1;

    uint64_t n = 0, v = 0;
    if (!parseKeyPair(key, keySize, n, v)) return -2;
    if (n <= 255) return -4;
    
    // Размер выходных данных: для каждого байта входных данных 
    // (r - случайное число, challenge - вызов, response - ответ)
    size_t requiredSize = dataSize * 12; // 3 числа по 4 байта
    if (*outputSize < requiredSize) return -3;

    // Симуляция протокола идентификации
    // Структура выходных данных для каждого байта:
    // [r1, r2, r3, r4, challenge, response1, response2, response3, response4]
    
    for (size_t i = 0; i < dataSize; ++i) {
        uint64_t secretValue = data[i];
        
        // Генерация случайного r (r < n)
        uint64_t r = 1 + (rand() % (n - 1));
        uint64_t x = modPow(r, 2, n);  // x = r^2 mod n
        
        // Сохраняем x и challenge (в реальном протоколе challenge присылает верификатор)
        uint8_t challenge = secretValue % 16; // 4-битный вызов
        
        // Вычисляем ответ: y = r * s^challenge mod n
        uint64_t s = v; // В этом контексте v - это s^2, ищем s
        // Находим s (квадратный корень из v по модулю n)
        // Упрощённо: используем v как есть для демонстрации
        uint64_t s_pow = modPow(secretValue, challenge, n);
        uint64_t response = (r * s_pow) % n;
        
        // Упаковка в выходной буфер
        size_t offset = i * 12;
        output[offset]     = static_cast<uint8_t>((x >> 24) & 0xFF);
        output[offset + 1] = static_cast<uint8_t>((x >> 16) & 0xFF);
        output[offset + 2] = static_cast<uint8_t>((x >> 8) & 0xFF);
        output[offset + 3] = static_cast<uint8_t>(x & 0xFF);
        output[offset + 4] = challenge;
        output[offset + 5] = static_cast<uint8_t>((response >> 24) & 0xFF);
        output[offset + 6] = static_cast<uint8_t>((response >> 16) & 0xFF);
        output[offset + 7] = static_cast<uint8_t>((response >> 8) & 0xFF);
        output[offset + 8] = static_cast<uint8_t>(response & 0xFF);
        output[offset + 9] = static_cast<uint8_t>(secretValue);
        output[offset + 10] = static_cast<uint8_t>((v >> 8) & 0xFF);
        output[offset + 11] = static_cast<uint8_t>(v & 0xFF);
    }
    
    *outputSize = dataSize * 12;
    return 0;
}

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    // В роли дешифрования - проверка доказательства
    if (!data || !key || !output || !outputSize) return -1;
    if (dataSize % 12 != 0) return -5; // Данные должны быть кратны 12 байтам
    
    uint64_t n = 0, s = 0;
    if (!parseKeyPair(key, keySize, n, s)) return -2;
    
    size_t outCount = dataSize / 12;
    if (*outputSize < outCount) return -3;
    
    uint64_t v = modPow(s, 2, n); // Вычисляем открытый ключ из секрета
    
    for (size_t i = 0; i < outCount; ++i) {
        size_t offset = i * 12;
        
        // Извлекаем x
        uint64_t x = (static_cast<uint64_t>(data[offset]) << 24) |
                     (static_cast<uint64_t>(data[offset + 1]) << 16) |
                     (static_cast<uint64_t>(data[offset + 2]) << 8) |
                     static_cast<uint64_t>(data[offset + 3]);
        
        uint8_t challenge = data[offset + 4];
        
        // Извлекаем response
        uint64_t response = (static_cast<uint64_t>(data[offset + 5]) << 24) |
                            (static_cast<uint64_t>(data[offset + 6]) << 16) |
                            (static_cast<uint64_t>(data[offset + 7]) << 8) |
                            static_cast<uint64_t>(data[offset + 8]);
        
        // Верификация
        uint64_t left = modPow(response, 2, n);
        uint64_t right = (x * modPow(v, challenge, n)) % n;
        
        bool verified = (left == right);
        
        // Сохраняем результат верификации и оригинальные данные
        output[i] = verified ? data[offset + 9] : 0;
        
        // Дополнительная информация для диагностики
        if (!verified) {
            printf("Ошибка верификации для байта %zu: x=%llu, challenge=%d, response=%llu\n", 
                   i, (unsigned long long)x, challenge, (unsigned long long)response);
        }
    }
    
    *outputSize = outCount;
    return 0;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    
    srand(static_cast<unsigned>(time(nullptr)));
    
    // Генерация простого числа n = p * q (как в RSA)
    int bits = (param >= 10 && param <= 16) ? param : 12;
    uint64_t low = 1ULL << ((bits / 2) - 1);
    uint64_t high = (1ULL << (bits / 2)) - 1;
    if (low < 17) low = 17;
    
    uint64_t p = randomPrime(low, high);
    uint64_t q;
    do { q = randomPrime(low, high); } while (q == p);
    
    uint64_t n = p * q;
    if (n <= 255) return -10;
    
    // Генерация секрета s и открытого ключа v = s^2 mod n
    uint64_t s = generateSecret(n);
    uint64_t v = modPow(s, 2, n);
    
    char buf[256];
    int written = snprintf(buf, sizeof(buf), 
                          "VERIFY(public):%llu,%llu PROVE(private):%llu,%llu\n"
                          "Note: n=%llu*%llu=%llu, s=%llu, v=%llu",
                          (unsigned long long)n, (unsigned long long)v,
                          (unsigned long long)n, (unsigned long long)s,
                          (unsigned long long)p, (unsigned long long)q,
                          (unsigned long long)n,
                          (unsigned long long)s, (unsigned long long)v);
    
    if (written < 0 || static_cast<size_t>(written) >= *keyBufferSize) return -3;
    
    memcpy(keyBuffer, buf, written);
    *keyBufferSize = static_cast<size_t>(written);
    return 0;
}

}