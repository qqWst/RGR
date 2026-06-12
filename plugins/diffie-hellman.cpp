// Учебная реализация протокола Диффи-Хеллмана (DH).
// Принцип: Две стороны вырабатывают общий секрет, обмениваясь открытыми ключами.


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

bool isPrimitiveRoot(uint64_t g, uint64_t p) {
    if (gcd(g, p) != 1) return false;
    
    uint64_t phi = p - 1;
    if (modPow(g, phi / 2, p) == 1) return false;
    
    for (uint64_t i = 2; i * i <= phi; ++i) {
        if (phi % i == 0) {
            if (modPow(g, i, p) == 1) return false;
            if (modPow(g, phi / i, p) == 1) return false;
        }
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

// Генерация примитивного корня
uint64_t findPrimitiveRoot(uint64_t p) {
    // Для малых p можно перебрать
    for (uint64_t g = 2; g < p; ++g) {
        if (isPrimitiveRoot(g, p)) return g;
    }
    return 2; // fallback
}

// Разбор трёх чисел из строки
bool parseTriple(const uint8_t* key, size_t keySize, uint64_t& a, uint64_t& b, uint64_t& c) {
    char buf[128] = {0};
    if (keySize >= sizeof(buf)) return false;
    memcpy(buf, key, keySize);
    buf[keySize] = '\0';
    
    char* comma1 = strchr(buf, ',');
    if (!comma1) return false;
    *comma1 = '\0';
    
    char* comma2 = strchr(comma1 + 1, ',');
    if (!comma2) return false;
    *comma2 = '\0';
    
    a = static_cast<uint64_t>(strtoull(buf, nullptr, 10));
    b = static_cast<uint64_t>(strtoull(comma1 + 1, nullptr, 10));
    c = static_cast<uint64_t>(strtoull(comma2 + 1, nullptr, 10));
    
    return (a > 0 && b > 0 && c > 0);
}

bool parsePair(const uint8_t* key, size_t keySize, uint64_t& a, uint64_t& b) {
    char buf[128] = {0};
    if (keySize >= sizeof(buf)) return false;
    memcpy(buf, key, keySize);
    buf[keySize] = '\0';
    
    char* comma = strchr(buf, ',');
    if (!comma) return false;
    *comma = '\0';
    
    a = static_cast<uint64_t>(strtoull(buf, nullptr, 10));
    b = static_cast<uint64_t>(strtoull(comma + 1, nullptr, 10));
    
    return (a > 0 && b > 0);
}

}

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Diffie-Hellman (протокол выработки ключа)";
}

EXPORT const char* getKeyInfo() {
    return "Формат:\n"
           "  Для генерации открытого ключа (шифрование): \"p,g,a\"\n"
           "    p - простое число, g - примитивный корень, a - секретная экспонента\n"
           "  Для вычисления общего секрета (дешифрование): \"p,g,B\"\n"
           "    B - открытый ключ другой стороны\n"
           "Протокол: Стороны обмениваются A=g^a mod p и B=g^b mod p,\n"
           "          общий секрет K = B^a mod p = A^b mod p.\n"
           "При генерации param = битность p (10-16).";
}

EXPORT size_t getMinKeySize() { return 7; }
EXPORT size_t getMaxKeySize() { return 128; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    // Шифрование: вычисление открытого ключа A = g^a mod p
    // Входные данные игнорируются, используется только ключ
    if (!key || !output || !outputSize) return -1;
    
    uint64_t p = 0, g = 0, a = 0;
    if (!parseTriple(key, keySize, p, g, a)) return -2;
    if (p <= 255) return -4;
    
    if (*outputSize < 8) return -3; // Результат 8 байт
    
    uint64_t A = modPow(g, a, p);
    
    // Упаковка открытого ключа
    output[0] = static_cast<uint8_t>((A >> 56) & 0xFF);
    output[1] = static_cast<uint8_t>((A >> 48) & 0xFF);
    output[2] = static_cast<uint8_t>((A >> 40) & 0xFF);
    output[3] = static_cast<uint8_t>((A >> 32) & 0xFF);
    output[4] = static_cast<uint8_t>((A >> 24) & 0xFF);
    output[5] = static_cast<uint8_t>((A >> 16) & 0xFF);
    output[6] = static_cast<uint8_t>((A >> 8) & 0xFF);
    output[7] = static_cast<uint8_t>(A & 0xFF);
    
    *outputSize = 8;
    return 0;
}

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    // Дешифрование: вычисление общего секрета K = B^a mod p
    if (!data || !key || !output || !outputSize) return -1;
    if (dataSize != 8) return -5; // Ожидаем открытый ключ другой стороны (8 байт)
    
    uint64_t p = 0, g = 0, B = 0;
    if (!parseTriple(key, keySize, p, g, B)) {
        uint64_t a = 0;
        if (parsePair(key, keySize, p, a)) {
            B = g;
            uint64_t K = modPow(B, a, p);
            
            // Общий секрет можно использовать как ключ шифрования
            size_t keyLen = (K > 0xFFFFFFFF) ? 8 : 4;
            if (*outputSize < keyLen) return -3;
            
            for (size_t i = 0; i < keyLen; ++i) {
                output[i] = static_cast<uint8_t>((K >> (8 * (keyLen - 1 - i))) & 0xFF);
            }
            *outputSize = keyLen;
            return 0;
        }
        return -2;
    }
    
    // Вычисляем общий секрет
    uint64_t K = modPow(B, g, p);
    
    size_t keyLen = (K > 0xFFFFFFFF) ? 8 : 4;
    if (*outputSize < keyLen) return -3;
    
    for (size_t i = 0; i < keyLen; ++i) {
        output[i] = static_cast<uint8_t>((K >> (8 * (keyLen - 1 - i))) & 0xFF);
    }
    *outputSize = keyLen;
    
    return 0;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    
    srand(static_cast<unsigned>(time(nullptr)));
    
    int bits = (param >= 10 && param <= 16) ? param : 12;
    uint64_t low = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;
    if (low < 2) low = 2;
    
    uint64_t p = randomPrime(low, high);
    
    uint64_t g = findPrimitiveRoot(p);
    
    uint64_t a = 2 + (rand() % (p - 3));
    
    uint64_t A = modPow(g, a, p);
    
    char buf[256];
    int written = snprintf(buf, sizeof(buf),
                          "Для стороны A (свой ключ): %llu,%llu,%llu\n"
                          "Открытый ключ A (для отправки B): %llu,%llu,%llu\n"
                          "Параметры протокола: p=%llu (простое), g=%llu (примитивный корень)\n"
                          "Секрет A: a=%llu\n"
                          "Общий секрет будет: K = B^a mod p",
                          (unsigned long long)p, (unsigned long long)g, (unsigned long long)a,
                          (unsigned long long)p, (unsigned long long)g, (unsigned long long)A,
                          (unsigned long long)p, (unsigned long long)g,
                          (unsigned long long)a);
    
    if (written < 0 || static_cast<size_t>(written) >= *keyBufferSize) return -3;
    
    memcpy(keyBuffer, buf, written);
    *keyBufferSize = static_cast<size_t>(written);
    return 0;
}

}