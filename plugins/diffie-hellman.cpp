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

// Вспомогательные функции
static uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

static uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

static int isPrime(uint64_t n) {
    if (n < 2) return 0;
    if (n < 4) return 1;
    if (n % 2 == 0) return 0;
    for (uint64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return 0;
    }
    return 1;
}

static int isPrimitiveRoot(uint64_t g, uint64_t p) {
    if (gcd(g, p) != 1) return 0;
    
    uint64_t phi = p - 1;
    if (modPow(g, phi / 2, p) == 1) return 0;
    
    for (uint64_t i = 2; i * i <= phi; ++i) {
        if (phi % i == 0) {
            if (modPow(g, i, p) == 1) return 0;
            if (modPow(g, phi / i, p) == 1) return 0;
        }
    }
    
    return 1;
}

static uint64_t randomPrime(uint64_t low, uint64_t high) {
    while (1) {
        uint64_t candidate = low + (rand() % (high - low + 1));
        if (candidate % 2 == 0) candidate++;
        if (candidate <= high && isPrime(candidate)) return candidate;
    }
}

static uint64_t findPrimitiveRoot(uint64_t p) {
    for (uint64_t g = 2; g < p; ++g) {
        if (isPrimitiveRoot(g, p)) return g;
    }
    return 2;
}

// Функция для преобразования uint64_t в строку
void uint64ToStr(uint64_t num, char* out) {
    if (num == 0) {
        out[0] = '0';
        out[1] = '\0';
        return;
    }
    
    char temp[32];
    int pos = 0;
    while (num > 0) {
        temp[pos++] = '0' + (num % 10);
        num /= 10;
    }
    
    for (int i = 0; i < pos; ++i) {
        out[i] = temp[pos - 1 - i];
    }
    out[pos] = '\0';
}

int parseTriple(const uint8_t* key, size_t keySize, uint64_t* a, uint64_t* b, uint64_t* c) {
    char buf[128] = {0};
    if (keySize >= sizeof(buf)) return 0;
    memcpy(buf, key, keySize);
    buf[keySize] = '\0';
    
    char* comma1 = strchr(buf, ',');
    if (!comma1) return 0;
    *comma1 = '\0';
    
    char* comma2 = strchr(comma1 + 1, ',');
    if (!comma2) return 0;
    *comma2 = '\0';
    
    *a = strtoull(buf, NULL, 10);
    *b = strtoull(comma1 + 1, NULL, 10);
    *c = strtoull(comma2 + 1, NULL, 10);
    
    return (*a > 0 && *b > 0 && *c > 0);
}

int parsePair(const uint8_t* key, size_t keySize, uint64_t* a, uint64_t* b) {
    char buf[128] = {0};
    if (keySize >= sizeof(buf)) return 0;
    memcpy(buf, key, keySize);
    buf[keySize] = '\0';
    
    char* comma = strchr(buf, ',');
    if (!comma) return 0;
    *comma = '\0';
    
    *a = strtoull(buf, NULL, 10);
    *b = strtoull(comma + 1, NULL, 10);
    
    return (*a > 0 && *b > 0);
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
    if (!key || !output || !outputSize) return -1;
    
    uint64_t p = 0, g = 0, a = 0;
    if (!parseTriple(key, keySize, &p, &g, &a)) return -2;
    if (p <= 255) return -4;
    
    if (*outputSize < 8) return -3;
    
    uint64_t A = modPow(g, a, p);
    
    output[0] = (A >> 56) & 0xFF;
    output[1] = (A >> 48) & 0xFF;
    output[2] = (A >> 40) & 0xFF;
    output[3] = (A >> 32) & 0xFF;
    output[4] = (A >> 24) & 0xFF;
    output[5] = (A >> 16) & 0xFF;
    output[6] = (A >> 8) & 0xFF;
    output[7] = A & 0xFF;
    
    *outputSize = 8;
    return 0;
}

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;
    if (dataSize != 8) return -5;
    
    uint64_t p = 0, g = 0, B = 0;
    if (!parseTriple(key, keySize, &p, &g, &B)) {
        uint64_t a = 0;
        if (parsePair(key, keySize, &p, &a)) {
            B = g;
            uint64_t K = modPow(B, a, p);
            
            size_t keyLen = (K > 0xFFFFFFFF) ? 8 : 4;
            if (*outputSize < keyLen) return -3;
            
            for (size_t i = 0; i < keyLen; ++i) {
                output[i] = (K >> (8 * (keyLen - 1 - i))) & 0xFF;
            }
            *outputSize = keyLen;
            return 0;
        }
        return -2;
    }
    
    uint64_t K = modPow(B, g, p);
    
    size_t keyLen = (K > 0xFFFFFFFF) ? 8 : 4;
    if (*outputSize < keyLen) return -3;
    
    for (size_t i = 0; i < keyLen; ++i) {
        output[i] = (K >> (8 * (keyLen - 1 - i))) & 0xFF;
    }
    *outputSize = keyLen;
    
    return 0;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    
    srand(time(NULL));
    
    int bits = (param >= 10 && param <= 16) ? param : 12;
    uint64_t low = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;
    if (low < 2) low = 2;
    
    uint64_t p = randomPrime(low, high);
    uint64_t g = findPrimitiveRoot(p);
    uint64_t a = 2 + (rand() % (p - 3));
    uint64_t A = modPow(g, a, p);
    
    // Преобразуем числа в строки вручную
    char strP[32], strG[32], strA[32], strAkey[32];
    uint64ToStr(p, strP);
    uint64ToStr(g, strG);
    uint64ToStr(a, strA);
    uint64ToStr(A, strAkey);
    
    char buf[256];
    int written = sprintf(buf,
                          "Private key: %s,%s,%s\n"
                          "Public key: %s,%s,%s",
                          strP, strG, strA,
                          strP, strG, strAkey);
    
    if (written < 0 || (size_t)written >= *keyBufferSize) {
        // Минимальный вывод
        written = sprintf(buf, "%s,%s,%s\n%s,%s,%s",
                          strP, strG, strA,
                          strP, strG, strAkey);
    }
    
    if (written < 0 || (size_t)written >= *keyBufferSize) {
        return -3;
    }
    
    memcpy(keyBuffer, buf, written);
    *keyBufferSize = (size_t)written;
    return 0;
}

}