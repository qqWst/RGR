// Учебная реализация RSA на малых числах (модуль до 2^16).
// Ключ шифрования: "n,e" (текстом). Ключ дешифрования: "n,d".
// Каждый байт шифруется отдельно, результат — пара байт (старший, младший).

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

// Возведение в степень по модулю
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

// НОД
uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) { uint64_t t = b; b = a % b; a = t; }
    return a;
}

// Расширенный алгоритм Евклида для модульного обратного
int64_t modInverse(int64_t a, int64_t m) {
    int64_t g = a, x = 1, y = 0;
    int64_t g1 = m, x1 = 0, y1 = 1;
    while (g1 != 0) {
        int64_t q = g / g1;
        int64_t tg = g - q * g1, tx = x - q * x1, ty = y - q * y1;
        g = g1; x = x1; y = y1;
        g1 = tg; x1 = tx; y1 = ty;
    }
    if (g != 1) return -1;
    return (x % m + m) % m;
}

// Простое ли число
bool isPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;
    for (uint64_t i = 3; i * i <= n; i += 2) {
        if (n % i == 0) return false;
    }
    return true;
}

// Генерация случайного простого числа в диапазоне [low, high]
uint64_t randomPrime(uint64_t low, uint64_t high) {
    while (true) {
        uint64_t candidate = low + (rand() % (high - low + 1));
        if (candidate % 2 == 0) candidate++;
        if (candidate <= high && isPrime(candidate)) return candidate;
    }
}

// Разбор ключа "n,e" или "n,d"
bool parseKey(const uint8_t* key, size_t keySize, uint64_t& n, uint64_t& exp) {
    char buf[128] = {0};
    if (keySize >= sizeof(buf)) return false;
    memcpy(buf, key, keySize);
    buf[keySize] = '\0';

    char* comma = strchr(buf, ',');
    if (!comma) return false;
    *comma = '\0';

    n   = static_cast<uint64_t>(strtoull(buf, nullptr, 10));
    exp = static_cast<uint64_t>(strtoull(comma + 1, nullptr, 10));
    return (n > 0 && exp > 0);
}

} // namespace

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "RSA (асимметричный шифр)";
}

EXPORT const char* getKeyInfo() {
    return "Формат: \"n,e\" для шифрования, \"n,d\" для дешифрования.\n"
           "Пример: 3233,17 / 3233,2753\n"
           "При генерации param = битность n (8-16).";
}

EXPORT size_t getMinKeySize() { return 3; }
EXPORT size_t getMaxKeySize() { return 128; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    uint64_t n = 0, e = 0;
    if (!parseKey(key, keySize, n, e)) return -2;
    if (n <= 255) return -4; // модуль должен быть больше любого байта
    if (*outputSize < dataSize * 2) return -3;

    for (size_t i = 0; i < dataSize; ++i) {
        uint64_t m = data[i];
        uint64_t c = modPow(m, e, n);
        output[2 * i]     = static_cast<uint8_t>((c >> 8) & 0xFF);
        output[2 * i + 1] = static_cast<uint8_t>(c & 0xFF);
    }
    *outputSize = dataSize * 2;
    return 0;
}

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;
    if (dataSize % 2 != 0) return -5;

    uint64_t n = 0, d = 0;
    if (!parseKey(key, keySize, n, d)) return -2;

    size_t outCount = dataSize / 2;
    if (*outputSize < outCount) return -3;

    for (size_t i = 0; i < outCount; ++i) {
        uint64_t c = (static_cast<uint64_t>(data[2 * i]) << 8) | data[2 * i + 1];
        uint64_t m = modPow(c, d, n);
        output[i] = static_cast<uint8_t>(m & 0xFF);
    }
    *outputSize = outCount;
    return 0;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;

    srand(static_cast<unsigned>(time(nullptr)));

    // Битность по умолчанию: 12 (n ~ 4096)
    int bits = (param >= 8 && param <= 16) ? param : 12;
    uint64_t low  = 1ULL << ((bits / 2) - 1);
    uint64_t high = (1ULL << (bits / 2)) - 1;
    if (low < 17) low = 17;

    uint64_t p = randomPrime(low, high);
    uint64_t q;
    do { q = randomPrime(low, high); } while (q == p);

    uint64_t n = p * q;
    if (n <= 255) return -10; // повторить генерацию вручную с большим bits

    uint64_t phi = (p - 1) * (q - 1);

    // Выбираем e
    uint64_t e = 17;
    if (e >= phi || gcd(e, phi) != 1) {
        e = 3;
        while (e < phi && gcd(e, phi) != 1) e += 2;
    }

    int64_t d = modInverse(static_cast<int64_t>(e), static_cast<int64_t>(phi));
    if (d < 0) return -11;

    // Записываем оба ключа в формате "n,e | n,d"
    char buf[128];
    int written = snprintf(buf, sizeof(buf), "PUB:%llu,%llu PRIV:%llu,%llu",
                           (unsigned long long)n, (unsigned long long)e,
                           (unsigned long long)n, (unsigned long long)d);

    if (written < 0 || static_cast<size_t>(written) >= *keyBufferSize) return -3;

    memcpy(keyBuffer, buf, written);
    *keyBufferSize = static_cast<size_t>(written);
    return 0;
}

}