// Учебная реализация бесключевого протокола Шамира.
// Идея: Алиса и Боб имеют общее простое p, свои секретные пары (C, D), где C*D ≡ 1 (mod p-1).
// Сообщение m шифруется как m^C mod p. Дешифрование: c^D mod p.
//
// В данном плагине реализован "один шаг": шифрование m -> m^C mod p,
// и обратное преобразование c -> c^D mod p.
// Полный 3-проходный протокол требует двух сторон;
// для учебной демонстрации используем одну пару (C, D) — фактически это
// схема "степени по модулю" с проверкой обратимости.
//
// Формат ключа: "p,C" (шифрование), "p,D" (дешифрование).

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
    uint64_t r = 1; base %= mod;
    while (exp > 0) {
        if (exp & 1) r = (r * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return r;
}

uint64_t gcdU(uint64_t a, uint64_t b) {
    while (b != 0) { uint64_t t = b; b = a % b; a = t; }
    return a;
}

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

bool isPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;
    for (uint64_t i = 3; i * i <= n; i += 2)
        if (n % i == 0) return false;
    return true;
}

uint64_t randomPrime(uint64_t low, uint64_t high) {
    while (true) {
        uint64_t c = low + (rand() % (high - low + 1));
        if (c % 2 == 0) c++;
        if (c <= high && isPrime(c)) return c;
    }
}

bool parsePair(const uint8_t* key, size_t keySize, uint64_t& p, uint64_t& exp) {
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

} // namespace

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Shamir (бесключевой протокол)";
}

EXPORT const char* getKeyInfo() {
    return "Простое p (p > 255).\n"
           "Шифрование: \"p,C\" — c = m^C mod p.\n"
           "Дешифрование: \"p,D\" — m = c^D mod p, где C*D ≡ 1 (mod p-1).\n"
           "param при генерации = битность p (10-16).";
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
    if (*outputSize < dataSize * 2) return -3;

    for (size_t i = 0; i < dataSize; ++i) {
        uint64_t m = data[i];
        uint64_t c = modPow(m, C, p);
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

    uint64_t p = 0, D = 0;
    if (!parsePair(key, keySize, p, D)) return -2;

    size_t outCount = dataSize / 2;
    if (*outputSize < outCount) return -3;

    for (size_t i = 0; i < outCount; ++i) {
        uint64_t c = (static_cast<uint64_t>(data[2 * i]) << 8) | data[2 * i + 1];
        uint64_t m = modPow(c, D, p);
        output[i] = static_cast<uint8_t>(m & 0xFF);
    }
    *outputSize = outCount;
    return 0;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;

    srand(static_cast<unsigned>(time(nullptr)));

    int bits = (param >= 10 && param <= 16) ? param : 12;
    uint64_t low  = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;
    if (low <= 256) low = 257;

    uint64_t p = randomPrime(low, high);
    uint64_t phi = p - 1;

    // Подбираем C, взаимно простое с phi
    uint64_t C = 0;
    for (uint64_t cand = 3; cand < phi; cand += 2) {
        if (gcdU(cand, phi) == 1) { C = cand; break; }
    }
    if (C == 0) return -11;

    int64_t D = modInverse(static_cast<int64_t>(C), static_cast<int64_t>(phi));
    if (D < 0) return -11;

    char buf[128];
    int w = snprintf(buf, sizeof(buf), "ENC:%llu,%llu DEC:%llu,%llu",
                     (unsigned long long)p, (unsigned long long)C,
                     (unsigned long long)p, (unsigned long long)D);
    if (w < 0 || static_cast<size_t>(w) >= *keyBufferSize) return -3;

    memcpy(keyBuffer, buf, w);
    *keyBufferSize = static_cast<size_t>(w);
    return 0;
}

}