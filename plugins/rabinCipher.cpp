// Учебная реализация шифра Рабина.
// Открытый ключ: n = p*q, где p,q — простые, p≡q≡3 (mod 4).
// Шифр: c = m^2 mod n. Дешифрование даёт 4 корня, выбираем тот,
// чьи последние 8 бит совпадают со старшими (используем избыточность).
// Формат ключа: "n" (шифрование), "p,q" (дешифрование).

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

int64_t extGcd(int64_t a, int64_t b, int64_t& x, int64_t& y) {
    if (b == 0) { x = 1; y = 0; return a; }
    int64_t x1, y1;
    int64_t g = extGcd(b, a % b, x1, y1);
    x = y1; y = x1 - (a / b) * y1;
    return g;
}

bool isPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;
    for (uint64_t i = 3; i * i <= n; i += 2)
        if (n % i == 0) return false;
    return true;
}

// Простое p такое, что p ≡ 3 (mod 4)
uint64_t randomBlumPrime(uint64_t low, uint64_t high) {
    while (true) {
        uint64_t c = low + (rand() % (high - low + 1));
        if (c % 4 != 3) c += (3 - c % 4 + 4) % 4;
        if (c <= high && isPrime(c)) return c;
    }
}

bool parseSingle(const uint8_t* key, size_t keySize, uint64_t& n) {
    char buf[64] = {0};
    if (keySize >= sizeof(buf)) return false;
    memcpy(buf, key, keySize);
    n = strtoull(buf, nullptr, 10);
    return n > 0;
}

bool parsePair(const uint8_t* key, size_t keySize, uint64_t& p, uint64_t& q) {
    char buf[64] = {0};
    if (keySize >= sizeof(buf)) return false;
    memcpy(buf, key, keySize);
    char* comma = strchr(buf, ',');
    if (!comma) return false;
    *comma = '\0';
    p = strtoull(buf, nullptr, 10);
    q = strtoull(comma + 1, nullptr, 10);
    return p > 0 && q > 0;
}

} // namespace

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Rabin (асимметричный шифр)";
}

EXPORT const char* getKeyInfo() {
    return "Шифрование: \"n\" (n = p*q, p≡q≡3 mod 4).\n"
           "Дешифрование: \"p,q\".\n"
           "Для устранения неоднозначности байт дублируется (m = byte*256 + byte).\n"
           "param при генерации = битность n (10-16).";
}

EXPORT size_t getMinKeySize() { return 1; }
EXPORT size_t getMaxKeySize() { return 64; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    uint64_t n = 0;
    if (!parseSingle(key, keySize, n)) return -2;
    if (n <= 0xFFFF) return -4; // n должно вмещать m = byte*256 + byte
    if (*outputSize < dataSize * 2) return -3;

    for (size_t i = 0; i < dataSize; ++i) {
        // Дублируем байт для избыточности
        uint64_t m = (static_cast<uint64_t>(data[i]) << 8) | data[i];
        uint64_t c = (m * m) % n;
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

    uint64_t p = 0, q = 0;
    if (!parsePair(key, keySize, p, q)) return -2;

    uint64_t n = p * q;
    size_t outCount = dataSize / 2;
    if (*outputSize < outCount) return -3;

    // Коэффициенты CRT
    int64_t yp = 0, yq = 0;
    extGcd(static_cast<int64_t>(p), static_cast<int64_t>(q), yp, yq);

    for (size_t i = 0; i < outCount; ++i) {
        uint64_t c = (static_cast<uint64_t>(data[2 * i]) << 8) | data[2 * i + 1];

        uint64_t mp = modPow(c, (p + 1) / 4, p);
        uint64_t mq = modPow(c, (q + 1) / 4, q);

        // 4 корня методом CRT
        int64_t r1 =  (yp * static_cast<int64_t>(p) * static_cast<int64_t>(mq)
                     + yq * static_cast<int64_t>(q) * static_cast<int64_t>(mp));
        int64_t r2 =  (yp * static_cast<int64_t>(p) * static_cast<int64_t>(mq)
                     - yq * static_cast<int64_t>(q) * static_cast<int64_t>(mp));
        r1 = ((r1 % static_cast<int64_t>(n)) + n) % n;
        r2 = ((r2 % static_cast<int64_t>(n)) + n) % n;
        uint64_t roots[4] = {
            static_cast<uint64_t>(r1),
            static_cast<uint64_t>(r2),
            n - static_cast<uint64_t>(r1),
            n - static_cast<uint64_t>(r2)
        };

        // Ищем корень с дублированными байтами
        uint8_t found = 0;
        bool ok = false;
        for (int k = 0; k < 4; ++k) {
            uint64_t m = roots[k];
            uint8_t hi = static_cast<uint8_t>((m >> 8) & 0xFF);
            uint8_t lo = static_cast<uint8_t>(m & 0xFF);
            if (hi == lo) { found = lo; ok = true; break; }
        }

        output[i] = ok ? found : 0;
    }

    *outputSize = outCount;
    return 0;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;

    srand(static_cast<unsigned>(time(nullptr)));

    int bits = (param >= 10 && param <= 16) ? param : 12;
    uint64_t low  = 1ULL << ((bits / 2) - 1);
    uint64_t high = (1ULL << (bits / 2)) - 1;
    if (low < 7) low = 7;

    uint64_t p = randomBlumPrime(low, high);
    uint64_t q;
    do { q = randomBlumPrime(low, high); } while (q == p);

    uint64_t n = p * q;
    if (n <= 0xFFFF) return -10;

    char buf[128];
    int w = snprintf(buf, sizeof(buf), "PUB:%llu PRIV:%llu,%llu",
                     (unsigned long long)n,
                     (unsigned long long)p, (unsigned long long)q);
    if (w < 0 || static_cast<size_t>(w) >= *keyBufferSize) return -3;

    memcpy(keyBuffer, buf, w);
    *keyBufferSize = static_cast<size_t>(w);
    return 0;
}

}