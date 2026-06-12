// Учебная реализация бесключевого протокола Шамира с поддержкой 64-битного модуля.
// Используется __int128 для умножения.

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

using BigInt = unsigned __int128;

uint64_t mulMod(uint64_t a, uint64_t b, uint64_t mod) {
    return static_cast<uint64_t>((static_cast<BigInt>(a) * b) % mod);
}

uint64_t modPow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t r = 1; base %= mod;
    while (exp > 0) {
        if (exp & 1) r = mulMod(r, base, mod);
        exp >>= 1;
        base = mulMod(base, base, mod);
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

bool millerRabinTest(uint64_t n, uint64_t a) {
    if (n % a == 0) return n == a;
    uint64_t d = n - 1;
    int r = 0;
    while ((d & 1) == 0) { d >>= 1; r++; }

    uint64_t x = modPow(a, d, n);
    if (x == 1 || x == n - 1) return true;
    for (int i = 0; i < r - 1; ++i) {
        x = mulMod(x, x, n);
        if (x == n - 1) return true;
    }
    return false;
}

bool isPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;
    uint64_t witnesses[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    for (uint64_t a : witnesses) {
        if (a >= n) break;
        if (!millerRabinTest(n, a)) return false;
    }
    return true;
}

uint64_t rand64() {
    uint64_t r = 0;
    for (int i = 0; i < 4; ++i) {
        r = (r << 16) | (static_cast<uint64_t>(rand()) & 0xFFFF);
    }
    return r;
}

uint64_t randomPrime(uint64_t low, uint64_t high) {
    while (true) {
        uint64_t range = high - low + 1;
        uint64_t c = low + (rand64() % range);
        if (c % 2 == 0) c |= 1;
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
    return "Shamir (бесключевой, 64-битный модуль)";
}

EXPORT const char* getKeyInfo() {
    return "Простое p — до 64 бит. Используется __int128 для арифметики.\n"
           "Шифрование: \"p,C\" — c = m^C mod p.\n"
           "Дешифрование: \"p,D\" — m = c^D mod p, где C*D ≡ 1 (mod p-1).\n"
           "param при генерации = битность p (32-62, рекомендуется 60).\n"
           "Каждый байт шифруется в 8 байт.";
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
        uint64_t c = modPow(m, C, p);
        for (int j = 7; j >= 0; --j) {
            output[i * 8 + (7 - j)] = static_cast<uint8_t>((c >> (j * 8)) & 0xFF); }
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
        for (int j = 0; j < 8; ++j) {
            c = (c << 8) | data[i * 8 + j];
        }
        uint64_t m = modPow(c, D, p);
        output[i] = static_cast<uint8_t>(m & 0xFF);
    }
    *outputSize = outCount;
    return 0;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;

    srand(static_cast<unsigned>(time(nullptr)));

    int bits = (param >= 32 && param <= 62) ? param : 60;

    uint64_t low  = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;
    if (low <= 256) low = 257;

    uint64_t p = randomPrime(low, high);
    uint64_t phi = p - 1;

    // Подбираем C, взаимно простое с phi (начинаем с нечётного крупного значения)
    uint64_t C = 0;
    uint64_t start = phi / 2;
    if ((start & 1) == 0) start++;
    for (uint64_t cand = start; cand < phi; cand += 2) {
        if (gcdU(cand, phi) == 1) { C = cand; break; }
    }
    if (C == 0) {
        // Запасной вариант — перебор с малых значений
        for (uint64_t cand = 3; cand < phi; cand += 2) {
            if (gcdU(cand, phi) == 1) { C = cand; break; }
        }
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