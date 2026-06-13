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

uint64_t binMod(uint64_t base, uint64_t power, uint64_t modulo) {
    base %= modulo;
    if (modulo > 1) power %= modulo - 1;
    uint64_t result = 1;
    while (power > 0) {
        if (power & 1) result = mulMod(result, base, modulo);
        base = mulMod(base, base, modulo);
        power >>= 1;
    }
    return result;
}

uint64_t gcdU(uint64_t a, uint64_t b) {
    while (b != 0) { uint64_t t = b; b = a % b; a = t; }
    return a;
}

uint64_t modNegative(uint64_t base, uint64_t modulo) {
    base = base % modulo;
    uint64_t m0 = modulo;
    int64_t u1 = 0, u2 = 1, u3;
    uint64_t q = modulo / base;
    uint64_t r = modulo % base;
    uint64_t r0;
    while (r > 0) {
        r0 = r;
        u3 = u1 - u2 * q;
        modulo = base; base = r;
        u1 = u2; u2 = u3;
        q = modulo / base;
        r = modulo % base;
    }
    if (r0 != 1) return 0;
    return (u3 > 0) ? u3 : u3 + m0;
}

bool millerRabinTest(uint64_t n, uint64_t a) {
    if (n % a == 0) return n == a;
    uint64_t d = n - 1;
    int r = 0;
    while ((d & 1) == 0) { d >>= 1; r++;  } 

    uint64_t x = binMod(a, d, n);
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
        r = (r << 16) |
            (static_cast<uint64_t>(rand()) & 0xFFFF);
    }
    return r;
}

uint64_t randomPrime(uint64_t low, uint64_t high) {
    while (true) {
        uint64_t range = high - low + 1;
        uint64_t candidate = low + (rand64() % range);
        if (candidate % 2 == 0) candidate |= 1;
        if (candidate <= high && isPrime(candidate)) return candidate;
    }
}

bool parseKey(const uint8_t* key, size_t keySize, uint64_t& n, uint64_t& exp) {

    char buf[128] = {0};

    if (keySize >= sizeof(buf)) return false;

    memcpy(buf, key, keySize);

    buf[keySize] = '\0';

    char* comma = strchr(buf, ',');

    if (!comma) return false;
    *comma = '\0';
    n   = strtoull(buf, nullptr, 10);
    exp = strtoull(comma + 1, nullptr, 10);
    return (n > 0 && exp > 0);
}

}

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "RSA (асимметричный, 64-битный модуль)";
}

EXPORT const char* getKeyInfo() {
    return "Формат: \"n,e\" для шифрования, \"n,d\" для дешифрования.\n"
           "Модуль n — до 64 бит (использует __int128 для арифметики).\n"
           "При генерации param = битность n (32-62, рекомендуется 56).\n"
           "Каждый исходный байт шифруется в 8 байт.";
}

EXPORT size_t getMinKeySize() { return 3; }
EXPORT size_t getMaxKeySize() { return 128; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    uint64_t n = 0, e = 0;
    if (!parseKey(key, keySize, n, e)) return -2;
    if (n <= 255) return -4;
    if (*outputSize < dataSize * 8) return -3;

    for (size_t i = 0; i < dataSize; ++i) {
        uint64_t m = data[i];
        uint64_t c = binMod(m, e, n);
        for (int b = 7; b >= 0; --b) {
            output[i * 8 + (7 - b)] = static_cast<uint8_t>((c >> (b * 8)) & 0xFF);
        }
    }
    *outputSize = dataSize * 8;
    return 0;
}

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;
    if (dataSize % 8 != 0) return -5;

    uint64_t n = 0, d = 0;
    if (!parseKey(key, keySize, n, d)) return -2;

    size_t outCount = dataSize / 8;
    if (*outputSize < outCount) return -3;

    for (size_t i = 0; i < outCount; ++i) {
        uint64_t c = 0;
        for (int b = 0; b < 8; ++b) {
            c = (c << 8) | data[i * 8 + b];
        }
        uint64_t m = binMod(c, d, n);
        output[i] = static_cast<uint8_t>(m & 0xFF);
    }
    *outputSize = outCount;
    return 0;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;

    srand(static_cast<unsigned>(time(nullptr)));

    int bits = (param >= 32 && param <= 62) ? param : 56;
    int halfBits = bits / 2;

    uint64_t low  = 1ULL << (halfBits - 1);
    uint64_t high = (1ULL << halfBits) - 1;
    if (low < 17) low = 17;

    uint64_t p = randomPrime(low, high);
    uint64_t q;
    do { q = randomPrime(low, high); } while (q == p);

    uint64_t n = p * q;
    if (n <= 255) return -10;

    uint64_t phi = (p - 1) * (q - 1);

    uint64_t e = 65537;
    if (e >= phi || gcdU(e, phi) != 1) {
        e = 17;
        if (e >= phi || gcdU(e, phi) != 1) {
            e = 3;
            while (e < phi && gcdU(e, phi) != 1) e += 2;
        }
    }

    int64_t d = modNegative(static_cast<int64_t>(e), static_cast<int64_t>(phi));
    if (d < 0) return -11;

    char buf[128];
    int w = snprintf(buf, sizeof(buf), "PUB:%llu,%llu PRIV:%llu,%llu",
                     (unsigned long long)n, (unsigned long long)e,
                     (unsigned long long)n, (unsigned long long)d);
    if (w < 0 || static_cast<size_t>(w) >= *keyBufferSize) return -3;

    memcpy(keyBuffer, buf, w);
    *keyBufferSize = static_cast<size_t>(w);
    return 0;
}

}