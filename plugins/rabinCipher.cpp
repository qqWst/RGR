// Учебная реализация шифра Рабина с поддержкой 64-битного модуля.
// Используется __int128 для умножения. Паддинг: к байту b приписывается
// 16-битная маска ~b, что почти исключает коллизии при выборе корня.

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

// Расширенный алгоритм Евклида (со знаком, без __int128)
int64_t extGcd(int64_t a, int64_t b, int64_t& x, int64_t& y) {
    if (b == 0) { x = 1; y = 0; return a; }
    int64_t x1, y1;
    int64_t g = extGcd(b, a % b, x1, y1);
    x = y1; y = x1 - (a / b) * y1;
    return g;
}

// Сложение / вычитание по модулю без переполнения
uint64_t addMod(uint64_t a, uint64_t b, uint64_t mod) {
    return static_cast<uint64_t>((static_cast<BigInt>(a) + b) % mod);
}

uint64_t subMod(uint64_t a, uint64_t b, uint64_t mod) {
    // (a - b) mod mod
    if (a >= b) return (a - b) % mod;
    return mod - ((b - a) % mod);
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

// Простое p ≡ 3 (mod 4)
uint64_t randomBlumPrime(uint64_t low, uint64_t high) {
    while (true) {
        uint64_t range = high - low + 1;
        uint64_t c = low + (rand64() % range);
        // Приводим к виду 4k+3
        c = c | 3;
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
    return "Rabin (асимметричный, 64-битный модуль)";
}

EXPORT const char* getKeyInfo() {
    return "Шифрование: \"n\" (n = p*q, p≡q≡3 mod 4).\n"
           "Дешифрование: \"p,q\".\n"
           "Паддинг 16 бит: m = (b << 16) | (~b & 0xFFFF) для устранения неоднозначности.\n"
           "param при генерации = битность n (32-62, рекомендуется 56).\n"
           "Каждый байт шифруется в 8 байт.";
}

EXPORT size_t getMinKeySize() { return 1; }
EXPORT size_t getMaxKeySize() { return 64; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    uint64_t n = 0;
    if (!parseSingle(key, keySize, n)) return -2;
    // Нужно, чтобы m = (b<<16)|(~b&0xFFFF) < n, то есть n > 2^24
    if (n <= 0xFFFFFF) return -4;
    if (*outputSize < dataSize * 8) return -3;

    for (size_t i = 0; i < dataSize; ++i) {
        uint8_t b = data[i];
        uint64_t mask = static_cast<uint64_t>(~b & 0xFF);
        uint64_t m = (static_cast<uint64_t>(b) << 16) | (mask << 8) | mask;
        uint64_t c = mulMod(m, m, n);
        for (int j = 7; j >= 0; --j) {
            output[i * 8 + (7 - j)] = static_cast<uint8_t>((c >> (j * 8)) & 0xFF);
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

    uint64_t p = 0, q = 0;
    if (!parsePair(key, keySize, p, q)) return -2;

    uint64_t n = p * q;
    size_t outCount = dataSize / 8;
    if (*outputSize < outCount) return -3;

    // CRT: находим yp, yq такие, что yp*p + yq*q = 1
    int64_t yp = 0, yq = 0;
    extGcd(static_cast<int64_t>(p), static_cast<int64_t>(q), yp, yq);
    // Приводим к положительным значениям по модулю n
    uint64_t ypU = static_cast<uint64_t>(((yp % static_cast<int64_t>(n)) + static_cast<int64_t>(n)) % static_cast<int64_t>(n));
    uint64_t yqU = static_cast<uint64_t>(((yq % static_cast<int64_t>(n)) + static_cast<int64_t>(n)) % static_cast<int64_t>(n));

    for (size_t i = 0; i < outCount; ++i) {
        uint64_t c = 0;
        for (int j = 0; j < 8; ++j) {
            c = (c << 8) | data[i * 8 + j];
        }

        uint64_t mp = modPow(c, (p + 1) / 4, p);
        uint64_t mq = modPow(c, (q + 1) / 4, q);

        // Комбинируем 4 корня через CRT
        uint64_t a = mulMod(mulMod(ypU, p, n), mq, n);
        uint64_t b = mulMod(mulMod(yqU, q, n), mp, n);
        uint64_t r1 = addMod(a, b, n);
        uint64_t r2 = subMod(a, b, n);
        uint64_t roots[4] = { r1, r2, subMod(n, r1, n), subMod(n, r2, n) };

        // Ищем корень с правильным паддингом: средний байт = младший = ~старший
        uint8_t found = 0;
        bool ok = false;
        for (int k = 0; k < 4; ++k) {
            uint64_t m = roots[k];
            uint8_t hi  = static_cast<uint8_t>((m >> 16) & 0xFF);
            uint8_t mid = static_cast<uint8_t>((m >> 8) & 0xFF);
            uint8_t lo  = static_cast<uint8_t>(m & 0xFF);
            uint8_t expectedMask = static_cast<uint8_t>(~hi);
            if (mid == expectedMask && lo == expectedMask) {
                found = hi;
                ok = true;
                break;
            }
        }
        output[i] = ok ? found : 0;
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
    if (low < 4096) low = 4096; // n гарантированно > 2^24

    uint64_t p = randomBlumPrime(low, high);
    uint64_t q;
    do { q = randomBlumPrime(low, high); } while (q == p);

    uint64_t n = p * q;
    if (n <= 0xFFFFFF) return -10;

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