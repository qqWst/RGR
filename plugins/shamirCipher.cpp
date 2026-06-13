#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>

#include <string>
#include <vector>
#include <stdexcept>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

using namespace std;

uint64_t gcd(uint64_t a, uint64_t b)
{
    while (b != 0)
    {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t binMod(uint64_t base, uint64_t power, uint64_t modulo) {
    base %= modulo;
    power %= modulo - 1;
    uint64_t result = 1;
    while (power > 0) {
        if (power & 1) {
            result = (result * base) % modulo;
        }
        base = (base * base) % modulo;
        power >>= 1;
    }
    return result;
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
        modulo = base;
        base = r;
        u1 = u2;
        u2 = u3;
        q = modulo / base;
        r = modulo % base;
    }
    if (r0 != 1) {
        return 0;
    }
    uint64_t result = (u3 > 0) ? u3 : u3 + m0;
    return result;
}

static bool millerRabinTest(uint64_t n, uint64_t a) {
    if (n % a == 0) return n == a;
    uint64_t d = n - 1;
    int r = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        r++;
    }
    uint64_t x = binMod(a, d, n);
    if (x == 1 || x == n - 1) return true;
    for (int i = 0; i < r - 1; ++i) {
        x = (x * x) % n;
        if (x == n - 1) return true;
    }
    return false;
}

static bool isPrime(uint64_t n) {
    if (n < 2) return false;
    if (n < 4) return true;
    if (n % 2 == 0) return false;
    uint64_t witnesses[] = {2, 3, 5, 7, 11, 13};
    for (uint64_t a : witnesses) {
        if (a >= n) break;
        if (!millerRabinTest(n, a)) return false;
    }
    return true;
}

static uint64_t rand32() {
    uint64_t r = 0;
    for (int i = 0; i < 2; ++i) {
        r = (r << 16) | (static_cast<uint64_t>(rand()) & 0xFFFF);
    }
    return r;
}

static uint64_t randomPrime(int bits) {
    if (bits < 10) bits = 10;
    if (bits > 30) bits = 30;
    uint64_t low  = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;
    if (low <= 256) low = 257;
    while (true) {
        uint64_t range = high - low + 1;
        uint64_t candidate = low + (rand32() % range);
        if (candidate % 2 == 0) candidate |= 1;
        if (candidate <= high && isPrime(candidate)) {
            return candidate;
        }
    }
}

static bool parsePair(const uint8_t* key, size_t keySize, uint64_t& p, uint64_t& exp) {
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

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Shamir (бесключевой протокол)";
}

EXPORT const char* getKeyInfo() {
    return "Простое p (p > 255) — общий параметр протокола.\n"
           "Шифрование: \"p,C\" — c = m^C mod p.\n"
           "Дешифрование: \"p,D\" — m = c^D mod p, где C*D ≡ 1 (mod p-1).\n"
           "Базовые функции: binMod() для возведения в степень,\n"
           "modNegative() для вычисления D = C^(-1) mod (p-1).\n"
           "При генерации param = битность p (10-30, рекомендуется 28).";
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
        uint64_t c = binMod(m, C, p);
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
    uint64_t p = 0, D = 0;
    if (!parsePair(key, keySize, p, D)) return -2;
    size_t outCount = dataSize / 8;
    if (*outputSize < outCount) return -3;
    for (size_t i = 0; i < outCount; ++i) {
        uint64_t c = 0;
        for (int b = 0; b < 8; ++b) {
            c = (c << 8) | data[i * 8 + b];
        }
        uint64_t m = binMod(c, D, p);
        output[i] = static_cast<uint8_t>(m & 0xFF);
    }
    *outputSize = outCount;
    return 0;
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    srand(static_cast<unsigned>(time(nullptr)));
    int bits = (param >= 10 && param <= 30) ? param : 28;
    uint64_t p = randomPrime(bits);
    uint64_t phi = p - 1;
    uint64_t C = 0;
    uint64_t start = phi / 2;
    if ((start & 1) == 0) start++;
    for (uint64_t cand = start; cand < phi; cand += 2) {
        if (gcd(cand, phi) == 1) {
            C = cand;
            break;
        }
    }
    if (C == 0) {
        for (uint64_t cand = 3; cand < phi; cand += 2) {
            if (gcd(cand, phi) == 1) {
                C = cand;
                break;
            }
        }
    }
    if (C == 0) return -11;
    uint64_t D = modNegative(C, phi);
    if (D == 0) return -11;
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