// Учебная реализация протокола идентификации Фиата-Шамира.
// Принцип: Сторона A доказывает знание секрета S, не раскрывая его.
// Открытый ключ: v = s^2 mod n (где s - секрет)

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <vector>

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
    for (uint64_t i = 3; i * i <= n; i += 2)
        if (n % i == 0) return false;
    return true;
}

uint64_t randomPrime(uint64_t low, uint64_t high) {
    while (true) {
        uint64_t candidate = low + (rand() % (high - low + 1));
        if (candidate % 2 == 0) candidate++;
        if (candidate <= high && isPrime(candidate)) return candidate;
    }
}

// Структура для хранения доказательства
struct Proof {
    uint64_t x;        // x = r^2 mod n
    uint8_t challenge; // challenge (битовая маска)
    uint64_t y;        // y = r * s^e mod n
};

// Парсинг ключей
bool parseKey(const uint8_t* key, size_t keySize, uint64_t& n, uint64_t& value) {
    char buf[128] = {0};
    if (keySize >= sizeof(buf)) return false;
    memcpy(buf, key, keySize);
    buf[keySize] = '\0';
    
    char* comma = strchr(buf, ',');
    if (!comma) return false;
    *comma = '\0';
    
    n = strtoull(buf, nullptr, 10);
    value = strtoull(comma + 1, nullptr, 10);
    return (n > 0 && value > 0);
}

// Парсинг доказательства из бинарных данных
std::vector<Proof> parseProofs(const uint8_t* data, size_t dataSize, uint64_t n) {
    std::vector<Proof> proofs;
    // Каждый раунд: 8 байт (x) + 1 байт (challenge) + 8 байт (y) = 17 байт
    size_t roundSize = 17;
    size_t rounds = dataSize / roundSize;
    
    for (size_t i = 0; i < rounds; ++i) {
        Proof p;
        size_t offset = i * roundSize;
        
        // Читаем x (8 байт)
        p.x = 0;
        for (int j = 0; j < 8; ++j) {
            p.x = (p.x << 8) | data[offset + j];
        }
        
        // Читаем challenge (1 байт)
        p.challenge = data[offset + 8];
        
        // Читаем y (8 байт)
        p.y = 0;
        for (int j = 0; j < 8; ++j) {
            p.y = (p.y << 8) | data[offset + 9 + j];
        }
        
        proofs.push_back(p);
    }
    return proofs;
}

} // namespace

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Fiat-Shamir (ZK идентификация)";
}

EXPORT const char* getKeyInfo() {
    return "ПРОТОКОЛ ИДЕНТИФИКАЦИИ С НУЛЕВЫМ РАЗГЛАШЕНИЕМ\n\n"
           "Роли:\n"
           "  PROVER (доказывающий) - знает секрет s\n"
           "  VERIFIER (проверяющий) - знает открытый ключ v = s^2 mod n\n\n"
           "Формат ключей:\n"
           "  PROVER: \"n,s\" (секретный ключ)\n"
           "  VERIFIER: \"n,v\" (открытый ключ)\n\n"
           "Протокол (k раундов):\n"
           "  1. Prover выбирает случайный r, отправляет x = r^2 mod n\n"
           "  2. Verifier отправляет случайный бит e (0 или 1)\n"
           "  3. Prover отправляет y = r * s^e mod n\n"
           "  4. Verifier проверяет: y^2 = x * v^e (mod n)\n\n"
           "Вероятность обмана: 2^(-k)\n"
           "Рекомендуемое k: 20 (надёжность 99.9999%)";
}

EXPORT size_t getMinKeySize() { return 5; }
EXPORT size_t getMaxKeySize() { return 256; }

// Функция PROVER: создание доказательства
EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;
    
    uint64_t n = 0, s = 0;
    if (!parseKey(key, keySize, n, s)) return -2;
    if (n <= 255) return -4;
    
    // Количество раундов = размер входных данных (каждый байт = раунд)
    size_t rounds = dataSize;
    size_t requiredSize = rounds * 17; // x(8) + challenge(1) + y(8)
    
    if (*outputSize < requiredSize) return -3;
    
    srand(static_cast<unsigned>(time(nullptr)));
    
    for (size_t round = 0; round < rounds; ++round) {
        // Шаг 1: Prover выбирает случайный r
        uint64_t r;
        do {
            r = 2 + (rand() % (n - 3));
        } while (gcd(r, n) != 1);
        
        uint64_t x = modPow(r, 2, n);
        
        // Шаг 2: Verifier отправляет challenge (в данном случае из входных данных)
        uint8_t e = data[round] % 2;  // challenge - 1 бит
        
        // Шаг 3: Prover вычисляет y = r * s^e mod n
        uint64_t s_pow = (e == 1) ? s : 1;
        uint64_t y = (r * s_pow) % n;
        
        // Упаковываем доказательство
        size_t offset = round * 17;
        
        // x (8 байт, big-endian)
        for (int j = 0; j < 8; ++j) {
            output[offset + j] = static_cast<uint8_t>((x >> (56 - j * 8)) & 0xFF);
        }
        
        // challenge (1 байт)
        output[offset + 8] = e;
        
        // y (8 байт, big-endian)
        for (int j = 0; j < 8; ++j) {
            output[offset + 9 + j] = static_cast<uint8_t>((y >> (56 - j * 8)) & 0xFF);
        }
    }
    
    *outputSize = requiredSize;
    return 0;
}

// Функция VERIFIER: проверка доказательства
EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;
    
    uint64_t n = 0, v = 0;
    if (!parseKey(key, keySize, n, v)) return -2;
    
    // Проверяем, что размер данных кратен размеру раунда
    size_t roundSize = 17;
    if (dataSize % roundSize != 0) return -5;
    
    size_t rounds = dataSize / roundSize;
    if (*outputSize < rounds) return -3;
    
    bool allVerified = true;
    
    for (size_t round = 0; round < rounds; ++round) {
        size_t offset = round * roundSize;
        
        // Читаем x
        uint64_t x = 0;
        for (int j = 0; j < 8; ++j) {
            x = (x << 8) | data[offset + j];
        }
        
        // Читаем challenge
        uint8_t e = data[offset + 8];
        if (e > 1) {
            output[round] = 0;
            allVerified = false;
            continue;
        }
        
        // Читаем y
        uint64_t y = 0;
        for (int j = 0; j < 8; ++j) {
            y = (y << 8) | data[offset + 9 + j];
        }
        
        // Шаг 4: Verifier проверяет y^2 = x * v^e (mod n)
        uint64_t left = modPow(y, 2, n);
        uint64_t right = (x * modPow(v, e, n)) % n;
        
        bool verified = (left == right);
        output[round] = verified ? 1 : 0;
        
        if (!verified) {
            allVerified = false;
            printf("Раунд %zu: проверка не пройдена! "
                   "y^2=%llu, x*v^e=%llu\n", 
                   round, (unsigned long long)left, (unsigned long long)right);
        }
    }
    
    *outputSize = rounds;
    
    if (!allVerified) {
        return -10; // Доказательство не подтверждено
    }
    
    return 0;
}

// Генерация ключей для протокола
EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    
    srand(static_cast<unsigned>(time(nullptr)));
    
    // Генерация n = p * q
    int bits = (param >= 10 && param <= 16) ? param : 12;
    uint64_t low = 1ULL << ((bits / 2) - 1);
    uint64_t high = (1ULL << (bits / 2)) - 1;
    if (low < 17) low = 17;
    
    uint64_t p = randomPrime(low, high);
    uint64_t q;
    do { q = randomPrime(low, high); } while (q == p);
    
    uint64_t n = p * q;
    if (n <= 255) return -10;
    
    // Генерация секрета s (взаимно простой с n)
    uint64_t s;
    do {
        s = 2 + (rand() % (n - 3));
    } while (gcd(s, n) != 1);
    
    // Вычисление открытого ключа v = s^2 mod n
    uint64_t v = modPow(s, 2, n);
    
    char buf[512];
    int written = snprintf(buf, sizeof(buf),
                          "              КЛЮЧИ ДЛЯ ПРОТОКОЛА ФИАТА-ШАМИРА               \n"
                          "ПАРАМЕТРЫ СИСТЕМЫ:\n"
                          "  n = %llu = %llu x %llu\n"
                          "  (безопасность: %d бит)\n\n"
                          "КЛЮЧ PROVER (секретный, НЕ РАЗГЛАШАТЬ):\n"
                          "  \"%llu,%llu\"\n\n"
                          "КЛЮЧ VERIFIER (открытый, можно публиковать):\n"
                          "  \"%llu,%llu\"\n\n"
                          "ПРОВЕРКА: v = s^2 mod n => %llu = %llu^2 mod %llu\n"
                          "  %llu = %llu (mod %llu) %s\n\n"
                          "ИНСТРУКЦИЯ ПО ПРИМЕНЕНИЮ:\n"
                          "  1. Prover: шифрует данные ключом (%llu,%llu) - создаёт доказательство\n"
                          "  2. Verifier: дешифрует ключом (%llu,%llu) - проверяет доказательство\n"
                          "  3. Если дешифрование вернуло все 1 => личность подтверждена\n"
                          "  4. Рекомендуется использовать 20+ раундов для надёжности\n",
                          (unsigned long long)n, (unsigned long long)p, (unsigned long long)q,
                          bits,
                          (unsigned long long)n, (unsigned long long)s,
                          (unsigned long long)n, (unsigned long long)v,
                          (unsigned long long)v, (unsigned long long)s, (unsigned long long)n,
                          (unsigned long long)v, (unsigned long long)((s * s) % n), (unsigned long long)n,
                          (v == (s * s % n)) ? "ВЕРНО" : "ОШИБКА",
                          (unsigned long long)n, (unsigned long long)s,
                          (unsigned long long)n, (unsigned long long)v);
    
    if (written < 0 || static_cast<size_t>(written) >= *keyBufferSize) return -3;
    
    memcpy(keyBuffer, buf, written);
    *keyBufferSize = static_cast<size_t>(written);
    return 0;
}

}