// Плагин: протокол Фиат-Шамир (доказательство с нулевым разглашением).
//   encrypt(message, private_key) → доказательство в виде байт
//   decrypt(proof,   public_key)  → "VERIFIED" или "FAILED"

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>
#include <sstream>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

using namespace std;

static const int FIAT_SHAMIR_ROUNDS = 20;

namespace {

uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) { uint64_t t = b; b = a % b; a = t; }
    return a;
}

uint64_t binMod(uint64_t base, uint64_t power, uint64_t modulo) {
    base %= modulo;
    if (modulo > 1) power %= modulo - 1;
    uint64_t result = 1;
    while (power > 0) {
        if (power & 1) result = (result * base) % modulo;
        base = (base * base) % modulo;
        power >>= 1;
    }
    return result;
}

bool millerRabinTest(uint64_t n, uint64_t a) {
    if (n % a == 0) return n == a;
    uint64_t d = n - 1; int r = 0;
    while ((d & 1) == 0) { d >>= 1; r++; }
    uint64_t x = binMod(a, d, n);
    if (x == 1 || x == n - 1) return true;
    for (int i = 0; i < r - 1; ++i) {
        x = (x * x) % n;
        if (x == n - 1) return true;
    }
    return false;
}

bool isPrime(uint64_t n) {
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

uint64_t rand32() {
    uint64_t r = 0;
    for (int i = 0; i < 2; ++i) r = (r << 16) | (static_cast<uint64_t>(rand()) & 0xFFFF);
    return r;
}

uint64_t generatePrime(int bits) {
    if (bits < 8) bits = 8;
    if (bits > 16) bits = 16;
    uint64_t low  = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;
    while (true) {
        uint64_t range = high - low + 1;
        uint64_t c = low + (rand32() % range);
        if (c % 2 == 0) c |= 1;
        if (c <= high && isPrime(c)) return c;
    }
}

// Парсинг ключа формата "n,X" где X — либо S, либо V
bool parseKey(const uint8_t* key, size_t keySize, uint64_t& n, uint64_t& x) {
    char buf[64] = {0};
    if (keySize >= sizeof(buf)) return false;
    memcpy(buf, key, keySize);
    char* comma = strchr(buf, ',');
    if (!comma) return false;
    *comma = '\0';
    n = strtoull(buf, nullptr, 10);
    x = strtoull(comma + 1, nullptr, 10);
    return n > 1 && x > 0;
}

// Хеш-функция для генерации challenge (детерминированная)
int hashToBit(uint64_t x, int round) {
    uint64_t h = 0xCAFEBABE;
    h = h * 31 + x;
    h = h * 31 + static_cast<uint64_t>(round);
    return static_cast<int>(h & 1);
}

} // namespace

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Fiat-Shamir (доказательство знания секрета)";
}

EXPORT const char* getKeyInfo() {
    return "Протокол доказательства с нулевым разглашением (ZKP).\n"
           "\n"
           "В отличие от обычных шифров, Fiat-Shamir НЕ скрывает сообщение,\n"
           "а позволяет доказать знание секрета без его раскрытия.\n"
           "\n"
           "СЦЕНАРИЙ работы через стандартное меню:\n"
           "\n"
           "1. Генерация ключей (пункт 3 главного меню):\n"
           "     Получите пару: PUB:n,V и PRIV:n,S\n"
           "\n"
           "2. \"Шифрование\" текста (пункт 1, режим 1):\n"
           "     Введите любое сообщение и закрытый ключ \"n,S\".\n"
           "     Результат (hex) — это ваше ДОКАЗАТЕЛЬСТВО знания S.\n"
           "     Передайте его проверяющей стороне.\n"
           "\n"
           "3. \"Дешифрование\" доказательства (пункт 1, режим 2):\n"
           "     Введите доказательство (hex) и открытый ключ \"n,V\".\n"
           "     Результат: VERIFIED или FAILED \n"
           "\n"
           "Шифрование (создание доказательства): ключ \"n,S\".\n"
           "Дешифрование (проверка):              ключ \"n,V\".";
}

EXPORT size_t getMinKeySize() { return 3; }
EXPORT size_t getMaxKeySize() { return 128; }

// encrypt = создание доказательства знания S
EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;
    (void)data; (void)dataSize;

    uint64_t n = 0, S = 0;
    if (!parseKey(key, keySize, n, S)) return -2;
    if (S == 0 || S >= n) return -4;

    uint64_t V = (S * S) % n;
    srand(static_cast<unsigned>(time(nullptr)));

    // Формируем доказательство как текстовую строку
    std::ostringstream proof;
    proof << "FS|" << n << "|" << V;

    for (int round = 0; round < FIAT_SHAMIR_ROUNDS; ++round) {
        uint64_t r = 2 + (rand32() % (n - 3));
        uint64_t x = (r * r) % n;
        int e = hashToBit(x, round);
        uint64_t y = (e == 0) ? r : (r * S) % n;
        proof << "|" << x << "," << y;
    }

    std::string s = proof.str();
    if (s.size() >= *outputSize) return -3;
    memcpy(output, s.data(), s.size());
    *outputSize = s.size();
    return 0;
}

// decrypt = проверка доказательства
EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    uint64_t n = 0, V = 0;
    if (!parseKey(key, keySize, n, V)) return -2;

    std::string proofStr(reinterpret_cast<const char*>(data), dataSize);

    auto writeResult = [&](const std::string& s) -> int {
        if (s.size() >= *outputSize) return -3;
        memcpy(output, s.data(), s.size());
        *outputSize = s.size();
        return 0;
    };

    if (proofStr.substr(0, 3) != "FS|") {
        return writeResult("FAILED: неверный формат доказательства");
    }

    // Разбираем доказательство по разделителю '|'
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos < proofStr.size()) {
        size_t next = proofStr.find('|', pos);
        if (next == std::string::npos) {
            parts.push_back(proofStr.substr(pos));
            break;
        }
        parts.push_back(proofStr.substr(pos, next - pos));
        pos = next + 1;
    }

    if (parts.size() < 4) return writeResult("FAILED: доказательство неполное");

    uint64_t nProof = strtoull(parts[1].c_str(), nullptr, 10);
    uint64_t VProof = strtoull(parts[2].c_str(), nullptr, 10);

    if (nProof != n || VProof != V) {
        return writeResult("FAILED: ключ не соответствует доказательству");
    }

    int numRounds = static_cast<int>(parts.size()) - 3;
    int passed = 0;

    for (int round = 0; round < numRounds; ++round) {
        const std::string& rd = parts[3 + round];
        size_t comma = rd.find(',');
        if (comma == std::string::npos) break;

        uint64_t x = strtoull(rd.substr(0, comma).c_str(), nullptr, 10);
        uint64_t y = strtoull(rd.substr(comma + 1).c_str(), nullptr, 10);

        int e = hashToBit(x, round);
        uint64_t left = (y * y) % n;
        uint64_t right = (e == 0) ? x : (x * V) % n;
        if (left == right) passed++;
    }

    std::ostringstream result;
    if (passed == numRounds) {
        result << "VERIFIED ✓ Доказательство подлинно ("
               << passed << "/" << numRounds << " раундов пройдено)";
    } else {
        result << "FAILED ✗ Доказательство НЕ подлинно ("
               << passed << "/" << numRounds << " раундов пройдено)";
    }
    return writeResult(result.str());
}

// Генерация пары ключей
EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    (void)param;
    srand(static_cast<unsigned>(time(nullptr)));

    uint64_t p = generatePrime(14);
    uint64_t q;
    do { q = generatePrime(14); } while (q == p);
    uint64_t n = p * q;

    uint64_t S = 0;
    for (int i = 0; i < 100; ++i) {
        uint64_t c = 2 + (rand32() % (n - 3));
        if (gcd(c, n) == 1) { S = c; break; }
    }
    if (S == 0) return -10;

    uint64_t V = (S * S) % n;

    char buf[256];
    int w = snprintf(buf, sizeof(buf),
                     "PUB (для проверки): %llu,%llu\n"
                     "PRIV (для создания доказательств): %llu,%llu",
                     (unsigned long long)n, (unsigned long long)V,
                     (unsigned long long)n, (unsigned long long)S);
    if (w < 0 || static_cast<size_t>(w) >= *keyBufferSize) return -3;
    memcpy(keyBuffer, buf, w);
    *keyBufferSize = static_cast<size_t>(w);
    return 0;
}

}