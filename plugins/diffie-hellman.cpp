// Плагин: протокол Диффи-Хеллмана
// Работает ТОЛЬКО через генератор ключей.
// Шифрование/дешифрование не поддерживаются (это не шифр, а протокол обмена ключами).

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <string>

using namespace std;

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

static uint64_t binMod(uint64_t base, uint64_t power, uint64_t modulo) {
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
    for (size_t i = 0; i < sizeof(witnesses)/sizeof(witnesses[0]); ++i) {
        uint64_t a = witnesses[i];
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

static uint64_t generateSafePrime(int bits) {
    if (bits < 10) bits = 10;
    if (bits > 24) bits = 24;
    uint64_t low  = 1ULL << (bits - 1);
    uint64_t high = (1ULL << bits) - 1;
    while (true) {
        uint64_t range = high - low + 1;
        uint64_t c = low + (rand32() % range);
        if (c % 4 != 3) c += (3 - c % 4 + 4) % 4;
        if (c > high) continue;
        if (isPrime(c) && isPrime((c - 1) / 2)) return c;
    }
}

static uint64_t findGenerator(uint64_t p) {
    uint64_t q = (p - 1) / 2;
    for (uint64_t g = 2; g < p; ++g) {
        if (binMod(g, 2, p) == 1) continue;
        if (binMod(g, q, p) == 1) continue;
        return g;
    }
    return 2;
}

static bool parsePrivateKey(const string& s, uint64_t& p, uint64_t& g, uint64_t& a) {
    size_t c1 = s.find(',');
    if (c1 == string::npos) return false;
    size_t c2 = s.find(',', c1 + 1);
    if (c2 == string::npos) return false;
    try {
        p = stoull(s.substr(0, c1));
        g = stoull(s.substr(c1 + 1, c2 - c1 - 1));
        a = stoull(s.substr(c2 + 1));
        return p > 1 && g > 1 && a > 0;
    } catch (...) {
        return false;
    }
}

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Diffie-Hellman (обмен ключами)";
}

EXPORT const char* getKeyInfo() {
    return "Протокол согласования общего секретного ключа.\n"
           "\n"
           "Этот алгоритм НЕ шифрует данные.\n"
           "Работает ТОЛЬКО через пункт меню \"Генератор ключей\".\n"
           "\n"
           "Параметр генерации:\n"
           "  0 — сгенерировать свою пару (PUBLIC + PRIVATE)\n"
           "  1 — вычислить общий ключ (нужно ввести публичное значение\n"
           "      партнёра и свой закрытый ключ)\n";
}

EXPORT size_t getMinKeySize() { return 1; }
EXPORT size_t getMaxKeySize() { return 512; }

// Шифрование не поддерживается
EXPORT int encrypt(const uint8_t* /*data*/, size_t /*dataSize*/,
                   const uint8_t* /*key*/, size_t /*keySize*/,
                   uint8_t* /*output*/, size_t* /*outputSize*/) {
    return -2;
}

// Дешифрование не поддерживается
EXPORT int decrypt(const uint8_t* /*data*/, size_t /*dataSize*/,
                   const uint8_t* /*key*/, size_t /*keySize*/,
                   uint8_t* /*output*/, size_t* /*outputSize*/) {
    return -2;
}

// Универсальная функция: в зависимости от param выполняет разные действия
EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;

    srand(static_cast<unsigned>(time(NULL)));

    //РЕЖИМ 1: Сгенерировать новую пару
    if (param == 0) {
        int bits = 20;
        uint64_t p = generateSafePrime(bits);
        uint64_t g = findGenerator(p);
        uint64_t a = 2 + (rand32() % (p - 3));
        uint64_t A = binMod(g, a, p);

        char buf[256];
        int w = snprintf(buf, sizeof(buf),
                         "Сгенерирована новая пара ключей:\n"
                         "  PUBLIC (передайте партнёру): %llu\n"
                         "  PRIVATE (сохраните в тайне): %llu,%llu,%llu\n"
                         "\n"
                         "Для вычисления общего ключа выберите этот алгоритм\n"
                         "снова в генераторе с параметром 1.",
                         (unsigned long long)A,
                         (unsigned long long)p, (unsigned long long)g, (unsigned long long)a);

        if (w < 0 || (size_t)w >= *keyBufferSize) return -3;
        memcpy(keyBuffer, buf, w);
        *keyBufferSize = (size_t)w;
        return 0;
    }

    // РЕЖИМ 2: Вычислить общий ключ 
    cout << "\nВведите публичное значение партнёра (число): ";
    string partnerStr;
    getline(cin, partnerStr);

    cout << "Введите ваш закрытый ключ (формат \"p,g,a\"): ";
    string privateStr;
    getline(cin, privateStr);

    // Разбираем закрытый ключ
    uint64_t p = 0, g = 0, a = 0;
    if (!parsePrivateKey(privateStr, p, g, a)) {
        const char* err = "Ошибка: неверный формат закрытого ключа (нужно \"p,g,a\")";
        size_t len = strlen(err);
        if (len >= *keyBufferSize) return -3;
        memcpy(keyBuffer, err, len);
        *keyBufferSize = len;
        return 0;
    }

    // Разбираем публичное значение партнёра
    uint64_t partnerPublic = 0;
    try {
        partnerPublic = stoull(partnerStr);
    } catch (...) {
        const char* err = "Ошибка: публичное значение должно быть числом";
        size_t len = strlen(err);
        if (len >= *keyBufferSize) return -3;
        memcpy(keyBuffer, err, len);
        *keyBufferSize = len;
        return 0;
    }

    if (partnerPublic < 2 || partnerPublic >= p) {
        const char* err = "Ошибка: публичное значение должно быть в диапазоне [2, p-1]";
        size_t len = strlen(err);
        if (len >= *keyBufferSize) return -3;
        memcpy(keyBuffer, err, len);
        *keyBufferSize = len;
        return 0;
    }

    // Вычисляем общий ключ: K = partnerPublic^a mod p
    uint64_t sharedKey = binMod(partnerPublic, a, p);

    char buf[256];
    int w = snprintf(buf, sizeof(buf),
                     "Общий секретный ключ: %llu\n"
                     "\n"
                     "Этот же ключ получит ваш партнёр, используя ваше\n"
                     "публичное значение и свой закрытый ключ.\n"
                     "Используйте его как ключ для XOR-шифрования.",
                     (unsigned long long)sharedKey);

    if (w < 0 || (size_t)w >= *keyBufferSize) return -3;
    memcpy(keyBuffer, buf, w);
    *keyBufferSize = (size_t)w;
    return 0;
}

}