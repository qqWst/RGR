// Учебная реализация RSA с поддержкой больших чисел.
// Модуль n — до 64 бит. Промежуточные умножения выполняются через __int128.
// Каждый байт шифруется отдельно, результат — 8 байт (64-битное число).

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

// Тип большого числа (128 бит) — поддерживается GCC и Clang.
using BigInt = unsigned __int128;

// Умножение по модулю без переполнения
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

// Расширенный алгоритм Евклида для модульного обратного
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

// Тест Миллера-Рабина для проверки простоты больших чисел
bool millerRabinTest(uint64_t n, uint64_t a) {
    // Шаг 1: Проверка делимости
    // Если n делится на a, то n может быть равно a (тогда a простое)
    // или n составное (если a < n и делится без остатка)
    if (n % a == 0) return n == a;
    // Шаг 2: Представляем n-1 как d * 2^r (где d нечётное)
    uint64_t d = n - 1;
    int r = 0;
    while ((d & 1) == 0) { d >>= 1; r++;  } // Увеличиваем счётчик степени двойки

    // Шаг 3: Вычисляем a^d mod n (первое свидетельство)
    uint64_t x = binMod(a, d, n);

    // Шаг 4: Проверка тривиальных случаев
    // Если x ≡ 1 (mod n) или x ≡ -1 (mod n), то n вероятно простое
    if (x == 1 || x == n - 1) return true;
    // Шаг 5: Последовательно возводим в квадрат r-1 раз
    // Проверяем, появится ли -1 на каком-то шаге
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

    // Свидетели, гарантирующие точность теста для n < 2^64
    uint64_t witnesses[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    for (uint64_t a : witnesses) {
        if (a >= n) break;
        if (!millerRabinTest(n, a)) return false;
    }
    return true;
}

// Случайное 64-битное число (комбинируем несколько rand())
uint64_t rand64() {
    // 1. Инициализируем 64-битный результат нулём
    uint64_t r = 0;
    // 2. Выполняем 4 итерации (4 * 16 бит = 64 бита)
    for (int i = 0; i < 4; ++i) {
        // 3. Сдвигаем текущий результат влево на 16 бит
        //    Освобождаем место для новых 16 бит в младших разрядах
        r = (r << 16) |
            // 4. Получаем 16 бит от rand() и добавляем их в младшие разряды
            (static_cast<uint64_t>(rand()) & 0xFFFF);
    }
    return r;
}

// Случайное простое число в диапазоне [low, high]
uint64_t randomPrime(uint64_t low, uint64_t high) {
    while (true) {
        // 1. Вычисляем размер диапазона
        uint64_t range = high - low + 1;
        // 2. Генерируем случайное число в диапазоне [low, high]
        uint64_t candidate = low + (rand64() % range);
        // 3. Делаем число нечётным (если чётное, то единственное простое - 2)
        // устанавливаем младший бит в единицу
        if (candidate % 2 == 0) candidate |= 1;
        // Шаг 4: Проверяем результат
        // candidate <= high - защита от переполнения (если low был чётным и high+1)
        if (candidate <= high && isPrime(candidate)) return candidate;
    }
}

// Разбор ключа "n,e"
// Функция преобразует строковый ключ формата "модуль,экспонента" в числа
// Пример: "3233,17" -> n=3233, exp=17
// Возвращает true при успешном разборе, false при ошибке
bool parseKey(const uint8_t* key, size_t keySize, uint64_t& n, uint64_t& exp) {
    // Шаг 1: Создаём буфер для строковой копии ключа
    // Размер 128 байт достаточно для большинства ключей RSA
    char buf[128] = {0};

    // Шаг 2: Проверяем, что ключ не превышает размер буфера
    if (keySize >= sizeof(buf)) return false;

    // Шаг 3: Копируем двоичные данные в буфер
    // key - указатель на начало данных
    // keySize - количество байт для копирования
    memcpy(buf, key, keySize);

    // Шаг 4: Добавляем нуль-терминатор в конец строки
    buf[keySize] = '\0';

    // Шаг 5: Ищем запятую-разделитель в строке
    char* comma = strchr(buf, ',');

    // Шаг 6: Если запятая не найдена - формат неверный
    if (!comma) return false;

    // Шаг 7: Заменяем запятую на нуль-терминатор
    // Это разделяет строку на две части: первое число и второе число
    *comma = '\0';

    // Шаг 8: Преобразуем первую часть (до запятой) в число (n - модуль)
    // strtoull = string to unsigned long long
    n   = strtoull(buf, nullptr, 10);

    // Шаг 9: Преобразуем вторую часть (после запятой) в число (exp - экспонента)
    // comma + 1 - указатель на символ после запятой
    exp = strtoull(comma + 1, nullptr, 10);
    // Шаг 10: Проверяем, что оба числа положительные
    return (n > 0 && exp > 0);
}

} // namespace

//директива линковки 
//указывает C++ компилятору использовать
//C-стиль именования и линковки для функций внутри блока
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
        // Записываем 8 байт (старшие первыми)
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

    // Битность по умолчанию 56 (n ≈ 2^56, p,q ≈ 2^28)
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

    // Выбираем e (стандарт: 65537, иначе 17 или 3)
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