// ============================================================
// Реализация криптосистемы Рабина для системы шифрования.
// ============================================================
// Алгоритм основан на сложности задачи факторизации числа n = p*q,
// где p, q — большие простые числа, удовлетворяющие условию p ≡ q ≡ 3 (mod 4).
//
// Шифрование: c = m^2 mod n (возведение в квадрат по модулю n).
// Дешифрование: нахождение квадратного корня из c по модулю n
// с использованием знания множителей p и q (китайская теорема об остатках).
//
// Для устранения неоднозначности (дешифрование даёт 4 корня)
// используется padding: каждый байт m дублируется в виде m' = (m << 8) | m.
// Это позволяет однозначно выбрать правильный корень из четырёх.
// ============================================================

#include <cstdint>    // Типы uint8_t, uint64_t, int64_t и др.
#include <cstddef>    // Тип size_t
#include <cstdlib>    // Функции rand(), srand()
#include <cstring>    // Функция memcpy() для копирования байт
#include <cstdio>     // Функция snprintf() для форматирования строк
#include <ctime>      // Функция time() для инициализации генератора случайных чисел

#include <string>     // Класс std::string для работы со строками
#include <vector>     // Класс std::vector для динамических массивов
#include <stdexcept>  // Класс std::runtime_error для выброса исключений
#include <algorithm>  // Стандартные алгоритмы

// Макрос для экспорта функций из динамической библиотеки.
// На Windows используется __declspec(dllexport),
// на Linux/macOS — атрибут видимости default.
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

using namespace std;

// ============================================================
// РАЗДЕЛ 1: Базовые криптоматематические функции (cryptoUtils)
// ============================================================
// Эти функции являются основой для всех криптографических вычислений
// в шифре Рабина: возведение в степень по модулю, нахождение НОД
// и модульного обратного элемента.

// Вычисление наибольшего общего делителя (НОД) алгоритмом Евклида.
// Используется внутри modNegative() как побочный результат алгоритма.
//
// Параметры:
//   a, b — два целых числа, для которых ищем НОД
// Возвращает: НОД(a, b)
uint64_t gcd(uint64_t a, uint64_t b)
{
    // Классический алгоритм Евклида через циклическое деление с остатком
    while (b != 0)
    {
        uint64_t temp = b;  // Сохраняем b во временную переменную
        b = a % b;          // Новый b = остаток от деления a на b
        a = temp;           // Новый a = старый b
    }
    return a; // Когда b = 0, в a остаётся НОД
}

// Быстрое возведение в степень по модулю (бинарный алгоритм).
// Вычисляет (base^power) mod modulo за O(log power) умножений.
//
// Параметры:
//   base   — основание степени
//   power  — показатель степени
//   modulo — модуль
// Возвращает: base^power mod modulo
uint64_t binMod(uint64_t base, uint64_t power, uint64_t modulo) {
    base %= modulo;          // Приводим основание по модулю
    power %= modulo - 1;     // Применяем малую теорему Ферма для уменьшения степени
    uint64_t result = 1;     // Начальное значение результата (любое^0 = 1)

    // Цикл по битам показателя степени (от младшего к старшему)
    while (power > 0) {
        // Если текущий младший бит степени = 1, домножаем результат на base
        if (power & 1) {result = (result * base) % modulo;}

        // Возводим основание в квадрат для следующей итерации
        base = (base * base) % modulo;
        // Сдвигаем степень вправо (переходим к следующему биту)
        power >>= 1;
    }
    return result;
}

// Нахождение модульного обратного элемента: x такой, что (base * x) mod modulo = 1.
// Реализовано через расширенный алгоритм Евклида (итеративная версия).
//
// Параметры:
//   base   — число, для которого ищем обратное
//   modulo — модуль
// Возвращает: base^(-1) mod modulo, или 0 если обратного не существует
uint64_t modNegative(uint64_t base, uint64_t modulo) {
    base = base % modulo;    // Приводим base по модулю

    uint64_t m0 = modulo;    // Сохраняем исходный модуль для финальной коррекции
    int64_t u1 = 0, u2 = 1, u3;  // Коэффициенты Безу (могут быть отрицательными)

    // Начальные значения для алгоритма Евклида
    uint64_t q = modulo / base;  // Частное от деления
    uint64_t r = modulo % base;  // Остаток от деления
    uint64_t r0;                 // Будет хранить предыдущий остаток (нужно для проверки НОД)

    // Главный цикл: продолжаем, пока остаток не станет равен 0
    while (r > 0) {
        r0 = r;                  // Сохраняем текущий остаток (для проверки НОД в конце)
        u3 = u1 - u2 * q;        // Вычисляем новый коэффициент Безу

        // Сдвигаем переменные для следующей итерации:
        modulo = base; base = r; // (modulo, base) ← (base, остаток)
        u1 = u2; u2 = u3;        // (u1, u2) ← (u2, новый u3)

        q = modulo / base;       // Новое частное
        r = modulo % base;       // Новый остаток
    }

    // Если последний ненулевой остаток ≠ 1, то НОД(base, m0) ≠ 1,
    // и обратного элемента не существует
    if (r0 != 1) {
        return 0;
    }

    // Если u3 положительное — берём его как есть, иначе прибавляем модуль m0
    // (приводим к положительному значению в диапазоне [0, m0-1])
    uint64_t result = (u3 > 0)? u3 : u3 + m0;

    return result;
}

// ============================================================
// РАЗДЕЛ 2: Вспомогательные структуры и типы
// ============================================================

// Структура для хранения пары ключей Рабина.
// openKey    — открытый ключ, содержит число n (строковое представление).
// privateKey — закрытый ключ, содержит p и q через разделитель '|'.
struct KeyPair {
    std::string openKey;     // Пример: "1234567890123"
    std::string privateKey;  // Пример: "123456789|987654321"
};

// ============================================================
// РАЗДЕЛ 3: Тест простоты и генерация простых чисел
// ============================================================

// Один раунд теста простоты Миллера-Рабина.
// Проверяет, является ли n составным с помощью свидетеля a.
//
// Параметры:
//   n — проверяемое число
//   a — свидетель (основание для проверки)
// Возвращает: true если тест пройден, false если n составное
static bool millerRabinTest(uint64_t n, uint64_t a) {
    // Если n делится на a, то n простое только если n == a
    if (n % a == 0) return n == a;

    // Представляем n-1 в виде d * 2^r, где d нечётное
    uint64_t d = n - 1;
    int r = 0;
    while ((d & 1) == 0) {  // Пока d чётное
        d >>= 1;             // d = d / 2
        r++;                 // Увеличиваем степень двойки
    }

    // Вычисляем x = a^d mod n с помощью нашей функции binMod
    uint64_t x = binMod(a, d, n);

    // Если x = 1 или x = n-1, то n вероятно простое
    if (x == 1 || x == n - 1) return true;

    // Возводим x в квадрат r-1 раз
    for (int i = 0; i < r - 1; ++i) {
        x = (x * x) % n;     // x = x^2 mod n
        if (x == n - 1) return true;  // Тест пройден
    }

    return false; // n составное
}

// Детерминированный тест простоты для чисел до 2^32.
// Использует малый набор свидетелей, достаточный для 32-битных чисел.
//
// Параметры:
//   n — проверяемое число
// Возвращает: true если n простое, false если составное
static bool isPrime(uint64_t n) {
    if (n < 2) return false;       // Числа меньше 2 не простые
    if (n < 4) return true;        // 2 и 3 — простые
    if (n % 2 == 0) return false;  // Чётные (кроме 2) не простые

    // Свидетели, гарантирующие точность для n < 2^32
    uint64_t witnesses[] = {2, 3, 5, 7, 11, 13};

    // Проверяем каждым свидетелем
    for (uint64_t a : witnesses) {
        if (a >= n) break;                       // Свидетель не может быть ≥ n
        if (!millerRabinTest(n, a)) return false; // Тест провален — число составное
    }

    return true; // Все тесты пройдены — число простое
}

// Генерация случайного 32-битного числа.
// Стандартный rand() возвращает число до RAND_MAX (~15 бит),
// поэтому комбинируем 2 вызова rand() по 16 бит.
//
// Возвращает: случайное 32-битное число
static uint64_t rand32() {
    uint64_t r = 0;
    // Собираем 32 бита из двух 16-битных кусков
    for (int i = 0; i < 2; ++i) {
        r = (r << 16) | (static_cast<uint64_t>(rand()) & 0xFFFF);
    }
    return r;
}

// Генерация случайного простого числа заданной битности.
// Генерирует случайные нечётные числа в диапазоне [2^(bits-1), 2^bits - 1]
// и проверяет каждое на простоту.
//
// Параметры:
//   bits — желаемая битность числа
// Возвращает: случайное простое число указанной битности
uint64_t generatePrime(int bits) {
    // Ограничиваем битность разумными рамками
    if (bits < 4) bits = 4;
    if (bits > 30) bits = 30;  // Чтобы p*q ≤ 60 бит (избегаем переполнения)

    // Вычисляем диапазон чисел указанной битности
    uint64_t low  = 1ULL << (bits - 1);      // Минимальное число: 2^(bits-1)
    uint64_t high = (1ULL << bits) - 1;      // Максимальное число: 2^bits - 1

    // Генерируем кандидатов, пока не найдём простое число
    while (true) {
        uint64_t range = high - low + 1;
        uint64_t candidate = low + (rand32() % range);
        if (candidate % 2 == 0) candidate |= 1; // Делаем нечётным

        if (candidate <= high && isPrime(candidate)) {
            return candidate; // Нашли простое
        }
    }
}

// ============================================================
// РАЗДЕЛ 4: Основные функции криптосистемы Рабина
// ============================================================

// Разбор строки закрытого ключа формата "p|q".
// Извлекает два числа p и q, разделённые символом '|'.
//
// Параметры:
//   keyString — строка вида "123|456"
//   n         — выходное значение первого числа (p)
//   e         — выходное значение второго числа (q)
// Возвращает: true если разбор успешен, false при ошибке формата
bool parseRabinKey(const std::string& keyString, uint64_t& n, uint64_t& e) {
    // Ищем позицию разделителя '|' в строке
    size_t pos = keyString.find('|');

    // Проверяем, что разделитель найден
    if (pos == std::string::npos) {
        return false;
    }

    // Проверяем, что не пустые части
    if (pos == 0 || pos == keyString.length() - 1) {
        return false;
    }

    try {
        // Извлекаем p (всё до '|')
        std::string pString = keyString.substr(0, pos);
        // Извлекаем q (всё после '|')
        std::string qString = keyString.substr(pos + 1);

        n = std::stoull(pString);
        e = std::stoull(qString);

        // Проверка валидности
        return (n > 1 && e > 1);

    } catch (const std::exception&) {
        return false;
    }
}

// Извлечение квадратного корня по модулю простого числа p ≡ 3 mod 4.
// Формула: m_p = c^((p+1)/4) mod p
// Работает только для простых p, удовлетворяющих условию Блюма.
//
// Параметры:
//   a — число, из которого извлекаем корень
//   p — простой модуль (p ≡ 3 mod 4)
// Возвращает: sqrt(a) mod p
uint64_t sqrtModPrime(uint64_t a, uint64_t p) {
    if (a % p == 0) return 0;        // Если a делится на p, корень равен 0
    return binMod(a, (p + 1) / 4, p); // Используем функцию binMod из cryptoUtils
}

// Генерация простого числа Блюма (p ≡ 3 mod 4).
// Числа Блюма необходимы для шифра Рабина, так как формула
// извлечения корня sqrtModPrime требует именно такого свойства.
//
// Параметры:
//   bits — битность генерируемого простого числа
// Возвращает: простое число p такое, что p ≡ 3 (mod 4)
uint64_t generatePrimeRubin(int bits) {
    while (true) {
        uint64_t candidate = generatePrime(bits);
        if (candidate % 4 == 3) {  // Проверяем условие Блюма
            return candidate;
        }
    }
}

// Генерация пары ключей для криптосистемы Рабина.
// Открытый ключ: n = p * q (произведение двух простых Блюма).
// Закрытый ключ: p и q по отдельности.
//
// Возвращает: структуру KeyPair с открытым и закрытым ключами
KeyPair keyGeneration() {
    KeyPair keys;

    // Генерируем два различных простых числа Блюма (16-битных)
    uint64_t p = generatePrimeRubin(16);
    uint64_t q = generatePrimeRubin(16);

    // Убеждаемся, что p ≠ q (иначе факторизация тривиальна)
    while (p == q) {
        q = generatePrimeRubin(16);
    }

    // Вычисляем модуль n = p * q
    uint64_t n = p * q;

    // Формируем строковые представления ключей
    keys.openKey = to_string(n);                          // Открытый: "n"
    keys.privateKey = to_string(p) + '|' + to_string(q);  // Закрытый: "p|q"

    return keys;
}

// Проверка padding: значение должно иметь вид 0xAAAA (два одинаковых байта).
// При шифровании мы дублировали байт: m' = (m << 8) | m.
// При дешифровании из 4 корней выбираем тот, который имеет такую структуру.
//
// Параметры:
//   value        — кандидат на правильный корень
//   originalChar — выходной параметр: восстановленный исходный байт
// Возвращает: true если padding верный, false иначе
bool checkRabinPadding(uint64_t value, uint64_t& originalChar) {
    // Padding использует 16-битные значения
    if (value > 0xFFFF) {
        return false;
    }

    // Извлекаем старший и младший байты
    uint64_t highByte = (value >> 8) & 0xFF;
    uint64_t lowByte = value & 0xFF;

    // Проверяем, что байты одинаковы
    if (highByte != lowByte) {
        return false;
    }

    // Padding верный, возвращаем восстановленный байт
    originalChar = lowByte;
    return true;
}

// Шифрование текста криптосистемой Рабина с использованием padding.
// Для каждого символа: c = (m')^2 mod n, где m' = (m << 8) | m.
//
// Параметры:
//   text — исходный текст для шифрования
//   keys — пара ключей (используется openKey = n)
// Возвращает: вектор шифротекста (каждый элемент — uint64_t)
vector<uint64_t> encryptRabin(const std::string& text, KeyPair keys) {
    vector<uint64_t> cipherText;

    // Извлекаем открытый ключ n из строки
    uint64_t n = stoull(keys.openKey);

    // Шифруем каждый символ отдельно
    for (size_t i = 0; i < text.size(); i++) {
        // Получаем код символа (0..255)
        uint64_t m = static_cast<unsigned char>(text[i]);

        // PADDING: дублируем байт для однозначного выбора корня при дешифровании.
        // Пример: 'A' = 0x41 → m_padded = 0x4141
        uint64_t m_padded = (m << 8) | m;

        // Шифруем: c = (m_padded)^2 mod n
        // Используем binMod из cryptoUtils для возведения в степень 2
        uint64_t c = binMod(m_padded, 2, n);

        // Добавляем зашифрованное значение в вектор
        cipherText.push_back(c);
    }

    return cipherText;
}

// Дешифрование шифротекста криптосистемой Рабина.
// Использует китайскую теорему об остатках (CRT) для нахождения корней.
// Из 4 возможных корней выбирается тот, который проходит проверку padding.
//
// Параметры:
//   cipherText — вектор зашифрованных значений
//   keys       — пара ключей (используются openKey = n и privateKey = "p|q")
// Возвращает: расшифрованную строку
string decryption(const vector<uint64_t>& cipherText, KeyPair keys) {
    string plaintext;

    uint64_t p, q;
    uint64_t n = stoull(keys.openKey);     // Извлекаем n из открытого ключа
    parseRabinKey(keys.privateKey, p, q);  // Извлекаем p и q из закрытого

    // Вычисляем коэффициенты CRT с помощью функции modNegative из cryptoUtils.
    // yp * p + yq * q = 1, где:
    //   yp = p^(-1) mod q
    //   yq = q^(-1) mod p
    uint64_t yp = modNegative(p, q);
    uint64_t yq = modNegative(q, p);

    // Обрабатываем каждое зашифрованное значение
    for (size_t i = 0; i < cipherText.size(); i++) {
        uint64_t c = cipherText[i];

        // Шаг 1: Находим квадратные корни по модулю p и q
        // mp = c^((p+1)/4) mod p
        // mq = c^((q+1)/4) mod q
        uint64_t mp = sqrtModPrime(c, p);
        uint64_t mq = sqrtModPrime(c, q);

        // Шаг 2: Вычисляем части формулы CRT
        // term1 = yp * p * mq mod n
        // term2 = yq * q * mp mod n
        uint64_t term1 = ((yp * p) % n * mq) % n;
        uint64_t term2 = ((yq * q) % n * mp) % n;

        // Шаг 3: Четыре корня по формулам Рабина
        // r1 = (term1 + term2) mod n
        uint64_t r1 = (term1 + term2) % n;

        // r2 = n - r1 (отрицание по модулю n)
        uint64_t r2 = (r1 == 0) ? 0 : n - r1;

        // r3 = (term1 - term2) mod n
        uint64_t r3;
        if (term1 >= term2) {
            r3 = term1 - term2;        // Обычное вычитание
        } else {
            r3 = n - (term2 - term1);  // Вычитание с переносом через n
        }

        // r4 = n - r3
        uint64_t r4 = (r3 == 0) ? 0 : n - r3;

        // Шаг 4: Выбираем правильный корень через проверку padding.
        // Правильный корень имеет вид 0xAAAA (два одинаковых байта).
        uint64_t decrypted = 0;
        bool found = false;

        // Последовательно проверяем все 4 корня
        if (checkRabinPadding(r1, decrypted)) {
            found = true;
        }
        else if (checkRabinPadding(r2, decrypted)) {
            found = true;
        }
        else if (checkRabinPadding(r3, decrypted)) {
            found = true;
        }
        else if (checkRabinPadding(r4, decrypted)) {
            found = true;
        }

        // Если ни один корень не прошёл проверку — данные повреждены
        if (!found) {
            throw runtime_error("Rabin decryption failed: no root passes padding check");
        }

        // Добавляем восстановленный символ в результат
        plaintext.push_back(static_cast<char>(decrypted));
    }

    return plaintext;
}

// ============================================================
// РАЗДЕЛ 5: Обёртки для унифицированного C-интерфейса плагина
// ============================================================
// Эти функции являются «мостом» между внутренней логикой (C++ с string, vector)
// и внешним интерфейсом приложения (C с байтовыми буферами uint8_t*).
// Все функции объявлены как extern "C" для совместимости с dlsym().

extern "C" {

// Возвращает человекочитаемое название алгоритма
EXPORT const char* getAlgorithmName() {
    return "Rabin (асимметричный шифр с padding)";
}

// Возвращает справочный текст о формате ключей
EXPORT const char* getKeyInfo() {
    return "Шифрование: \"n\" (n = p*q, p≡q≡3 mod 4).\n"
           "Дешифрование: \"p|q\" (через символ '|').\n"
           "Padding: m_padded = (m << 8) | m для однозначного выбора корня.\n"
           "Каждый исходный байт шифруется в 8 байт (uint64_t).\n"
           "Используются 16-битные простые числа Блюма.";
}

// Минимальный и максимальный размер ключа в байтах
EXPORT size_t getMinKeySize() { return 1; }
EXPORT size_t getMaxKeySize() { return 64; }

// Обёртка шифрования: байты → string → encryptRabin() → vector<uint64_t> → байты
EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    // Проверка указателей
    if (!data || !key || !output || !outputSize) return -1;

    // Каждый байт → 8 байт шифротекста, проверяем размер буфера
    if (*outputSize < dataSize * 8) return -3;

    try {
        // Формируем KeyPair: открытый ключ — строка с числом n
        KeyPair keys;
        keys.openKey = std::string(reinterpret_cast<const char*>(key), keySize);

        // Проверяем, что ключ корректно парсится как число
        try {
            uint64_t n = std::stoull(keys.openKey);
            if (n <= 0xFFFF) return -4; // n должно быть больше 16 бит для padding
        } catch (...) {
            return -2;
        }

        // Преобразуем входные байты в строку
        std::string text(reinterpret_cast<const char*>(data), dataSize);

        // Вызываем основную функцию шифрования
        std::vector<uint64_t> cipher = encryptRabin(text, keys);

        // Сериализуем vector<uint64_t> в байты (по 8 байт на символ, big-endian)
        for (size_t i = 0; i < cipher.size(); ++i) {
            uint64_t c = cipher[i];
            for (int b = 7; b >= 0; --b) {
                output[i * 8 + (7 - b)] = static_cast<uint8_t>((c >> (b * 8)) & 0xFF);
            }
        }
        *outputSize = cipher.size() * 8;
        return 0;

    } catch (const std::exception&) {
        return -2;
    }
}

// Обёртка дешифрования: байты → vector<uint64_t> → decryption() → string → байты
EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    // Шифротекст должен быть кратен 8 байтам
    if (dataSize % 8 != 0) return -5;

    try {
        // Формируем KeyPair с закрытым ключом "p|q"
        KeyPair keys;
        keys.privateKey = std::string(reinterpret_cast<const char*>(key), keySize);

        // Разбираем закрытый ключ на p и q
        uint64_t p = 0, q = 0;
        if (!parseRabinKey(keys.privateKey, p, q)) return -2;

        // Восстанавливаем n = p * q для открытого ключа
        uint64_t n = p * q;
        keys.openKey = std::to_string(n);

        size_t outCount = dataSize / 8;
        if (*outputSize < outCount) return -3;

        // Десериализуем байты в vector<uint64_t> (big-endian)
        std::vector<uint64_t> cipher(outCount);
        for (size_t i = 0; i < outCount; ++i) {
            uint64_t c = 0;
            for (int b = 0; b < 8; ++b) {
                c = (c << 8) | data[i * 8 + b];
            }
            cipher[i] = c;
        }

        // Вызываем основную функцию дешифрования
        std::string plaintext = decryption(cipher, keys);

        // Копируем результат в выходной буфер
        std::memcpy(output, plaintext.data(), plaintext.size());
        *outputSize = plaintext.size();
        return 0;

    } catch (const std::exception&) {
        return -2;
    }
}

// Обёртка генерации ключа через keyGeneration().
// Выводит оба ключа (открытый и закрытый) одной строкой.
EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    (void)param; // Параметр не используется

    // Инициализируем генератор случайных чисел
    srand(static_cast<unsigned>(time(nullptr)));

    try {
        // Вызываем основную функцию генерации
        KeyPair keys = keyGeneration();

        // Форматируем вывод: "PUB:n PRIV:p|q"
        std::string output = "PUB:" + keys.openKey + " PRIV:" + keys.privateKey;

        if (output.size() >= *keyBufferSize) return -3;

        std::memcpy(keyBuffer, output.data(), output.size());
        *keyBufferSize = output.size();
        return 0;

    } catch (const std::exception&) {
        return -10;
    }
}

} // extern "C"