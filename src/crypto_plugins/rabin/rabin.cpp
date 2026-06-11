#include "../pluginInterface.h"
#include "../crypto_utils/cryptoUtils.h"
#include "../../prime_generator/primeGenerator.h"

#include <algorithm>

using namespace std;

bool parseRabinKey(const std::string& keyString, uint64_t& n, uint64_t& e) {
    // Ищем позицию разделителя '|'
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

// Функция для извлечения квадратного корня по модулю простого числа p ≡ 3 mod 4
uint64_t sqrtModPrime(uint64_t a, uint64_t p) {
    if (a % p == 0) return 0;
    return mod(a, (p + 1) / 4, p);
}

uint64_t generatePrimeRubin(int bits) {
    while (true) {
        uint64_t candidate = generatePrime(bits);
        if (candidate % 4 == 3) {
            return candidate;
        }
    }
}

// Генерация ключей для криптосистемы Рабина
KeyPair keyGeneration() {
    KeyPair keys;
    // Генерируем простые числа в диапазоне от 65536 до 131072 для демонстрации
    // В реальном использовании нужны числа порядка 1024-2048 бит
    uint64_t p = generatePrimeRubin(16);
    uint64_t q = generatePrimeRubin(16);
    
    while (p == q) {
        q = generatePrimeRubin(16);
    }
    
    uint64_t n = p * q;

    keys.openKey = to_string(n);
    keys.privateKey = to_string(p) + '|' + to_string(q);

    return keys;
}

// Функция шифрования (c = m^2 mod n)
vector<uint64_t> encrypt(const std::string& text, KeyPair keys) {
    vector<uint64_t> cipherText;

    uint64_t n = stoull(keys.openKey);
    
    for (size_t i = 0; i < text.size(); i++) {
        uint64_t m = static_cast<unsigned char>(text[i]); // Получаем код символа
        uint64_t c = mod(m, 2, n); // c = m^2 mod n
        cipherText.push_back(c);
        
        // Для отладки (можно закомментировать)
        // cout << "Символ '" << text[i] << "' (код: " << m << ") -> " << c << endl;
    }
    
    return cipherText;
}

// Функция дешифрования с использованием китайской теоремы об остатках
string decryption(const vector<uint64_t>& cipherText, KeyPair keys) {
    string plaintext;

    uint64_t p, q;
    uint64_t n = stoull(keys.openKey);
    parseRabinKey(keys.privateKey, p, q); // 1234|5432
    
    // Вычисляем вспомогательные коэффициенты для CRT
    uint64_t inv_p = modNegative(p, q); // p^(-1) mod q
    uint64_t inv_q = modNegative(q, p); // q^(-1) mod p
    
    for (size_t i = 0; i < cipherText.size(); i++) {
        uint64_t c = cipherText[i];
        
        // Шаг 1: Находим квадратные корни по модулю p и q
        uint64_t mp = sqrtModPrime(c, p);
        uint64_t mq = sqrtModPrime(c, q);
        
        // Шаг 2: Находим 4 возможных корня с помощью CRT
        // r1 = (mp * q * inv_q + mq * p * inv_p) mod n
        // r2 = (mp * q * inv_q - mq * p * inv_p) mod n
        // r3 = (-mp * q * inv_q + mq * p * inv_p) mod n
        // r4 = (-mp * q * inv_q - mq * p * inv_p) mod n
        
        int64_t term1 = (int64_t)mp * q % n * inv_q % n;
        int64_t term2 = (int64_t)mq * p % n * inv_p % n;
        
        uint64_t r1 = (term1 + term2) % n;
        uint64_t r2 = (term1 - term2 + n) % n;
        uint64_t r3 = (-term1 + term2 + n) % n;
        uint64_t r4 = (-term1 - term2 + 2 * n) % n;
        
        // Шаг 3: Выбираем правильный вариант (код символа должен быть в диапазоне 0-255 для UTF-8)
        uint64_t decrypted = 0;
        if (r1 <= 255) decrypted = r1;
        else if (r2 <= 255) decrypted = r2;
        else if (r3 <= 255) decrypted = r3;
        else if (r4 <= 255) decrypted = r4;
        else decrypted = r1 % 256; // Fallback: берем младший байт
        
        plaintext.push_back(static_cast<char>(decrypted));
        
        // Для отладки (можно закомментировать)
        // cout << "Шифротекст: " << c << " -> Расшифровано: " << decrypted << " -> '" << static_cast<char>(decrypted) << "'" << endl;
    }
    
    return plaintext;
}