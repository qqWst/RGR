#include <cstdint>
#include <algorithm>

#include "../pluginInterface.h"
#include "../crypto_utils/cryptoUtils.h"
#include "../../prime_generator/primeGenerator.h"   

bool parseRSAKey(const std::string& key_str, uint64_t& n, uint64_t& e) {
    // Ищем позицию разделителя '|'
    size_t pos = key_str.find('|');
    
    // Проверяем, что разделитель найден
    if (pos == std::string::npos) {
        return false;
    }
    
    // Проверяем, что не пустые части
    if (pos == 0 || pos == key_str.length() - 1) {
        return false;
    }
    
    try {
        // Извлекаем n (всё до '|')
        std::string n_str = key_str.substr(0, pos);
        // Извлекаем e (всё после '|')
        std::string e_str = key_str.substr(pos + 1);
        
        n = std::stoull(n_str);
        e = std::stoull(e_str);
        
        // Проверка валидности
        return (n > 1 && e > 1);
        
    } catch (const std::exception&) {
        return false;
    }
}

KeyPair keyGeneration() {
    KeyPair keys;

    uint64_t p = generate_prime(16);
    uint64_t q = generate_prime(16);
    while (p == q) q = generate_prime(16);

    uint64_t n = p * q; 
    uint64_t phi = (p - 1) * (q - 1);

    uint64_t e = 65537;
    if (e >= phi) e = 17;
    while (gcd(e, phi) != 1) e += 2;

    uint64_t d = modNegative(e, phi);

    keys.openKey = std::to_string(e) + '|' + std::to_string(n);
    keys.privateKey = std::to_string(d) + '|' + std::to_string(n);

    return keys;
}

std::vector<uint64_t> encrypt(const std::string& text, KeyPair keys) 
{
    std::vector<uint64_t> result;
    uint64_t n, e;
    parseRSAKey(keys.openKey, n, e);
    for (int i = 0; i < text.size(); i++) 
    {
        uint64_t number = (unsigned char)text[i];
        uint64_t encryptedChar = mod(number, e, n); 
        
        result.push_back(encryptedChar);
    }
    return result;
}

std::string decrypt(const std::vector<uint64_t>& text, KeyPair keys) 
{
    std::string result;
    uint64_t d, n;
    parseRSAKey(keys.openKey, n, d);
    for (int i = 0; i < text.size(); i++) 
    {
        uint64_t decryptedNumber = mod(text[i], d, n);
        char decryptedChar = (char)(unsigned char)decryptedNumber;
        
        result.push_back(decryptedChar);
    }
    return result;
}

