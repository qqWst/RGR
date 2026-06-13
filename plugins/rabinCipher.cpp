#include <cstdint>    
#include <cstddef>    
#include <cstdlib>   
#include <cstring>  
#include <cstdio>     
#include <ctime>      

#include <string>    
#include <vector>    
#include <stdexcept>  
#include <algorithm> 

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
        if (power & 1) {result = (result * base) % modulo;}

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

        modulo = base; base = r; 
        u1 = u2; u2 = u3;     

        q = modulo / base;     
        r = modulo % base;     
    }

    if (r0 != 1) {
        return 0;
    }


    uint64_t result = (u3 > 0)? u3 : u3 + m0;

    return result;
}


struct KeyPair {
    std::string openKey;     
    std::string privateKey;  
};

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

uint64_t generatePrime(int bits) {
    if (bits < 4) bits = 4;
    if (bits > 30) bits = 30;  

    uint64_t low  = 1ULL << (bits - 1);     
    uint64_t high = (1ULL << bits) - 1;      

    while (true) {
        uint64_t range = high - low + 1;
        uint64_t candidate = low + (rand32() % range);
        if (candidate % 2 == 0) candidate |= 1; 

        if (candidate <= high && isPrime(candidate)) {
            return candidate; 
        }
    }
}

bool parseRabinKey(const std::string& keyString, uint64_t& n, uint64_t& e) {
    size_t pos = keyString.find('|');

    if (pos == std::string::npos) {
        return false;
    }

    if (pos == 0 || pos == keyString.length() - 1) {
        return false;
    }

    try {
        std::string pString = keyString.substr(0, pos);
        std::string qString = keyString.substr(pos + 1);

        n = std::stoull(pString);
        e = std::stoull(qString);

        return (n > 1 && e > 1);

    } catch (const std::exception&) {
        return false;
    }
}

uint64_t sqrtModPrime(uint64_t a, uint64_t p) {
    if (a % p == 0) return 0;        
    return binMod(a, (p + 1) / 4, p); 
}

uint64_t generatePrimeRubin(int bits) {
    while (true) {
        uint64_t candidate = generatePrime(bits);
        if (candidate % 4 == 3) { 
            return candidate;
        }
    }
}

KeyPair keyGeneration() {
    KeyPair keys;

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

bool checkRabinPadding(uint64_t value, uint64_t& originalChar) {
    if (value > 0xFFFF) {
        return false;
    }

    uint64_t highByte = (value >> 8) & 0xFF;
    uint64_t lowByte = value & 0xFF;

    if (highByte != lowByte) {
        return false;
    }

    originalChar = lowByte;
    return true;
}


vector<uint64_t> encryptRabin(const std::string& text, KeyPair keys) {
    vector<uint64_t> cipherText;

    uint64_t n = stoull(keys.openKey);

    for (size_t i = 0; i < text.size(); i++) {
        uint64_t m = static_cast<unsigned char>(text[i]);


        uint64_t m_padded = (m << 8) | m;


        uint64_t c = binMod(m_padded, 2, n);

        cipherText.push_back(c);
    }

    return cipherText;
}


string decryption(const vector<uint64_t>& cipherText, KeyPair keys) {
    string plaintext;

    uint64_t p, q;
    uint64_t n = stoull(keys.openKey);   
    parseRabinKey(keys.privateKey, p, q); 

    uint64_t yp = modNegative(p, q);
    uint64_t yq = modNegative(q, p);

    for (size_t i = 0; i < cipherText.size(); i++) {
        uint64_t c = cipherText[i];

        uint64_t mp = sqrtModPrime(c, p);
        uint64_t mq = sqrtModPrime(c, q);

        uint64_t term1 = ((yp * p) % n * mq) % n;
        uint64_t term2 = ((yq * q) % n * mp) % n;

        uint64_t r1 = (term1 + term2) % n;

        uint64_t r2 = (r1 == 0) ? 0 : n - r1;

        uint64_t r3;
        if (term1 >= term2) {
            r3 = term1 - term2;        
        } else {
            r3 = n - (term2 - term1);  
        }

        // r4 = n - r3
        uint64_t r4 = (r3 == 0) ? 0 : n - r3;

        uint64_t decrypted = 0;
        bool found = false;

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

        if (!found) {
            throw runtime_error("Rabin decryption failed: no root passes padding check");
        }

        plaintext.push_back(static_cast<char>(decrypted));
    }

    return plaintext;
}

extern "C" {

EXPORT const char* getAlgorithmName() {
    return "Rabin (асимметричный шифр с padding)";
}

EXPORT const char* getKeyInfo() {
    return "Шифрование: \"n\" (n = p*q, p≡q≡3 mod 4).\n"
           "Дешифрование: \"p|q\" (через символ '|').\n"
           "Padding: m_padded = (m << 8) | m для однозначного выбора корня.\n"
           "Каждый исходный байт шифруется в 8 байт (uint64_t).\n"
           "Используются 16-битные простые числа Блюма.";
}

EXPORT size_t getMinKeySize() { return 1; }
EXPORT size_t getMaxKeySize() { return 64; }

EXPORT int encrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    if (*outputSize < dataSize * 8) return -3;

    try {
        KeyPair keys;
        keys.openKey = std::string(reinterpret_cast<const char*>(key), keySize);

        try {
            uint64_t n = std::stoull(keys.openKey);
            if (n <= 0xFFFF) return -4;
        } catch (...) {
            return -2;
        }

        std::string text(reinterpret_cast<const char*>(data), dataSize);

        std::vector<uint64_t> cipher = encryptRabin(text, keys);

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

EXPORT int decrypt(const uint8_t* data, size_t dataSize,
                   const uint8_t* key, size_t keySize,
                   uint8_t* output, size_t* outputSize) {
    if (!data || !key || !output || !outputSize) return -1;

    if (dataSize % 8 != 0) return -5;

    try {
        KeyPair keys;
        keys.privateKey = std::string(reinterpret_cast<const char*>(key), keySize);

        uint64_t p = 0, q = 0;
        if (!parseRabinKey(keys.privateKey, p, q)) return -2;

        uint64_t n = p * q;
        keys.openKey = std::to_string(n);

        size_t outCount = dataSize / 8;
        if (*outputSize < outCount) return -3;

        std::vector<uint64_t> cipher(outCount);
        for (size_t i = 0; i < outCount; ++i) {
            uint64_t c = 0;
            for (int b = 0; b < 8; ++b) {
                c = (c << 8) | data[i * 8 + b];
            }
            cipher[i] = c;
        }

        std::string plaintext = decryption(cipher, keys);

        std::memcpy(output, plaintext.data(), plaintext.size());
        *outputSize = plaintext.size();
        return 0;

    } catch (const std::exception&) {
        return -2;
    }
}

EXPORT int generateKey(uint8_t* keyBuffer, size_t* keyBufferSize, int param) {
    if (!keyBuffer || !keyBufferSize) return -1;
    (void)param; 

    srand(static_cast<unsigned>(time(nullptr)));

    try {
        KeyPair keys = keyGeneration();

        std::string output = "PUB:" + keys.openKey + " PRIV:" + keys.privateKey;

        if (output.size() >= *keyBufferSize) return -3;

        std::memcpy(keyBuffer, output.data(), output.size());
        *keyBufferSize = output.size();
        return 0;

    } catch (const std::exception&) {
        return -10;
    }
}

}