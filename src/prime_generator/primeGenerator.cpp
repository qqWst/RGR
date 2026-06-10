#include "primeGenerator.h"
#include "../crypto_utils/cryptoUtils.h"

using namespace std;

// Глобальный генератор (инициализируется один раз)
mt19937& getRandom() {
    mt19937 rng(chrono::steady_clock::now().time_since_epoch().count());
    return rng;
}

// Решето Эратосфена
vector<int> sieve_primes(int limit) {
    vector<bool> is_prime(limit + 1, true);
    is_prime[0] = is_prime[1] = false;
    for (int i = 2; i * i <= limit; ++i)
        if (is_prime[i])
            for (int j = i * i; j <= limit; j += i)
                is_prime[j] = false;
    vector<int> primes;
    for (int i = 2; i <= limit; ++i)
        if (is_prime[i]) primes.push_back(i);
    return primes;
}

// Битовая длина
unsigned int bit_len(unsigned int n) {
    int len = 0;
    while (n) {
        ++len;
        n >>= 1;
    }
    return len;
}

uint64_t generate_F(int target_bits, const vector<int>& primes, vector<int>& usedPrimes) {
    auto& rng = getRandom();
    uniform_int_distribution<size_t> prime_idx_dist(0, primes.size() - 1);
    uniform_int_distribution<int> exp_dist(1, 5);
    
    uint64_t F = 1;
    int current_bits = 1;
    
    while (current_bits < target_bits) {
        int q = primes[prime_idx_dist(rng)];
        int alpha = exp_dist(rng);
        uint64_t q_pow = pow(q, alpha);
        uint64_t candidate = F * q_pow;
        int candidate_bits = bit_len(candidate);
        
        if (candidate_bits <= target_bits) {
            F = candidate;
            current_bits = candidate_bits;
            usedPrimes.push_back(q);
        } else {
            bool found = false;
            for (int a = alpha - 1; a >= 1; --a) {
                q_pow = pow(q, a);
                candidate = F * q_pow;
                candidate_bits = bit_len(candidate);
                if (candidate_bits <= target_bits) {
                    F = candidate;
                    current_bits = candidate_bits;
                    usedPrimes.push_back(q);
                    found = true;
                    break;
                }
            }
            if (!found) continue;
        }
    }
    return F;
}

uint64_t generate_R(int target_bits) {
    auto& rng = getRandom();
    uniform_int_distribution<uint64_t> dist(1, (1ULL << target_bits) - 1);
    uint64_t R = dist(rng);
    while (bit_len(R) != (unsigned int)target_bits) {
        R = dist(rng);
    }
    if (R % 2 == 1) R += 1;
    return R;
}

bool is_prime(uint64_t N, vector<int>& usedPrimes) {
    auto& rng = getRandom();
    int t = 3;
    uniform_int_distribution<int> rangeA(2, N - 1);
    uniform_int_distribution<size_t> rangePrimes(0, usedPrimes.size() - 1);
    
    // Удаляем дубликаты
    for (size_t i = 0; i < usedPrimes.size(); ++i) {
        for (size_t j = i + 1; j < usedPrimes.size(); ++j) {
            if (usedPrimes[i] == usedPrimes[j]) {
                usedPrimes.erase(usedPrimes.begin() + j);
                --j;
            }
        }
    }
    
    while (t-- > 0) {
        int a = rangeA(rng);
        int q = usedPrimes[rangePrimes(rng)];
        
        if (mod(a, N - 1, N) != 1) return false;
        
        int power = (N - 1) / q;
        int remain = mod(a, power, N);
        if (gcd(remain - 1, (int)N) != 1) return false;
    }
    return true;
}

// Публичная функция
uint64_t generate_prime(int bits) {
    if (bits < 4 || bits > 32) return 0;
    
    const vector<int> primes = sieve_primes(500);
    vector<int> usedPrimes;
    
    for (int attempt = 0; attempt < 100; ++attempt) {
        usedPrimes.clear();
        uint64_t F = generate_F(bits / 2 + 1, primes, usedPrimes);
        uint64_t R = generate_R(bits / 2);
        uint64_t N = R * F + 1;
        
        if (bit_len(N) != (unsigned int)bits) continue;
        
        if (is_prime(N, usedPrimes)) {
            return N;
        }
    }
    return 0;
}
