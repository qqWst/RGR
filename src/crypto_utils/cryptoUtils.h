#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <iostream>
#include <cstdint>

uint64_t gcd(uint64_t a, uint64_t b);
uint64_t mod(uint64_t base, uint64_t power, uint64_t modulo);
uint64_t modNegative(uint64_t base, uint64_t modulo);

#endif