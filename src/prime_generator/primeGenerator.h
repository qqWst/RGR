#ifndef PRIME_GENERATOR_H
#define PRIME_GENERATOR_H

#include <cstdint>
#include <vector>
#include <cmath>
#include <random>
#include <chrono>

/**
 * @brief Генерирует простое число заданной битовой длины
 * @param bits Битовая длина (4-32)
 * @return Простое число или 0 при ошибке
 */
uint64_t generate_prime(int bits);

#endif
