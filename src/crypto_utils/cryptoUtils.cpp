#include "cryptoUtils.h"

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
        r0 = r;  //сохраняем предыдущий остаток, чтобы получить gcd
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