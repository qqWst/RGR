#include "../src/types.h"
#include "../src/pluginLoader.h"
#include "../src/algorithmTable.h"
#include "../include/cryptoMath.h"
#include "../include/primeGenerator.h"

#include <iostream>
#include <string>

static ByteArray makeRandomData(size_t size) {
    ByteArray data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = cryptoMath::randomByte();
    }
    return data;
}

static bool compareData(const ByteArray& a, const ByteArray& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

static bool runRoundtripTest(Algorithm algorithm, const std::string& name, size_t size) {
    std::cout << "[TEST] " << name << " size=" << size << " ... ";
    try {
        Plugin plugin = loadPlugin(algorithm);
        ByteArray key = callGenerateKey(plugin);
        ByteArray plaintext = makeRandomData(size);
        ByteArray ciphertext = callEncrypt(plugin, key, plaintext);
        ByteArray decrypted = callDecrypt(plugin, key, ciphertext);
        unloadPlugin(plugin);

        if (compareData(plaintext, decrypted)) {
            std::cout << "OK\n";
            return true;
        } else {
            std::cout << "FAIL (mismatch)\n";
            return false;
        }
    }
    catch (const std::exception& ex) {
        std::cout << "FAIL (" << ex.what() << ")\n";
        return false;
    }
}

static bool runPrimeGeneratorTest(uint32_t bits) {
    std::cout << "[TEST] pocklington bits=" << bits << " ... ";
    int successes = 0;
    int attempts = 10;

    for (int i = 0; i < attempts; ++i) {
        uint64_t p = primeGenerator::generatePocklingtonPrime(bits);
        if (p != 0 && cryptoMath::isPrime(p)) {
            uint32_t actualBits = primeGenerator::bitLength(p);
            if (actualBits == bits) {
                ++successes;
            }
        }
    }

    if (successes >= attempts / 2) {
        std::cout << "OK (" << successes << "/" << attempts << ")\n";
        return true;
    } else {
        std::cout << "FAIL (" << successes << "/" << attempts << ")\n";
        return false;
    }
}

int main() {
    std::cout << "=== cryptum test suite ===\n\n";

    int total = 0;
    int passed = 0;

    std::cout << "--- Prime generator tests ---\n";
    for (uint32_t bits : {8u, 10u, 14u, 16u}) {
        ++total;
        if (runPrimeGeneratorTest(bits)) ++passed;
    }

    std::cout << "\n--- Algorithm roundtrip tests ---\n";
    const std::vector<size_t> testSizes = {16, 64, 256};
    for (const auto& entry : getAlgorithmTable()) {
        for (size_t size : testSizes) {
            ++total;
            if (runRoundtripTest(entry.algorithm, entry.name, size)) {
                ++passed;
            }
        }
    }

    std::cout << "\nResult: " << passed << "/" << total << " tests passed.\n";
    return (passed == total) ? 0 : 1;
}