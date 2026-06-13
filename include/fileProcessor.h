#ifndef FILE_PROCESSOR_H
#define FILE_PROCESSOR_H

#include "libraryLoader.h"
#include <string>
#include <vector>


constexpr size_t BLOCK_SIZE = 4096;

constexpr size_t WARN_FILE_SIZE = 1024 * 1024;

bool encryptFile(const CryptoPlugin& plugin,
                 const std::string& inputPath,
                 const std::string& outputPath,
                 const std::vector<uint8_t>& key);

bool decryptFile(const CryptoPlugin& plugin,
                 const std::string& inputPath,
                 const std::string& outputPath,
                 const std::vector<uint8_t>& key);

#endif