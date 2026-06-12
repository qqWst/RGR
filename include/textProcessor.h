#ifndef TEXT_PROCESSOR_H
#define TEXT_PROCESSOR_H

#include "libraryLoader.h"
#include <string>
#include <vector>

std::vector<uint8_t> encryptText(const CryptoPlugin& plugin,
                                  const std::string& plainText,
                                  const std::vector<uint8_t>& key);

std::string decryptText(const CryptoPlugin& plugin,
                        const std::vector<uint8_t>& cipherData,
                        const std::vector<uint8_t>& key);

std::vector<uint8_t> decryptToBytes(const CryptoPlugin& plugin,
                                     const std::vector<uint8_t>& cipherData,
                                     const std::vector<uint8_t>& key);

                                     
#endif