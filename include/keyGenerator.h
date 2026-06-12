#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include "libraryLoader.h"
#include <vector>

//модуль генерации ключа

std::vector<uint8_t> generateKeyForPlugin(const CryptoPlugin& plugin, int param);

#endif