#ifndef KEY_GENERATOR_H
#define KEY_GENERATOR_H

#include "libraryLoader.h"
#include <vector>


std::vector<uint8_t> generateKeyForPlugin(const CryptoPlugin& plugin, int param);

#endif