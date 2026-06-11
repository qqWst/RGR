#ifndef PLUGIN_INTERFACE_H
#define PLUGIN_INTERFACE_H
#include <string>
#include <vector>
#include <sstream>
#include <exception>

#include "../core/cryptoCore.h"

KeyPair keyGeneration();
std::vector<uint64_t> encrypt(const std::string& text, KeyPair keys);
std::string decrypt(const std::vector<uint64_t>& text, KeyPair keys);

#endif