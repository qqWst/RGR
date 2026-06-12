#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <cstdint>

bool fileExists(const std::string& path);
bool ensureDirectoryExists(const std::string& filePath);
bool validatePath(const std::string& path);

std::vector<uint8_t> stringToBytes(const std::string& str);
std::string bytesToString(const std::vector<uint8_t>& data);
std::string bytesToHex(const std::vector<uint8_t>& data);
std::vector<uint8_t> hexToBytes(const std::string& hex);

int readInt(const std::string& prompt);
std::string readLine(const std::string& prompt);

bool login(const std::string& expectedPassword);

#endif