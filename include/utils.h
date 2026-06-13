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

enum class CryptoError : int {
    Ok              =   0, 
    NullPointer     =  -1,  
    InvalidKey      =  -2,  
    BufferTooSmall  =  -3,  
    KeyTooSmall     =  -4,  
    InvalidDataSize =  -5, 
    KeygenFailed    = -10,   
    NoInverse       = -11    
};

std::string errorToMessage(int code);

#endif