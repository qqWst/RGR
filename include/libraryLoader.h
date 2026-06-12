#ifndef LIBRARY_LOADER_H
#define LIBRARY_LOADER_H

#include "cryptoApi.h"
#include <string>
#include <vector>

//Структура каждого крипто-плагина
struct CryptoPlugin {
    std::string filePath;       //путь
    std::string algorithmName;  //имя алгоритма
    void* handle = nullptr;

    GetAlgorithmNameFunc getAlgorithmName = nullptr;
    GetKeyInfoFunc       getKeyInfo       = nullptr;
    GetMinKeySizeFunc    getMinKeySize    = nullptr;
    GetMaxKeySizeFunc    getMaxKeySize    = nullptr;
    EncryptFunc          encrypt          = nullptr;
    DecryptFunc          decrypt          = nullptr;
    GenerateKeyFunc      generateKey      = nullptr;
};

bool loadPlugin(const std::string& path, CryptoPlugin& plugin);
void unloadPlugin(CryptoPlugin& plugin);
std::vector<CryptoPlugin> loadAllPlugins(const std::string& directory);
void unloadAllPlugins(std::vector<CryptoPlugin>& plugins);

#endif