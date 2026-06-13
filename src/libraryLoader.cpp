#include "libraryLoader.h"
#include <iostream>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

void* openLibrary(const std::string& path) {
#ifdef _WIN32
    return LoadLibraryA(path.c_str());
#else
    return dlopen(path.c_str(), RTLD_LAZY);
#endif
}

void* getSymbol(void* handle, const std::string& name) {
#ifdef _WIN32
    return reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(handle), name.c_str()));
#else
    return dlsym(handle, name.c_str());
#endif
}

void closeLibrary(void* handle) {
#ifdef _WIN32
    FreeLibrary(static_cast<HMODULE>(handle));
#else
    dlclose(handle);
#endif
}

std::string getLastErrorString() {
#ifdef _WIN32
    return "Windows error " + std::to_string(GetLastError());
#else
    const char* err = dlerror();
    return err ? std::string(err) : "Неизвестная ошибка";
#endif
}

}
bool loadPlugin(const std::string& path, CryptoPlugin& plugin) {

    plugin.handle = openLibrary(path);
    if (!plugin.handle) {
        std::cerr << "Не удалось загрузить библиотеку: " << path << std::endl;
        std::cerr << "Причина: " << getLastErrorString() << std::endl;
        return false;
    }

    plugin.filePath = path;
    
    plugin.getAlgorithmName = reinterpret_cast<GetAlgorithmNameFunc>(
        getSymbol(plugin.handle, "getAlgorithmName"));
    
    plugin.getKeyInfo = reinterpret_cast<GetKeyInfoFunc>(
        getSymbol(plugin.handle, "getKeyInfo"));
    
    plugin.getMinKeySize = reinterpret_cast<GetMinKeySizeFunc>(
        getSymbol(plugin.handle, "getMinKeySize"));
    
    plugin.getMaxKeySize = reinterpret_cast<GetMaxKeySizeFunc>(
        getSymbol(plugin.handle, "getMaxKeySize"));
    
    plugin.encrypt = reinterpret_cast<EncryptFunc>(
        getSymbol(plugin.handle, "encrypt"));
    
    plugin.decrypt = reinterpret_cast<DecryptFunc>(
        getSymbol(plugin.handle, "decrypt"));
    
    plugin.generateKey = reinterpret_cast<GenerateKeyFunc>(
        getSymbol(plugin.handle, "generateKey"));
    
    if (!plugin.getAlgorithmName || !plugin.encrypt || !plugin.decrypt ||
        !plugin.generateKey || !plugin.getMinKeySize || !plugin.getMaxKeySize ||
        !plugin.getKeyInfo) {
        
        std::cerr << "Библиотека " << path << " не реализует все необходимые функции." << std::endl;
        std::cerr << "Отсутствуют функции: ";
        if (!plugin.getAlgorithmName) std::cerr << "getAlgorithmName ";
        if (!plugin.getKeyInfo) std::cerr << "getKeyInfo ";
        if (!plugin.getMinKeySize) std::cerr << "getMinKeySize ";
        if (!plugin.getMaxKeySize) std::cerr << "getMaxKeySize ";
        if (!plugin.encrypt) std::cerr << "encrypt ";
        if (!plugin.decrypt) std::cerr << "decrypt ";
        if (!plugin.generateKey) std::cerr << "generateKey ";
        std::cerr << std::endl;
        
        closeLibrary(plugin.handle);
        plugin.handle = nullptr;
        return false;
    }
    
    plugin.algorithmName = plugin.getAlgorithmName();
    
    std::cout << "Загружен плагин: " << plugin.algorithmName << " (" << path << ")" << std::endl;
    return true;
}

void unloadPlugin(CryptoPlugin& plugin) {
    if (plugin.handle) {
        closeLibrary(plugin.handle);
        plugin.handle = nullptr;
    }
}

std::vector<CryptoPlugin> loadAllPlugins(const std::string& directory) {
    std::vector<CryptoPlugin> plugins;
    try {
        if (!std::filesystem::exists(directory)) {
            std::cerr << "Директория плагинов не найдена: " << directory << std::endl;
            return plugins;  
        }
        
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            std::string ext = entry.path().extension().string();
            
#ifdef _WIN32
            if (ext == ".dll") {
#else
            if (ext == ".so" || ext == ".dylib") {
#endif
                CryptoPlugin plugin;
                if (loadPlugin(entry.path().string(), plugin)) {
                    plugins.push_back(plugin);
                }
            }
        }
        
        std::cout << "\nВсего загружено плагинов: " << plugins.size() << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Ошибка при сканировании директории " << directory << ": " << e.what() << std::endl;
    }
    
    return plugins;
}

void unloadAllPlugins(std::vector<CryptoPlugin>& plugins) {
    for (auto& p : plugins) unloadPlugin(p);
    plugins.clear();
}