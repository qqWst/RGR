#include "libraryLoader.h"
#include <iostream>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

//реализует динамическую загрузку криптографических плагинов

//Анонимное пространство имён (утилиты)
namespace {

//Загружает DLL/.so файл в память
void* openLibrary(const std::string& path) {
#ifdef _WIN32
    return LoadLibraryA(path.c_str());
#else
    return dlopen(path.c_str(), RTLD_LAZY);
#endif
}

//Получает адрес функции по имени
void* getSymbol(void* handle, const std::string& name) {
#ifdef _WIN32
    return reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(handle), name.c_str()));
#else
    return dlsym(handle, name.c_str());
#endif
}

//Выгружает библиотеку
void closeLibrary(void* handle) {
#ifdef _WIN32
    FreeLibrary(static_cast<HMODULE>(handle));
#else
    dlclose(handle);
#endif
}

//Возвращает текст последней ошибки
std::string getLastErrorString() {
#ifdef _WIN32
    return "Windows error " + std::to_string(GetLastError());
#else
    const char* err = dlerror();
    return err ? std::string(err) : "Неизвестная ошибка";
#endif
}

} // namespace

//Загружает один плагин
// Алгоритм работы:
//   1. Загружаем библиотеку
//   2. Получаем указатели на все необходимые функции
//   3. Проверяем, что все функции найдены
//   4. Получаем название алгоритма
//   5. Возвращаем успех/неудачу
bool loadPlugin(const std::string& path, CryptoPlugin& plugin) {

    // Шаг 1: Загружаем библиотеку
    plugin.handle = openLibrary(path);
    if (!plugin.handle) {
        // Не удалось загрузить - выводим причину
        std::cerr << "Не удалось загрузить библиотеку: " << path << std::endl;
        std::cerr << "Причина: " << getLastErrorString() << std::endl;
        return false;
    }

    // Сохраняем путь к файлу (для отладки)
    plugin.filePath = path;
    
    // Шаг 2: Получаем указатели на функции плагина
    // Каждый указатель приводится к соответствующему типу через reinterpret_cast
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
    
    // Шаг 3: Проверяем, что все необходимые функции присутствуют
    // Если хоть одна функция отсутствует - плагин не соответствует спецификации
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
        
        // Выгружаем некорректный плагин
        closeLibrary(plugin.handle);
        plugin.handle = nullptr;
        return false;
    }
    
    // Шаг 4: Получаем название алгоритма из плагина
    // Это позволяет программе динамически узнавать, какой шифр предоставляет плагин
    plugin.algorithmName = plugin.getAlgorithmName();
    
    // Сообщаем о загрузке
    std::cout << "Загружен плагин: " << plugin.algorithmName << " (" << path << ")" << std::endl;
    return true;
}

// Выгружает плагин
// Просто закрывает библиотеку и обнуляет указатель
void unloadPlugin(CryptoPlugin& plugin) {
    if (plugin.handle) {
        closeLibrary(plugin.handle);
        plugin.handle = nullptr;
    }
}

// Загружает все плагины из указанной директории
// Алгоритм работы:
//   1. Проверяем существование директории
//   2. Перебираем все файлы в директории
//   3. Фильтруем по расширению (.dll для Windows, .so/.dylib для Linux)
//   4. Пытаемся загрузить каждый подходящий файл
//   5. Возвращаем вектор успешно загруженных плагинов
std::vector<CryptoPlugin> loadAllPlugins(const std::string& directory) {
    std::vector<CryptoPlugin> plugins;
    try {
        // Проверяем, существует ли директория
        if (!std::filesystem::exists(directory)) {
            std::cerr << "Директория плагинов не найдена: " << directory << std::endl;
            return plugins;  // Возвращаем пустой вектор
        }
        
        // Перебираем все записи в директории
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            // Получаем расширение файла (например, ".dll", ".so")
            std::string ext = entry.path().extension().string();
            
            // Фильтруем по расширению в зависимости от ОС
#ifdef _WIN32
            if (ext == ".dll") {
#else
            if (ext == ".so" || ext == ".dylib") {
#endif
                // Найден потенциальный плагин - пробуем загрузить
                CryptoPlugin plugin;
                if (loadPlugin(entry.path().string(), plugin)) {
                    // Загрузка успешна - добавляем в вектор
                    plugins.push_back(plugin);
                }
                // Если загрузка не удалась, просто пропускаем этот файл
            }
        }
        
        // Выводим итоговую статистику
        std::cout << "\nВсего загружено плагинов: " << plugins.size() << std::endl;
        
    } catch (const std::exception& e) {
        // Обрабатываем возможные исключения (например, нет прав доступа)
        std::cerr << "Ошибка при сканировании директории " << directory << ": " << e.what() << std::endl;
    }
    
    return plugins;
}

// Выгружает все плагины из вектора
// Проходит по всем элементам, выгружает каждый, затем очищает вектор
void unloadAllPlugins(std::vector<CryptoPlugin>& plugins) {
    for (auto& p : plugins) unloadPlugin(p);
    plugins.clear();
}