#include "libraryLoader.h"
#include "menu.h"
#include <iostream>
#include <clocale>

int main() {
    setlocale(LC_ALL, "");

    std::cout << "Загрузка плагинов..." << std::endl;
    std::vector<CryptoPlugin> plugins = loadAllPlugins("plugins");
    std::cout << "Загружено: " << plugins.size() << std::endl;

    runMainMenu(plugins);

    unloadAllPlugins(plugins);
    return 0;
}