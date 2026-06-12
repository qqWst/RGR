#include "libraryLoader.h"
#include "../include/menu.h"
#include "utils.h"
#include <iostream>
#include <clocale>

int main() {
    setlocale(LC_ALL, "");

    // Пароль для доступа к приложению
    const std::string appPassword = "qqww2233";

    // Шаг 2 алгоритма: вход пользователя
    if (!login(appPassword)) {
        // Шаг 2.2: неудача — сообщение об ошибке и завершение работы
        std::cerr << "Программа завершает работу." << std::endl;
        return 1;
    }

    // Шаг 3: главное меню
    std::cout << "Загрузка плагинов..." << std::endl;
    std::vector<CryptoPlugin> plugins = loadAllPlugins("plugins");
    std::cout << "Загружено: " << plugins.size() << std::endl;

    runMainMenu(plugins);

    unloadAllPlugins(plugins);
    return 0;
}