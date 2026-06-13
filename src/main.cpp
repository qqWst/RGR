#include "../include/libraryLoader.h"
#include "../include/menu.h"
#include "../include/utils.h"
#include <iostream>
#include <clocale>
#include <exception>

int main() {
    setlocale(LC_ALL, "");

    try {
        const std::string appPassword = "qqww2233";

        if (!login(appPassword)) {
            std::cerr << "Программа завершает работу." << std::endl;
            return 1;
        }

        std::cout << "Загрузка плагинов..." << std::endl;
        std::vector<CryptoPlugin> plugins = loadAllPlugins("plugins");
        std::cout << "Загружено: " << plugins.size() << std::endl;

        runMainMenu(plugins);

        unloadAllPlugins(plugins);

    } catch (const std::bad_alloc& e) {
        std::cerr << "\nКритическая ошибка: недостаточно памяти." << std::endl;
        std::cerr << "Подробности: " << e.what() << std::endl;
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "\nКритическая ошибка: " << e.what() << std::endl;
        std::cerr << "Программа аварийно завершена." << std::endl;
        return 3;
    } catch (...) {
        std::cerr << "\nНеизвестная критическая ошибка." << std::endl;
        std::cerr << "Программа аварийно завершена." << std::endl;
        return 4;
    }

    return 0;
}
