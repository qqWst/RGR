#include "libraryLoader.h"
#include "../include/menu.h"
#include "utils.h"
#include <iostream>
#include <clocale>
#include <exception>

int main() {
    setlocale(LC_ALL, "");

    // Глобальный обработчик исключений — обеспечивает отказоустойчивость (п. 4.2 ТЗ)
    try {
        // Пароль для доступа к приложению (п. 2.3 алгоритма)
        const std::string appPassword = "qqww2233";

        // Шаг 2: вход пользователя
        if (!login(appPassword)) {
            std::cerr << "Программа завершает работу." << std::endl;
            return 1;
        }

        // Шаг 3: загрузка плагинов
        std::cout << "Загрузка плагинов..." << std::endl;
        std::vector<CryptoPlugin> plugins = loadAllPlugins("plugins");
        std::cout << "Загружено: " << plugins.size() << std::endl;

        // Шаг 4: главное меню
        runMainMenu(plugins);

        // Корректная выгрузка
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