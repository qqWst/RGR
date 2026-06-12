#include "utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(dir) _mkdir(dir)
#else
#define MKDIR(dir) mkdir(dir, 0755)
#endif

bool fileExists(const std::string& path) {
    std::ifstream file(path); //входной файловый поток
    return file.good();
}

bool ensureDirectoryExists(const std::string& filePath) {
    // Функция принимает путь к файлу, проверяет существование директории
    // и при необходимости создаёт её с подтверждением пользователя
    
    // Ищем последний слеш (Unix / или Windows \)
    size_t lastSlash = filePath.find_last_of("/\\");
    
    // Если слешей нет - значит передан только имя файла без пути
    // Директория не требуется, возвращаем true (успех)
    if (lastSlash == std::string::npos) 
        return true;
    
    // Извлекаем путь к директории (всё, что до последнего слеша)
    std::string dirPath = filePath.substr(0, lastSlash);
    
    // Если путь к директории пустой (например, "/file.txt")
    if (dirPath.empty()) 
        return true;
    
    // Структура для хранения информации о файле/директории
    struct stat info;
    
    // stat() проверяет существование директории
    // Возвращает 0, если директория существует
    if (stat(dirPath.c_str(), &info) == 0) 
        return true;  // Директория уже есть, всё хорошо
    
    // Если дошли сюда - директория не существует
    // Сообщаем пользователю
    std::cout << "Директория \"" << dirPath << "\" не существует." << std::endl;
    
    // Запрашиваем подтверждение на создание
    std::cout << "Создать? (1 - да, 0 - нет): ";
    
    // Переменная для хранения выбора пользователя
    int choice = 0;
    
    // Считываем выбор из стандартного ввода
    std::cin >> choice;
    
    // Очищаем буфер ввода после std::cin >>
    // Убираем символ новой строки и лишние символы
    std::cin.ignore();
    
    // Если пользователь согласился (ввёл 1)
    if (choice == 1) {
        // MKDIR - макрос, который на Windows вызывает _mkdir(),
        // на Linux/macOS вызывает mkdir()
        // Создаёт директорию с указанным путём
        // Возвращает 0 при успешном создании
        if (MKDIR(dirPath.c_str()) == 0) {
            // Создание успешно, сообщаем об этом
            std::cout << "Директория создана." << std::endl;
            return true;  // Возвращаем успех
        } 
        else {
            // Создание не удалось (нет прав, путь неверный и т.д.)
            // Выводим ошибку в поток cerr (для ошибок)
            std::cerr << "Не удалось создать директорию." << std::endl;
            return false;  // Возвращаем неудачу
        }
    }
    
    // Пользователь отказался создавать директорию (ввёл 0)
    return false;  // Возвращаем неудачу
}

bool validatePath(const std::string& path) {
    // Функция проверяет корректность пути к файлу/директории
    // Возвращает true, если путь валидный, и false - если нет
    
    // Проверяем, не пустая ли строка пути
    if (path.empty()) {
        // Путь пуст - выводим сообщение об ошибке в поток cerr
        std::cerr << "Путь не может быть пустым." << std::endl;
        return false;  // Валидация не пройдена
    }
    
    // Строка с запрещёнными символами в путях (для Windows)
    // < > | " - эти символы нельзя использовать в именах файлов/папок
    const std::string forbidden = "<>|\"";
    
    // Внешний цикл - перебираем каждый символ в переданном пути
    for (char ch : path) {
        
        // Внутренний цикл - сравниваем текущий символ с каждым запрещённым
        for (char f : forbidden) {
            
            // Если символ из пути совпал с запрещённым символом
            if (ch == f) {
                
                // Сообщаем, какой именно недопустимый символ найден
                std::cerr << "Путь содержит недопустимый символ '" << ch << "'." << std::endl;
                
                // Сообщаем список всех запрещённых символов
                std::cerr << "В пути нельзя использовать: < > | \"" << std::endl;
                
                return false;  // Валидация не пройдена
            }
        }
    }
    
    // Если все проверки пройдены успешно
    return true;  // Путь валидный
}

std::vector<uint8_t> stringToBytes(const std::string& str) {
    // Функция преобразует строку в вектор байт (uint8_t)
    // str.begin() - итератор на первый символ строки
    // str.end()   - итератор на позицию после последнего символа
    // std::vector<uint8_t>(first, last) копирует элементы из диапазона [first, last)
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string bytesToString(const std::vector<uint8_t>& data) {
    //обратное аналогичное
    return std::string(data.begin(), data.end());
}

std::string bytesToHex(const std::vector<uint8_t>& data) {
    // Функция преобразует вектор байт в шестнадцатеричную строку
    // Каждый байт представляется двумя шестнадцатеричными цифрами

    // Создаём поток для построения строки
    std::ostringstream oss;
    for (uint8_t byte : data) {
        // std::hex - переключаем поток в шестнадцатеричный режим
        // std::setw(2) - устанавливаем ширину поля в 2 символа
        // std::setfill('0') - заполняем недостающие символы нулями
        // static_cast<int>(byte) - преобразуем uint8_t в int для корректного вывода
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    // Извлекаем строку из потока и возвращаем её
    return oss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    // Функция преобразует шестнадцатеричную строку в вектор байт

    std::vector<uint8_t> bytes;

    // Проверка 1: длина строки должна быть чётной
    // Каждый байт кодируется двумя hex-цифрами (например, "4A" = 74)
    if (hex.length() % 2 != 0) {
        // Если длина нечётная - строка не может быть корректным hex-представлением
        std::cerr << "Шифротекст имеет некорректный формат: длина должна быть чётной." << std::endl;
        return bytes;
    }
    for (size_t i = 0; i < hex.length(); i += 2) {
        // Извлекаем два символа, начиная с позиции i
        // std::stoi(строка, nullptr, 16) - преобразует hex-строку в целое число

        std::string byteStr = hex.substr(i, 2);
        try {
            // Параметры:
            //   byteStr   - строка для преобразования
            //   nullptr   - указатель для сохранения позиции (не нужен)
            //   16        - основание системы счисления (шестнадцатеричная)
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
            bytes.push_back(byte);
        } catch (const std::exception&) {
            // Если stoi выбросил исключение (неверные символы, выход за диапазон)
            // Выводим сообщение об ошибке
            std::cerr << "Шифротекст содержит недопустимые символы (только 0-9, a-f)." << std::endl;
            return {};
        }
    }
    return bytes;
}

int readInt(const std::string& prompt) {
    // Функция для безопасного чтения целого числа из стандартного ввода
    // Выводит приглашение (prompt) и повторяет запрос, пока не будет введено корректное целое число
    // Возвращает введённое целое число типа int

    // Выводим приглашение пользователю (например, "Введите число: ")
    std::cout << prompt;

    // Переменная для хранения введённого значения
    int value = 0;

    // Цикл продолжается, пока ввод не будет успешным
    while (!(std::cin >> value)) {

        // 1. Сбрасываем флаги ошибок потока (eofbit, failbit, badbit)
        std::cin.clear();

        // 2. Очищаем буфер ввода:
        //    ignore(10000, '\n') - игнорирует до 10000 символов или до символа '\n'
        std::cin.ignore(10000, '\n');
        std::cout << "Введите целое число: ";
    }
    std::cin.ignore(10000, '\n');
    return value;
}

std::string readLine(const std::string& prompt) {
    // Функция для чтения целой строки текста из стандартного ввода
    // Выводит приглашение (prompt) и считывает всю строку до символа '\n'
    // Возвращает введённую строку (может быть пустой)
    
    std::cout << prompt;
    std::string line;

    // std::getline() читает символы из потока std::cin до символа новой строки '\n'
    // Символ '\n' извлекается из потока, но не сохраняется в строку
    // Читает пробелы и другие символы (в отличие от std::cin >>)
    std::getline(std::cin, line);
    return line;
}

bool login(const std::string& expectedPassword) {
    std::cout << "========================================" << std::endl;
    std::cout << "       Авторизация пользователя" << std::endl;
    std::cout << "========================================" << std::endl;

    std::string entered = readLine("Введите пароль: ");

    switch (entered == expectedPassword ? 1 : 0) {
        case 1:
            std::cout << "Доступ разрешён." << std::endl;
            std::cout << "========================================" << std::endl;
            return true;
        case 0: //идет в default
        default:
            std::cerr << "Неверный пароль! Доступ запрещён." << std::endl;
            return false;
    }
}

std::string errorToMessage(int code) {
    switch (static_cast<CryptoError>(code)) {
        case CryptoError::Ok:
            return "Операция выполнена успешно.";
        case CryptoError::NullPointer:
            return "Внутренняя ошибка программы. Сообщите разработчику.";
        case CryptoError::InvalidKey:
            return "Неверный формат ключа. Проверьте формат через "
                   "пункт меню \"Информация о формате ключей\".";
        case CryptoError::BufferTooSmall:
            return "Недостаточно памяти для результата.";
        case CryptoError::KeyTooSmall:
            return "Ключ слишком короткий для безопасного шифрования. "
                   "Сгенерируйте новый ключ с большей битностью.";
        case CryptoError::InvalidDataSize:
            return "Повреждены входные данные. "
                   "Проверьте, что вы скопировали данные полностью.";
        case CryptoError::KeygenFailed:
            return "Не удалось сгенерировать ключ. "
                   "Попробуйте указать другое значение параметра битности.";
        case CryptoError::NoInverse:
            return "Не удалось вычислить обратный элемент. Повторите генерацию ключа.";
        default:
            return "Неизвестная ошибка (код: " + std::to_string(code) + ").";
    }
}