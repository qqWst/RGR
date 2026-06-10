#include "aes-cfb.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <limits>

using namespace std;

// === ПЕРЕЧИСЛЕНИЯ ДЛЯ АРХИТЕКТУРЫ ===

enum class CipherAlgorithm {
    AES_128_CFB = 1,
    DES_CBC = 2,  // Ваш шифр
    RC4 = 3       // Ваш шифр
};

enum class InputMode {
    CONSOLE = 1,
    FILE = 2
};

// === БАЗОВЫЕ ФУНКЦИИ ФАЙЛОВОГО ВВОДА/ВЫВОДА ===

vector<unsigned char> readFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "Ошибка: Не удалось открыть файл " << filename << "\n";
        return {};
    }
    return vector<unsigned char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

void writeFile(const string& filename, const vector<unsigned char>& data) {
    ofstream file(filename, ios::binary);
    if (!file) {
        cerr << "Ошибка: Не удалось создать файл " << filename << "\n";
        return;
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}


// === ЛОГИКА ДЛЯ AES-128 CFB ===

void runAesCfbConsole() {
    unsigned char key[16];
    generateRandomKey(key);
    
    cout << "\n[AES-128 CFB] Сгенерированный случайный ключ: ";
    printHex(key, 16);
    
    cout << "Введите текст для шифрования: ";
    string original;
    getline(cin, original);

    vector<unsigned char> plain;
    StringToBytes(original, plain);

    AddPKCS7Padding(plain);

    unsigned char iv[16];
    GenerateIV(iv);
    
    vector<unsigned char> textCript;
    // verbose = true, чтобы видеть пошаговый процесс в консоли
    EncryptCFB(plain, textCript, key, iv, true);

    cout << "\n\tПОЛНЫЙ ШИФРОТЕКСТ\nДанные: ";
    for (size_t i = 0; i < textCript.size(); ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(textCript[i]);
    }
    cout << dec << "\n\n";

    vector<unsigned char> decrypted;
    DecryptCFB(textCript, decrypted, key);
    RemovePKCS7Padding(decrypted);

    string result;
    BytesToString(decrypted, result);
    cout << "=== РЕЗУЛЬТАТ ===\nРасшифрованный текст: " << result << "\n";
}

void runAesCfbFile() {
    string filename;
    cout << "\n[AES-128 CFB] Введите имя файла (например, test.jpg или text.txt): ";
    cin >> filename;

    vector<unsigned char> plain = readFile(filename);
    if (plain.empty()) return;

    cout << "Считано " << plain.size() << " байт из файла " << filename << "\n";

    unsigned char key[16];
    generateRandomKey(key);
    cout << "Сгенерирован ключ: ";
    printHex(key, 16);

    unsigned char iv[16];
    GenerateIV(iv);

    AddPKCS7Padding(plain);
    vector<unsigned char> textCript;
    
    cout << "Шифрование... (пожалуйста, подождите)\n";
    // verbose = false, чтобы не засорять консоль
    EncryptCFB(plain, textCript, key, iv, false);

    string encFilename = "encrypted_" + filename;
    writeFile(encFilename, textCript);
    cout << "Зашифрованные данные сохранены в: " << encFilename << "\n";

    cout << "Расшифровка...\n";
    vector<unsigned char> decrypted;
    DecryptCFB(textCript, decrypted, key);
    RemovePKCS7Padding(decrypted);

    string decFilename = "decrypted_" + filename;
    writeFile(decFilename, decrypted);
    cout << "Восстановленные данные сохранены в: " << decFilename << "\n";
}

//добавить собственную логику для каждого шифра

// === ГЛАВНАЯ ФУНКЦИЯ ПРОГРАММЫ ===

int main() {
    setlocale(LC_ALL, "ru_RU.UTF-8");
    
    // 1. Выбор алгоритма
    cout << "=== ВЫБОР АЛГОРИТМА ШИФРОВАНИЯ ===\n";
    cout << "1. AES-128 CFB\n";
    cout << "2. (ваш шифр)\n";
    cout << "3. (ваш шифр)\n";
    cout << "Ваш выбор: ";
    
    int algoChoice;
    if (!(cin >> algoChoice)) {
        cout << "Ошибка ввода.\n";
        return 1;
    }
    CipherAlgorithm algo = static_cast<CipherAlgorithm>(algoChoice);

    // 2. Выбор режима работы
    cout << "\n=== ВЫБОР ИСТОЧНИКА ДАННЫХ ===\n";
    cout << "1. Ввод текста из консоли\n";
    cout << "2. Работа с файлом (txt, mp3, jpg, и др.)\n";
    cout << "Ваш выбор: ";
    
    int modeChoice;
    if (!(cin >> modeChoice)) {
        cout << "Ошибка ввода.\n";
        return 1;
    }
    InputMode mode = static_cast<InputMode>(modeChoice);

    // Очистка буфера после ввода чисел (необходимо перед getline)
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    // 3. Вызов нужного алгоритма
    switch (algo) {
        
        case CipherAlgorithm::AES_128_CFB:
            if (mode == InputMode::CONSOLE) {
                runAesCfbConsole();
            } else if (mode == InputMode::FILE) {
                runAesCfbFile();
            } else {
                cout << "Неверный режим работы.\n";
            }
            break;

        case CipherAlgorithm::DES_CBC:
            cout << "\n[DES CBC] Извините, алгоритм еще не подключен к системе.\n";
            // В будущем здесь будет: 
            // if (mode == InputMode::CONSOLE) runDesConsole(); 
            // и т.д.
            break;

        case CipherAlgorithm::RC4:
            cout << "\n[RC4] Извините, алгоритм еще не подключен к системе.\n";
            break;

        default:
            cout << "\nОшибка: Выбран неизвестный алгоритм шифрования.\n";
            break;
    }

    return 0;
}