#include "aes-cfb.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>

using namespace std;

// Функция для чтения любого файла (в т.ч. бинарного)
vector<unsigned char> readFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "Ошибка: Не удалось открыть файл " << filename << "\n";
        return {};
    }
    return vector<unsigned char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

// Функция для записи любого файла (в т.ч. бинарного)
void writeFile(const string& filename, const vector<unsigned char>& data) {
    ofstream file(filename, ios::binary);
    if (!file) {
        cerr << "Ошибка: Не удалось создать файл " << filename << "\n";
        return;
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

void runConsoleMode() {
    unsigned char key[16];
    generateRandomKey(key);
    
    cout << "\nСгенерированный случайный ключ: ";
    printHex(key, 16);
    
    cout << "Введите текст для шифрования: ";
    string original;
    cin.ignore();
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

void runFileMode() {
    string filename;
    cout << "\nВведите имя файла (с расширением, например test.jpg или text.txt): ";
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

    // Паддинг и Шифрование
    AddPKCS7Padding(plain);
    vector<unsigned char> textCript;
    
    cout << "Шифрование... (пожалуйста, подождите)\n";
    // verbose = false, чтобы не засорять консоль миллионами строк
    EncryptCFB(plain, textCript, key, iv, false);

    string encFilename = "encrypted_" + filename;
    writeFile(encFilename, textCript);
    cout << "Зашифрованные данные сохранены в файл: " << encFilename << "\n";

    // Расшифрование
    cout << "Расшифровка...\n";
    vector<unsigned char> decrypted;
    DecryptCFB(textCript, decrypted, key);
    RemovePKCS7Padding(decrypted);

    string decFilename = "decrypted_" + filename;
    writeFile(decFilename, decrypted);
    cout << "Восстановленные данные сохранены в файл: " << decFilename << "\n";
    cout << "Готово! Проверьте файлы.\n";
}

int main() {
    setlocale(LC_ALL, "ru_RU.UTF-8");
    
    cout << "=== AES-128 CFB ===\n";
    cout << "1. Ввод текста из консоли\n";
    cout << "2. Шифрование файла (txt, mp3, jpeg и др.)\n";
    cout << "Выберите режим (1 или 2): ";
    
    int choice;
    if (cin >> choice) {
        if (choice == 1) {
            runConsoleMode();
        } else if (choice == 2) {
            runFileMode();
        } else {
            cout << "Неверный выбор.\n";
        }
    }

    return 0;
}