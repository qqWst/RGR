# cryptum — учебная криптоутилита с динамическими библиотеками

## Архитектура

Главный модуль `cryptum` динамически загружает библиотеку
выбранного алгоритма (`libxor.so`, `librsa.so`, ...) во время
выполнения через `dlopen`/`LoadLibrary`.

Каждая библиотека экспортирует 3 функции:
- `generateKey` — генерация ключа;
- `encrypt` — шифрование;
- `decrypt` — расшифрование.

## Сборка

Через CMake:

    mkdir build && cd build
    cmake .. && make

Или через Make:

    make

## Использование

    ./cryptum --help
    ./cryptum -a xor -m generate-key -s key.bin
    ./cryptum -a xor -m encrypt -k key.bin -i file.txt -o file.enc
    ./cryptum -a xor -m decrypt -k key.bin -i file.enc -o file.txt

## Запуск тестов

    ./cryptumTest

## Поддерживаемые алгоритмы

| Имя    | Библиотека   | Описание                |
|--------|--------------|-------------------------|
| xor    | libxor.so    | XOR потоковый шифр      |
| rsa    | librsa.so    | RSA (малые простые)     |
| rabin  | librabin.so  | Криптосистема Рабина    |
| shamir | libshamir.so | Протокол Шамира         |

Все реализации **учебные**, не предназначены для защиты реальных данных.