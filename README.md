# sentinel
— это учебное криптографическое приложение с плагинной архитектурой. 
Основной модуль динамически загружает библиотеки алгоритмов во время выполнения, что позволяет легко добавлять новые криптографические протоколы без перекомпиляции основного приложения.

## Архитектура

Главный модуль `sentinel` динамически загружает библиотеку выбранного алгоритма:
- **Linux**: `*.so` (например, `xor.so`)
- **macOS**: `*.dylib`
- **Windows**: `*.dll`

через `dlopen`/`LoadLibrary`.

Каждая библиотека экспортирует 7 функций:
- `getAlgorithmName` — возвращает название алгоритма;
- `getKeyInfo` — возвращает описание формата ключа;
- `generateKey` — генерация ключа;
- `encrypt` — шифрование;
- `decrypt` — расшифрование;
- `getMinKeySize` — минимальный размер ключа;
- `getMaxKeySize` — максимальный размер ключа.

## Структура

sentinel/
│
├── build/                          # Артефакты сборки
│   ├── obj/                        # Объектные файлы
│   │   ├── fileProcessor.o
│   │   ├── keyGenerator.o
│   │   ├── libraryLoader.o
│   │   ├── main.o
│   │   ├── menu.o
│   │   ├── textProcessor.o
│   │   └── utils.o
│   ├── plugins/                    # Собранные библиотеки плагинов (.so/.dylib/.dll)
│   │   ├── diffie-hellman.so
│   │   ├── fiatShamir.so
│   │   ├── rabinCipher.so
│   │   ├── rsaCipher.so
│   │   ├── shamirCipher.so
│   │   └── xorCipher.so
│   └── sentinel                    # Исполняемый файл
│
├── include/                        # Заголовочные файлы
│   ├── cryptoApi.h
│   ├── fileProcessor.h
│   ├── keyGenerator.h
│   ├── libraryLoader.h
│   ├── menu.h
│   ├── textProcessor.h
│   └── utils.h
│
├── keys/                           # Сгенерированные ключи алгоритмов
│   ├── FS.txt                      # Ключи Fiat-Shamir
│   ├── rsa.txt                     # Ключи RSA
│   └── shamir.txt                  # Ключи Shamir
│
├── plugins/ # Исходный код плагинов
│ ├── diffie-hellmanCipher.cpp # Diffie-Hellman
│ ├── fiatShamirCipher.cpp # Fiat-Shamir
│ ├── rabinCipher.cpp # Rabin
│ ├── rsaCipher.cpp # RSA
│ ├── shamirCipher.cpp # Shamir
│ └── xorCipher.cpp # XOR
│
├── src/                            # Исходный код приложения
│   ├── fileProcessor.cpp
│   ├── keyGenerator.cpp
│   ├── libraryLoader.cpp
│   ├── main.cpp
│   ├── menu.cpp
│   ├── textProcessor.cpp
│   └── utils.cpp
│
├── testFiles/                      # Тестовые файлы
│   ├── Kon.mp3
│   └── NGTU.jpg
│
├── arch.txt                        # Архитектура
├── Makefile                        # Файл сборки
├── NGTU.jpg                        # изображение
└── README.md                       # Документация


## Сборка

### Требования
- g++ с поддержкой C++17
- Linux/macOS (для Windows используйте MinGW/MSYS2)

### Команды сборки

``bash

 Полная сборка (приложение + все плагины)

make all

 Только приложение
 
make app

 Только плагины
 
make plugins

 Сборка и запуск
 
make run

 Очистка артефактов
 
make clean

 Справка по командам
 
make help

## Использование

./build/sentinel

./build/sentinel --help

./build/sentinel -a xor -m generate-key -s key.bin

./build/sentinel -a xor -m encrypt -k key.bin -i file.txt -o file.enc

./build/sentinel -a xor -m decrypt -k key.bin -i file.enc -o file.txt

## Поддерживаемые алгоритмы

| Имя            | Библиотека        | Описание                    |
|----------------|-------------------|-----------------------------|
| xor            | xor.so            | XOR потоковый шифр          |
| rsa            | rsa.so            | RSA (малые простые)         |
| rabin          | rabin.so          | Криптосистема Рабина        |
| shamir         | shamir.so         | Протокол Шамира             |
| fiat-shamir    | fiatshamir.so     | Протокол Фиата-Шамира       |
| diffie-hellman | diffie-hellman.so | Протокол Диффи-Хеллмана     |

Все реализации **учебные**, не предназначены для защиты реальных данных.
