#ifndef MENU_H
#define MENU_H

#include "libraryLoader.h"
#include <vector>

enum class MainMenuOption {
    EncryptDecryptText = 1,
    EncryptDecryptFile = 2,
    KeyGenerator       = 3,
    ShowKeyInfo        = 4,
    Exit               = 0
};

enum class CryptoAction {
    Encrypt = 1,
    Decrypt = 2,
    Back    = 0
};

void runMainMenu(std::vector<CryptoPlugin>& plugins);

#endif