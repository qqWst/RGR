#ifdef UI.H
#define UI.H

enum class Action {
    ENCRYPT,
    DECRYPT,
    BOTH,
    KEYGENERATION
};

// Перечисления для выбора пользователя
enum class KeyGeneration {
    MANUAL,
    DIFFIE_HELLMAN,
    RSA,
    SHAMIR
};

enum class EncryptMethod {
    RSA,
    LOKI91
};

enum class InputMethod {
    CONSOLE,
    FILE
};

#endif