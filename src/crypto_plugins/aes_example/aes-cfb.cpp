#include "aes-cfb.h"
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <iomanip>

using namespace std;

const unsigned char S_box[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

const unsigned char Inv_S_box[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

const unsigned char Rcon[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };

// Внутренние функции (скрыты от пользователя, не объявлены в header)
void printMatrix(const unsigned char matrix[4][4], const string& name) {
    cout << name << ":\n";
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(matrix[row][col]) << " ";
        }
        cout << "\n";
    }
    cout << dec;
}

void printRoundKeys(unsigned char round_keys[11][4][4]) {
    cout << "\n\t--- СГЕНЕРИРОВАННЫЕ КЛЮЧИ РАУНДОВ ---\n";
    for (int round = 0; round <= 10; ++round) {
        cout << "Раундовый ключ " << round << ": ";
        for (int row = 0; row < 4; ++row) {
            for (int col = 0; col < 4; ++col) {
                cout << hex << setw(2) << setfill('0') << static_cast<int>(round_keys[round][row][col]);
            }
        }
        cout << dec << "\n";
    }
}

unsigned char GF_mult(unsigned char a, unsigned char b) {
    unsigned char result = 0;
    while (b > 0) {
        if (b & 1) result ^= a;
        bool high_bit_set = (a & 0x80); 
        a <<= 1;
        if (high_bit_set) a ^= 0x1B; 
        b >>= 1; 
    }
    return result;
}

void SubBytes(unsigned char matrix[4][4]) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            matrix[r][c] = S_box[matrix[r][c]];
}

void InvSubBytes(unsigned char matrix[4][4]) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            matrix[r][c] = Inv_S_box[matrix[r][c]];
}

void ShiftRows(unsigned char matrix[4][4]) {
    unsigned char first_val = matrix[1][0];
    matrix[1][0] = matrix[1][1]; matrix[1][1] = matrix[1][2];
    matrix[1][2] = matrix[1][3]; matrix[1][3] = first_val;
    swap(matrix[2][0], matrix[2][2]);
    swap(matrix[2][1], matrix[2][3]);
    unsigned char last_val = matrix[3][3];
    matrix[3][3] = matrix[3][2]; matrix[3][2] = matrix[3][1];
    matrix[3][1] = matrix[3][0]; matrix[3][0] = last_val;
}

void InvShiftRows(unsigned char matrix[4][4]) {
    unsigned char last_val = matrix[1][3];
    matrix[1][3] = matrix[1][2]; matrix[1][2] = matrix[1][1];
    matrix[1][1] = matrix[1][0]; matrix[1][0] = last_val;
    swap(matrix[2][0], matrix[2][2]);
    swap(matrix[2][1], matrix[2][3]);
    unsigned char first_val = matrix[3][0];
    matrix[3][0] = matrix[3][1]; matrix[3][1] = matrix[3][2];
    matrix[3][2] = matrix[3][3]; matrix[3][3] = first_val;
}

void MixColumns(unsigned char matrix[4][4]) {
    unsigned char col_data[4];
    for (int col = 0; col < 4; ++col) {
        for (int i = 0; i < 4; ++i) col_data[i] = matrix[i][col];
        matrix[0][col] = GF_mult(0x02, col_data[0]) ^ GF_mult(0x03, col_data[1]) ^ col_data[2] ^ col_data[3];
        matrix[1][col] = col_data[0] ^ GF_mult(0x02, col_data[1]) ^ GF_mult(0x03, col_data[2]) ^ col_data[3];
        matrix[2][col] = col_data[0] ^ col_data[1] ^ GF_mult(0x02, col_data[2]) ^ GF_mult(0x03, col_data[3]);
        matrix[3][col] = GF_mult(0x03, col_data[0]) ^ col_data[1] ^ col_data[2] ^ GF_mult(0x02, col_data[3]);
    }
}

void InvMixColumns(unsigned char matrix[4][4]) {
    unsigned char col_data[4];
    for (int col = 0; col < 4; ++col) {
        for(int i = 0; i < 4; ++i) col_data[i] = matrix[i][col];
        matrix[0][col] = GF_mult(0x0e, col_data[0]) ^ GF_mult(0x0b, col_data[1]) ^ GF_mult(0x0d, col_data[2]) ^ GF_mult(0x09, col_data[3]);
        matrix[1][col] = GF_mult(0x09, col_data[0]) ^ GF_mult(0x0e, col_data[1]) ^ GF_mult(0x0b, col_data[2]) ^ GF_mult(0x0d, col_data[3]);
        matrix[2][col] = GF_mult(0x0d, col_data[0]) ^ GF_mult(0x09, col_data[1]) ^ GF_mult(0x0e, col_data[2]) ^ GF_mult(0x0b, col_data[3]);
        matrix[3][col] = GF_mult(0x0b, col_data[0]) ^ GF_mult(0x0d, col_data[1]) ^ GF_mult(0x09, col_data[2]) ^ GF_mult(0x0e, col_data[3]);
    }
}

void AddRoundKey(unsigned char matrix[4][4], unsigned char key[4][4]) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            matrix[r][c] ^= key[r][c];
}

void ExpandKey(unsigned char* master_key, unsigned char round_keys[11][4][4]) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            round_keys[0][r][c] = master_key[r * 4 + c];

    for (int rnd = 1; rnd <= 10; ++rnd) {
        unsigned char tmp[4];
        for (int r = 0; r < 4; ++r) tmp[r] = round_keys[rnd - 1][r][3];

        unsigned char first_b = tmp[0];
        tmp[0] = tmp[1]; tmp[1] = tmp[2]; tmp[2] = tmp[3]; tmp[3] = first_b;

        for (int i = 0; i < 4; ++i) tmp[i] = S_box[tmp[i]];
        tmp[0] ^= Rcon[rnd - 1];

        for (int r = 0; r < 4; ++r) round_keys[rnd][r][0] = round_keys[rnd - 1][r][0] ^ tmp[r];

        for (int c = 1; c < 4; ++c)
            for (int r = 0; r < 4; ++r)
                round_keys[rnd][r][c] = round_keys[rnd][r][c - 1] ^ round_keys[rnd - 1][r][c];
    }
}

void EncryptBlock(unsigned char matrix[4][4], unsigned char round_keys[11][4][4], bool printState = false) {
    AddRoundKey(matrix, round_keys[0]);
    if (printState) printMatrix(matrix, "  После AddRoundKey 0");

    for (int rnd = 1; rnd < 10; ++rnd) {
        SubBytes(matrix);
        if (printState) printMatrix(matrix, "  После SubBytes " + to_string(rnd));
        ShiftRows(matrix);
        if (printState) printMatrix(matrix, "  После ShiftRows " + to_string(rnd));
        MixColumns(matrix);
        if (printState) printMatrix(matrix, "  После MixColumns " + to_string(rnd));
        AddRoundKey(matrix, round_keys[rnd]);
        if (printState) printMatrix(matrix, "  После AddRoundKey " + to_string(rnd));
    }

    SubBytes(matrix);
    if (printState) printMatrix(matrix, "  После SubBytes (финал)");
    ShiftRows(matrix);
    if (printState) printMatrix(matrix, "  После ShiftRows (финал)");
    AddRoundKey(matrix, round_keys[10]);
    if (printState) printMatrix(matrix, "  После AddRoundKey (финал)");
}


// Реализация публичных функций

void AddPKCS7Padding(vector<unsigned char>& data, int blockSize) {
    int padLen = blockSize - (data.size() % blockSize);
    for (int i = 0; i < padLen; ++i) data.push_back(static_cast<unsigned char>(padLen));
}

void RemovePKCS7Padding(vector<unsigned char>& data, int blockSize) {
    if (data.empty()) return;
    int padLen = data.back();
    if (padLen < 1 || padLen > blockSize || padLen > data.size()) {
        cout << "Ошибка: Некорректный паддинг!" << endl;
        return; 
    }
    for (size_t i = data.size() - padLen; i < data.size(); ++i) {
        if (data[i] != padLen) {
            cout << "Ошибка: Паддинг поврежден!" << endl;
            return;
        }
    }
    data.erase(data.end() - padLen, data.end());
}

void printHex(const unsigned char* data, int len) {
    for (int idx = 0; idx < len; ++idx) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(data[idx]) << " ";
    }
    cout << dec << "\n";
}

void generateRandomKey(unsigned char* key) {
    srand(static_cast<unsigned>(time(nullptr)));
    for (int k = 0; k < 16; ++k) key[k] = static_cast<unsigned char>(rand() % 256);
}

void GenerateIV(unsigned char* iv) {
    srand(static_cast<unsigned>(time(nullptr)) ^ rand());
    for (int k = 0; k < 16; ++k) iv[k] = static_cast<unsigned char>(rand() % 256);
}

void StringToBytes(const string& str, vector<unsigned char>& bytes) {
    bytes.clear();
    for (char ch : str) bytes.push_back(static_cast<unsigned char>(ch));
}

void BytesToString(const vector<unsigned char>& bytes, string& str) {
    str.clear();
    for (unsigned char b : bytes) str += static_cast<char>(b);
}

void EncryptCFB(const vector<unsigned char>& textOrig,
    vector<unsigned char>& textCript,
    unsigned char* key,
    unsigned char* iv,
    bool verbose) {

    unsigned char round_keys[11][4][4];
    ExpandKey(key, round_keys);
    
    if (verbose) {
        printRoundKeys(round_keys);
        cout << "\n\tВЕКТОР ИНИЦИАЛИЗАЦИИ (IV)\n";
        printHex(iv, 16);
    }

    textCript.clear();
    for (int i = 0; i < 16; ++i) textCript.push_back(iv[i]);

    unsigned char feedback[16];
    for (int i = 0; i < 16; ++i) feedback[i] = iv[i];

    int blockCounter = 0;
    size_t block_idx = 0;
    
    while (block_idx < textOrig.size()) {
        unsigned char matrix[4][4];

        if (verbose) {
            cout << "\n\tОБРАБОТКА БЛОКА " << blockCounter++ << "\n";
            cout << "Feedback до шифрования: ";
            printHex(feedback, 16);
        }

        for (int i = 0; i < 16; ++i) matrix[i / 4][i % 4] = feedback[i];
        
        if (verbose) printMatrix(matrix, "  State до");
        EncryptBlock(matrix, round_keys, verbose);
        if (verbose) printMatrix(matrix, "  State после");

        for (int i = 0; i < 16 && (block_idx + i) < textOrig.size(); ++i) {
            unsigned char encrypted_byte = matrix[i / 4][i % 4];
            textCript.push_back(encrypted_byte ^ textOrig[block_idx + i]);
            feedback[i] = textCript.back();
        }
        
        if (verbose) {
            cout << "Получен шифротекст блока: ";
            size_t bytes_processed = (block_idx + 16 < textOrig.size()) ? 16 : (textOrig.size() - block_idx);
            for (size_t i = textCript.size() - bytes_processed; i < textCript.size(); ++i) {
                cout << hex << setw(2) << setfill('0') << static_cast<int>(textCript[i]);
            }
            cout << dec << "\n";
        }
        
        block_idx += 16;
    }
}

void DecryptCFB(const vector<unsigned char>& textCript,
    vector<unsigned char>& textOrig,
    unsigned char* key) {

    textOrig.clear();
    if (textCript.size() < 16) return;

    unsigned char round_keys[11][4][4];
    ExpandKey(key, round_keys);

    unsigned char iv[16];
    unsigned char feedback[16];
    for (int i = 0; i < 16; ++i) {
        iv[i] = textCript[i];
        feedback[i] = iv[i];
    }

    size_t block_idx = 16;
    while (block_idx < textCript.size()) {
        unsigned char matrix[4][4];
        for (int i = 0; i < 16; ++i) matrix[i / 4][i % 4] = feedback[i];

        EncryptBlock(matrix, round_keys, false);

        for (int i = 0; i < 16 && (block_idx + i) < textCript.size(); ++i) {
            textOrig.push_back(matrix[i / 4][i % 4] ^ textCript[block_idx + i]);
            feedback[i] = textCript[block_idx + i];
        }
        block_idx += 16;
    }
}