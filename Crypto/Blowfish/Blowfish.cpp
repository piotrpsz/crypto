#include <iostream>
#include <string>
#include <cstring>
#include <sys/random.h>
#include "Blowfish.h"
#include "BlowfishData.h"

using namespace std;

Blowfish::Blowfish(const void* const cipher_key, const int key_size) {
    if (key_size < MinKeySize || key_size > MaxKeySize) {
        cerr << "Error (blowfish): invalid key size" << endl;
        return;
    }

    const u8* const key = static_cast<const u8*>(cipher_key);

    // S - init
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 256; j++) {
            s[i][j] = orgs[i][j];
        }
    }

    // P - init
    int k = 0;
    for (int i = 0; i < (RoundCount + 2); i++) {
        u32 d = 0;
        for (int j = 0; j < 4; j++) {
            d = (d << 8) | u32(key[k]);
            ++k;
            if (k >= key_size) {
                k = 0;
            }
        }
        p[i] = orgp[i] ^ d;
    }


    // P
    u32 data[2] = {0, 0};
    for (int i = 0; i < (RoundCount + 2); i += 2) {
        encrypt_block(data, data);
        p[i] = data[0];
        p[i+1] = data[1];
    }

    // S
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 256; j += 2) {
            encrypt_block(data, data);
            s[i][j] = data[0];
            s[i][j+1] = data[1];
        }
    }
}

inline u32 Blowfish::f(u32 x) const noexcept {
    const u32 d = x & 0x00ff; x >>= 8;
    const u32 c = x & 0x00ff; x >>= 8;
    const u32 b = x & 0x00ff; x >>= 8;
    const u32 a = x & 0x00ff;
    return ((s[0][a] + s[1][b]) ^ s[2][c]) + s[3][d];
}

void Blowfish::encrypt_block(const u32* const src, u32* const dst) const noexcept {
    u32 xl = src[0];
    u32 xr = src[1];

    xl = xl ^ p[0];
    xr = f(xl) ^ xr;
    xr = xr ^ p[1];
    xl = f(xr) ^ xl;

    xl = xl ^ p[2];
    xr = f(xl) ^ xr;
    xr = xr ^ p[3];
    xl = f(xr) ^ xl;

    xl = xl ^ p[4];
    xr = f(xl) ^ xr;
    xr = xr ^ p[5];
    xl = f(xr) ^ xl;

    xl = xl ^ p[6];
    xr = f(xl) ^ xr;
    xr = xr ^ p[7];
    xl = f(xr) ^ xl;

    xl = xl ^ p[8];
    xr = f(xl) ^ xr;
    xr = xr ^ p[9];
    xl = f(xr) ^ xl;

    xl = xl ^ p[10];
    xr = f(xl) ^ xr;
    xr = xr ^ p[11];
    xl = f(xr) ^ xl;

    xl = xl ^ p[12];
    xr = f(xl) ^ xr;
    xr = xr ^ p[13];
    xl = f(xr) ^ xl;

    xl = xl ^ p[14];
    xr = f(xl) ^ xr;
    xr = xr ^ p[15];
    xl = f(xr) ^ xl;

    dst[0] = xr ^ p[17];
    dst[1] = xl ^ p[16];
}

void Blowfish::decrypt_block(const u32* const src, u32* const dst) const noexcept {
    u32 xl = src[0];
    u32 xr = src[1];

    xl = xl ^ p[17];
    xr = f(xl) ^ xr;
    xr = xr ^ p[16];
    xl = f(xr) ^ xl;

    xl = xl ^ p[15];
    xr = f(xl) ^ xr;
    xr = xr ^ p[14];
    xl = f(xr) ^ xl;

    xl = xl ^ p[13];
    xr = f(xl) ^ xr;
    xr = xr ^ p[12];
    xl = f(xr) ^ xl;

    xl = xl ^ p[11];
    xr = f(xl) ^ xr;
    xr = xr ^ p[10];
    xl = f(xr) ^ xl;

    xl = xl ^ p[9];
    xr = f(xl) ^ xr;
    xr = xr ^ p[8];
    xl = f(xr) ^ xl;

    xl = xl ^ p[7];
    xr = f(xl) ^ xr;
    xr = xr ^ p[6];
    xl = f(xr) ^ xl;

    xl = xl ^ p[5];
    xr = f(xl) ^ xr;
    xr = xr ^ p[4];
    xl = f(xr) ^ xl;

    xl = xl ^ p[3];
    xr = f(xl) ^ xr;
    xr = xr ^ p[2];
    xl = f(xr) ^ xl;

    dst[0] = xr ^ p[0];
    dst[1] = xl ^ p[1];
}

/**
 * @brief encrypt_ecb
 * Szyfrowanie w trybie CBC.
 * Jeśli rozmiar jawnych danych nie jest wielokrotnością rozmiaru bloku
 * zostanie uzupełniony o tzw. padding.
 *
 * @param data - adres bufora z jawnymi danymi do zaszyfrowania.
 * @param nbytes - rozmiar bufora z jawnymi danymi w bajtach.
 * @return - tuple: adres bufora z zaszyfrowanymi danymi + jego rozmiar w bajtach.
 */
std::tuple<shared_ptr<void>, int>
Blowfish::encrypt_ecb(const void* const data, const int nbytes) const noexcept {

    if (data == nullptr || nbytes == 0) {
        return make_tuple(shared_ptr<void>(nullptr), 0);
    }

    int size = nbytes;
    const int n = size % BlockSize;
    u8* const plain = new u8[size + n];
    memcpy(plain, data, size);
    if (n) {
        // Ponieważ rozmiar bufora danych do zaszyfrownia
        // nie jest wielokrotnością bloku dodajemy padding
        // o stosownej długości.
        bzero(plain + size, n);
        plain[size] = 128;
        size += n;
    }

    u8* const cipher = new u8[size];

    u32* src = reinterpret_cast<u32*>(plain);
    u32* dst = reinterpret_cast<u32*>(cipher);

    for (int i = 0; i < (size/BlockSize); i++) {
        encrypt_block(src, dst);
        src += 2;
        dst += 2;
    }

    delete[] plain;
    return make_tuple(shared_ptr<void>(cipher, [](void* ptr) {delete[] static_cast<u8*>(ptr);}), size);
}

/**
 * @brief decrypt_ecb
 * Deszyfrowanie w trybie ECB.
 * Jeśli odszyfrowane jawne dane zawierają padding to zostanie on 'ucięty'.
 *
 * @param data - adres bufora z zaszyfrowanymi danymi do odszyfrowania.
 * @param nbytes - rozmiar bufora z zaszyfrowanymi danymi w bajtach.
 * @return - tuple: adres bufora z odszyfrowanymi danymi + jego rozmiar w bajtach.
 */
std::tuple<std::shared_ptr<void>, int>
Blowfish::decrypt_ecb(const void* const cipher, int nbytes) const noexcept {

    if (cipher == nullptr || nbytes == 0) {
        return make_tuple(shared_ptr<void>(nullptr), 0);
    }

    u8* const plain  = new u8[nbytes];
    bzero(plain, nbytes);

    const u32* src = reinterpret_cast<const u32*>(cipher);
    u32* dst = reinterpret_cast<u32*>(plain);

    for (int i = 0; i < (nbytes/BlockSize); i++) {
        decrypt_block(src, dst);
        src += 2;
        dst += 2;
    }

    if (const int idx = padding_index(plain, nbytes); idx != -1) {
        nbytes = idx;
    }
    return make_tuple(shared_ptr<void>(plain, [](void* ptr) {delete[] static_cast<u8*>(ptr);}), nbytes);
}

/**
 * @brief encrypt_cbc
 * Szyfrowanie CBC z wektorem IV. Jeśli IV nie został przekazany
 * jako parametr to zostanie losowo wygenerowany.
 * Wektor IV jest pierwszym blokiem zaszyfrowanych danych.
 * Jeśli rozmiar jawnych danych nie jest wielokrotnością rozmiaru bloku
 * zostanie uzupełniony o tzw. padding.
 *
 * @param data - adres bufora z jawnymi danymi do zaszyfrowania.
 * @param nbytes - rozmiar bufora z jawnymi danymi w bajtach.
 * @param iv - adres wektor IV (może być nullptr).
 * @return - tuple: adres bufora z zaszyfrowanymi danymi + jego rozmiar w bajtach.
 */
std::tuple<std::shared_ptr<void>, int>
Blowfish::encrypt_cbc(const void* const data, const int nbytes, void* iv) const noexcept {

    if (data == nullptr || nbytes == 0) {
        return make_tuple(shared_ptr<void>(nullptr), 0);
    }

    bool custom_iv = false;
    if (iv == nullptr) {
        // Jeśli funkcja wywołująca nie przekazała wektora IV
        // sami generujemy go losowo.
        iv = new u8[BlockSize];
        while (getrandom(iv, BlockSize, 0) != BlockSize);
        custom_iv = true;
    }

    u8* plain = nullptr;
    int size = nbytes;
    const int n = size % BlockSize;
    if (n) {
        // Ponieważ rozmiar bufora danych do zaszyfrownia
        // nie jest wielokrotnością bloku dodajemy padding
        // o stosownej długości.
        const int dn = BlockSize - n;
        plain = new u8[size + dn];
        memcpy(plain, data, size);
        bzero(plain + size, dn);
        plain[size] = 128;
        size += dn;
    } else {
        plain = new u8[size];
        memcpy(plain, data, size);
    }

    u8* const cipher = new u8[size + BlockSize];

    u32* src = reinterpret_cast<u32*>(plain);
    u32* dst = reinterpret_cast<u32*>(cipher);
    memcpy(dst, iv, BlockSize);

    u32 tmp[2];
    for (int i = 0; i < (size/BlockSize); i++) {
        tmp[0] = src[0] ^ dst[0];
        tmp[1] = src[1] ^ dst[1];
        dst += 2;
        encrypt_block(tmp, dst);
        src += 2;
    }

    if (custom_iv) delete[] static_cast<u8*>(iv);
    delete[] plain;

    return make_tuple(shared_ptr<void>(cipher, [](void* ptr) {delete[] static_cast<u8*>(ptr);}), size + BlockSize);
}

/**
 * @brief decrypt_cbc
 * Deszyfrowanie CBC.
 * Należy pamietać że pierwszym blokiem zaszyfrowanych danych jest wektor IV.
 * Jeśli odszyfrowane jawne dane zawierają padding to zostanie on 'ucięty'.
 *
 * @param data - adres bufora z zaszyfrowanymi danymi do odszyfrowania.
 * @param nbytes - rozmiar bufora z zaszyfrowanymi danymi w bajtach.
 * @return - tuple: adres bufora z odszyfrowanymi danymi + jego rozmiar w bajtach.
 */
std::tuple<std::shared_ptr<void>, int>
Blowfish::decrypt_cbc(const void* const cipher, int nbytes) const noexcept {

    if (cipher == nullptr || nbytes == 0) {
        return make_tuple(shared_ptr<void>(nullptr), 0);
    }

    nbytes -= BlockSize;
    u8* const plain  = new u8[nbytes];
    bzero(plain, nbytes);

    const u32* src = reinterpret_cast<const u32*>(cipher);
    u32* dst = reinterpret_cast<u32*>(plain);

    for (int i = 0; i < (nbytes/BlockSize); i++) {
        decrypt_block(src + 2, dst);

        dst[0] = dst[0] ^ src[0];
        dst[1] = dst[1] ^ src[1];
        dst += 2;
        src += 2;
    }

    if (const int idx = padding_index(plain, nbytes); idx != -1) {
        nbytes = idx;
    }
    return make_tuple(shared_ptr<void>(plain, [](void* ptr) {delete[] static_cast<u8*>(ptr);}), nbytes);
}

/**
 * @brief padding_index
 * Wyszukiwanie od końca 1-szego wystąpienia bajtu o wartości 128.
 * Szukany bajt może być poprzedzony (od końca) tylko bajtami zerowymi.
 *
 * @param data - adres bufora z danymi.
 * @param nbytes - rozmiar bufora z danymi.
 * @return indeks bajtu w wartości 128, lub -1 jeśli nie znaleziono.
 */
int Blowfish::padding_index(const u8* const data, const int nbytes) const noexcept {
    for (int i = nbytes - 1; i >= 0; i--) {
        if (data[i] != 0) {
            if (data[i] == 128) {
                return i;
            }
            break;
        }
    }
    return -1;
}
