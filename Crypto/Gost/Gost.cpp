/*
 * BSD 2-Clause License
 *
 * Copyright (c) 2020, Piotr Pszczółkowski
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*------- include files:
-------------------------------------------------------------------*/
#include <iostream>
#include <cstring>
#include "Gost.h"
#include "Crypto/Crypto.h"

/*------- namespaces:
-------------------------------------------------------------------*/
namespace beesoft {
namespace crypto {
using namespace std;

static constexpr int BlockSize = 8;
static constexpr int KeySize = 32;  // in bytes (= 8xu32)


Gost::Gost(const void* const user_key, const int key_size) {
    if (key_size != KeySize) {
        cerr << "Error (blowfish): invalid key size" << endl;
        return;
    }

    static const u8 k8[16] = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7};
    static const u8 k7[16] = {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10};
    static const u8 k6[16] = {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8};
    static const u8 k5[16] = {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15};
    static const u8 k4[16] = {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9};
    static const u8 k3[16] = {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11};
    static const u8 k2[16] = {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1};
    static const u8 k1[16] = {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7};

    memcpy(k, user_key, KeySize);

    for (int i = 0; i < 256; i++) {
        const int p1 = i >> 4;
        const int p2 = i & 15;
        k87[i] = (k8[p1] << 4) | k7[p2];
        k65[i] = (k6[p1] << 4) | k5[p2];
        k43[i] = (k4[p1] << 4) | k3[p2];
        k21[i] = (k2[p1] << 4) | k1[p2];
    }
}

Gost::~Gost() {
    Crypto::clear_bytes(k, 8 * sizeof(u32));
    Crypto::clear_bytes(k87, 256);
    Crypto::clear_bytes(k65, 256);
    Crypto::clear_bytes(k43, 256);
    Crypto::clear_bytes(k21, 256);
}

/**
 * @brief encrypt_cbc
 * Szyfrowanie w trybie CBC z wektorem IV. Jeśli IV nie został przekazany
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
Gost::encrypt_cbc(const void* const data, const int nbytes, void* iv) const noexcept {

    if (data == nullptr || nbytes == 0) {
        return make_tuple(shared_ptr<void>(nullptr), 0);
    }

    bool custom_iv = false;
    if (iv == nullptr) {
        // Jeśli funkcja wywołująca nie przekazała wektora IV
        // sami generujemy go losowo.
        iv = new u8[BlockSize];
        Crypto::random_bytes(iv, BlockSize);
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
 * Deszyfrowanie w trybie CBC.
 * Należy pamietać że pierwszym blokiem zaszyfrowanych danych jest wektor IV.
 * Jeśli odszyfrowane jawne dane zawierają padding to zostanie on 'ucięty'.
 *
 * @param data - adres bufora z zaszyfrowanymi danymi do odszyfrowania.
 * @param nbytes - rozmiar bufora z zaszyfrowanymi danymi w bajtach.
 * @return - tuple: adres bufora z odszyfrowanymi danymi + jego rozmiar w bajtach.
 */
std::tuple<std::shared_ptr<void>, int>
Gost::decrypt_cbc(const void* const cipher, int nbytes) const noexcept {

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

    if (const int idx = Crypto::padding_index(plain, nbytes); idx != -1) {
        nbytes = idx;
    }
    return make_tuple(shared_ptr<void>(plain, [](void* ptr) {delete[] static_cast<u8*>(ptr);}), nbytes);
}

/**
 * @brief encrypt_ecb
 * Szyfrowanie w trybie ECB.
 * Jeśli rozmiar jawnych danych nie jest wielokrotnością rozmiaru bloku
 * zostanie uzupełniony o tzw. padding.
 *
 * @param data - adres bufora z jawnymi danymi do zaszyfrowania.
 * @param nbytes - rozmiar bufora z jawnymi danymi w bajtach.
 * @return - tuple: adres bufora z zaszyfrowanymi danymi + jego rozmiar w bajtach.
 */
std::tuple<shared_ptr<void>, int>
Gost::encrypt_ecb(const void* const data, const int nbytes) const noexcept {

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
Gost::decrypt_ecb(const void* const cipher, int nbytes) const noexcept {

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

    if (const int idx = Crypto::padding_index(plain, nbytes); idx != -1) {
        nbytes = idx;
    }
    return make_tuple(shared_ptr<void>(plain, [](void* ptr) {delete[] static_cast<u8*>(ptr);}), nbytes);
}

/**
 * @brief encrypt_block
 * Szyfrowanie bloku (2xu32) jawnych danych.
 *
 * @param src - adres bufora z jawnymi danymi.
 * @param dst - adres bufora na dane zaszyfrowane.
 */
void Gost::encrypt_block(const u32* const src, u32* const dst) const noexcept {
    u32 n1 = src[0];
    u32 n2 = src[1];

    n2 ^= f(n1 + k[0]);
    n1 ^= f(n2 + k[1]);
    n2 ^= f(n1 + k[2]);
    n1 ^= f(n2 + k[3]);
    n2 ^= f(n1 + k[4]);
    n1 ^= f(n2 + k[5]);
    n2 ^= f(n1 + k[6]);
    n1 ^= f(n2 + k[7]);

    n2 ^= f(n1 + k[0]);
    n1 ^= f(n2 + k[1]);
    n2 ^= f(n1 + k[2]);
    n1 ^= f(n2 + k[3]);
    n2 ^= f(n1 + k[4]);
    n1 ^= f(n2 + k[5]);
    n2 ^= f(n1 + k[6]);
    n1 ^= f(n2 + k[7]);

    n2 ^= f(n1 + k[0]);
    n1 ^= f(n2 + k[1]);
    n2 ^= f(n1 + k[2]);
    n1 ^= f(n2 + k[3]);
    n2 ^= f(n1 + k[4]);
    n1 ^= f(n2 + k[5]);
    n2 ^= f(n1 + k[6]);
    n1 ^= f(n2 + k[7]);

    n2 ^= f(n1 + k[7]);
    n1 ^= f(n2 + k[6]);
    n2 ^= f(n1 + k[5]);
    n1 ^= f(n2 + k[4]);
    n2 ^= f(n1 + k[3]);
    n1 ^= f(n2 + k[2]);
    n2 ^= f(n1 + k[1]);
    n1 ^= f(n2 + k[0]);

    dst[0] = n2;
    dst[1] = n1;
}

/**
 * @brief decrypt_block
 * Odszyfrowanie bloku (2xu32) zaszyfrowanych danych.
 *
 * @param src - adres bufora z zaszyfrowanymi danymi
 * @param dst - adres bufora na dane odszyfrowane.
 */
void Gost::decrypt_block(const u32* const src, u32* const dst) const noexcept {
    u32 n1 = src[0];
    u32 n2 = src[1];

    n2 ^= f(n1 + k[0]);
    n1 ^= f(n2 + k[1]);
    n2 ^= f(n1 + k[2]);
    n1 ^= f(n2 + k[3]);
    n2 ^= f(n1 + k[4]);
    n1 ^= f(n2 + k[5]);
    n2 ^= f(n1 + k[6]);
    n1 ^= f(n2 + k[7]);

    n2 ^= f(n1 + k[7]);
    n1 ^= f(n2 + k[6]);
    n2 ^= f(n1 + k[5]);
    n1 ^= f(n2 + k[4]);
    n2 ^= f(n1 + k[3]);
    n1 ^= f(n2 + k[2]);
    n2 ^= f(n1 + k[1]);
    n1 ^= f(n2 + k[0]);

    n2 ^= f(n1 + k[7]);
    n1 ^= f(n2 + k[6]);
    n2 ^= f(n1 + k[5]);
    n1 ^= f(n2 + k[4]);
    n2 ^= f(n1 + k[3]);
    n1 ^= f(n2 + k[2]);
    n2 ^= f(n1 + k[1]);
    n1 ^= f(n2 + k[0]);

    n2 ^= f(n1 + k[7]);
    n1 ^= f(n2 + k[6]);
    n2 ^= f(n1 + k[5]);
    n1 ^= f(n2 + k[4]);
    n2 ^= f(n1 + k[3]);
    n1 ^= f(n2 + k[2]);
    n2 ^= f(n1 + k[1]);
    n1 ^= f(n2 + k[0]);

    dst[0] = n2;
    dst[1] = n1;
}

inline u32 Gost::f(const u32 x) const noexcept {
    const auto w0 = u32(k87[(x >> 24) & 0xff]) << 24;
    const auto w1 = u32(k65[(x >> 16) & 0xff]) << 16;
    const auto w2 = u32(k43[(x >>  8) & 0xff]) <<  8;
    const auto w3 = u32(k21[x & 0xff]);

    const u32 w = w0|w1|w2|w3;
    return (w << 11) | (w >> (32 - 11));
}

}} // namespaces
