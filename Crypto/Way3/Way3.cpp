/*
 * BSD 2-Clause License
 *
 *	Copyright (c) 2020, Piotr Pszczółkowski
 *	All rights reserved.
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
#include "Way3.h"
#include "Crypto/Crypto.h"

/*------- namespaces:
-------------------------------------------------------------------*/
namespace beesoft {
namespace crypto {
using namespace std;

static constexpr int Nmbr = 11;         // number of rounds
static constexpr int BlockSize = 12;    // in bytes (3xu32)
static constexpr int KeySize = 12;      // in bytes
static constexpr u32 ercon[12] = {0x0b0b, 0x1616, 0x2c2c, 0x5858, 0xb0b0, 0x7171, 0xe2e2, 0xd5d5, 0xbbbb, 0x6767, 0xcece, 0x8d8d};
static constexpr u32 drcon[12] = {0xb1b1, 0x7373, 0xe6e6, 0xdddd, 0xabab, 0x4747, 0x8e8e, 0x0d0d, 0x1a1a, 0x3434, 0x6868, 0xd0d0};

Way3::Way3()
{}

Way3::Way3(const void* const key, const int key_size) {
    if (key_size != KeySize) {
        cerr << "Error (blowfish): invalid key size" << endl;
        return;
    }
    memcpy(k, key, KeySize);
    memcpy(ki, key, KeySize);
    mu(theta(ki));
}

Way3::~Way3() {
    Crypto::clear_bytes(k, 3 * sizeof(u32));
    Crypto::clear_bytes(ki, 3 * sizeof(u32));
}

/**
 * @brief encrypt_block
 * Szyfrowanie bloku (3 x u32) jawnych danych.
 *
 * @param src - adres bufora z jawnymi danymi.
 * @param dst - adres bufora na dane zaszyfrowane.
 */
void Way3::encrypt_block(const u32* const src, u32* const dst) const noexcept {
    u32 a[3];
    memcpy(a, src, BlockSize);

    for (int i = 0; i < Nmbr; i++) {
        a[0] ^= (k[0] ^ (ercon[i] << 16));
        a[1] ^= k[1];
        a[2] ^= (k[2] ^ ercon[i]);
        rho(a);
    }
    a[0] ^= (k[0] ^ (ercon[Nmbr] << 16));
    a[1] ^= k[1];
    a[2] ^= (k[2] ^ ercon[Nmbr]);

    memcpy(dst, theta(a), BlockSize);
}

/**
 * @brief decrypt_block
 * Odszyfrowanie bloku (3 x u32) zaszyfrowanych danych.
 *
 * @param src - adres bufora z zaszyfrowanymi danymi
 * @param dst - adres bufora na dane odszyfrowane.
 */
void Way3::decrypt_block(const u32* const src, u32* const dst) const noexcept {
    u32 a[3];
    mu((u32*)memcpy(a, src, BlockSize));

    for (int i = 0; i < Nmbr; i++) {
        a[0] ^= ki[0] ^ (drcon[i] << 16);
        a[1] ^= ki[1];
        a[2] ^= ki[2] ^ drcon[i];
        rho(a);
    }
    a[0] ^= ki[0] ^ (drcon[Nmbr] << 16);
    a[1] ^= ki[1];
    a[2] ^= ki[2] ^ drcon[Nmbr];

    memcpy(dst, mu(theta(a)), BlockSize);
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
Way3::encrypt_ecb(const void* const data, const int nbytes) const noexcept {

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
        src += 3;
        dst += 3;
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
Way3::decrypt_ecb(const void* const cipher, int nbytes) const noexcept {

    if (cipher == nullptr || nbytes == 0) {
        return make_tuple(shared_ptr<void>(nullptr), 0);
    }

    u8* const plain  = new u8[nbytes];
    bzero(plain, nbytes);

    const u32* src = reinterpret_cast<const u32*>(cipher);
    u32* dst = reinterpret_cast<u32*>(plain);

    for (int i = 0; i < (nbytes/BlockSize); i++) {
        decrypt_block(src, dst);
        src += 3;
        dst += 3;
    }

    if (const int idx = Crypto::padding_index(plain, nbytes); idx != -1) {
        nbytes = idx;
    }
    return make_tuple(shared_ptr<void>(plain, [](void* ptr) {delete[] static_cast<u8*>(ptr);}), nbytes);
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
Way3::encrypt_cbc(const void* const data, const int nbytes, void* iv) const noexcept {

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

    u32 tmp[3];
    for (int i = 0; i < (size/BlockSize); i++) {
        tmp[0] = src[0] ^ dst[0];
        tmp[1] = src[1] ^ dst[1];
        tmp[2] = src[2] ^ dst[2];
        dst += 3;
        encrypt_block(tmp, dst);
        src += 3;
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
Way3::decrypt_cbc(const void* const cipher, int nbytes) const noexcept {

    if (cipher == nullptr || nbytes == 0) {
        return make_tuple(shared_ptr<void>(nullptr), 0);
    }

    nbytes -= BlockSize;
    u8* const plain  = new u8[nbytes];
    bzero(plain, nbytes);

    const u32* src = reinterpret_cast<const u32*>(cipher);
    u32* dst = reinterpret_cast<u32*>(plain);

    for (int i = 0; i < (nbytes/BlockSize); i++) {
        decrypt_block(src + 3, dst);

        dst[0] = dst[0] ^ src[0];
        dst[1] = dst[1] ^ src[1];
        dst[2] = dst[2] ^ src[2];
        dst += 3;
        src += 3;
    }

    if (const int idx = Crypto::padding_index(plain, nbytes); idx != -1) {
        nbytes = idx;
    }
    return make_tuple(shared_ptr<void>(plain, [](void* ptr) {delete[] static_cast<u8*>(ptr);}), nbytes);
}



/********************************************************************
 *                                                                  *
 *                        H E L P E R S                             *
 *                                                                  *
 *******************************************************************/

u32* Way3::gamma(u32* const data) const noexcept {
    const u32 a0 = data[0];
    const u32 a1 = data[1];
    const u32 a2 = data[2];

    data[0] = (~a0) ^ ((~a1) & a2);
    data[1] = (~a1) ^ ((~a2) & a0);
    data[2] = (~a2) ^ ((~a0) & a1);
    return data;
}

u32* Way3::mu(u32* const data) const noexcept {
    u32 a0 = data[0];
    u32 a1 = data[1];
    u32 a2 = data[2];
    u32 b0 = 0;
    u32 b1 = 0;
    u32 b2 = 0;

    for (int i = 0; i < 32; i++) {
        b0 <<= 1; b1 <<= 1; b2 <<= 1;
        b0 |= (a2 & 1);
        b1 |= (a1 & 1);
        b2 |= a0 & 1;
        a0 >>= 1; a1 >>= 1; a2 >>= 1;
    }

    data[0] = b0;
    data[1] = b1;
    data[2] = b2;
    return data;
}

u32* Way3::theta(u32* const data) const noexcept {
    const u32 a0 = data[0];
    const u32 a1 = data[1];
    const u32 a2 = data[2];

    data[0] = a0 ^
            (a0 >> 16) ^ (a1 << 16) ^
            (a1 >> 16) ^ (a2 << 16) ^
            (a1 >> 24) ^ (a2 <<  8) ^
            (a2 >>  8) ^ (a0 << 24) ^
            (a2 >> 16) ^ (a0 << 16) ^
            (a2 >> 24) ^ (a0 <<  8);

    data[1] = a1 ^
            (a1 >> 16) ^ (a2 << 16) ^
            (a2 >> 16) ^ (a0 << 16) ^
            (a2 >> 24) ^ (a0 <<  8) ^
            (a0 >>  8) ^ (a1 << 24) ^
            (a0 >> 16) ^ (a1 << 16) ^
            (a0 >> 24) ^ (a1 << 8);

    data[2] = a2 ^
            (a2 >> 16) ^ (a0 << 16) ^
            (a0 >> 16) ^ (a1 << 16) ^
            (a0 >> 24) ^ (a1 <<  8) ^
            (a1 >>  8) ^ (a2 << 24) ^
            (a1 >> 16) ^ (a2 << 16) ^
            (a1 >> 24) ^ (a2 << 8);

    return data;
}

u32* Way3::pi_1(u32* const data) const noexcept {
    const u32 a0 = data[0];
    const u32 a2 = data[2];

    data[0] = (a0 >> 10) ^ (a0 << 22);
    data[2] = (a2 <<  1) ^ (a2 >> 31);
    return data;
}

u32* Way3::pi_2(u32* const data) const noexcept {
    const u32 a0 = data[0];
    const u32 a2 = data[2];

    data[0] = (a0 <<  1) ^ (a0 >> 31);
    data[2] = (a2 >> 10) ^ (a2 << 22);
    return data;
}

u32* Way3::rho(u32* const data) const noexcept {
    return pi_2(gamma(pi_1(theta(data))));
}

}} // namespaces
