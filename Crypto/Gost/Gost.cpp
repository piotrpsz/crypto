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

/*------- namespaces:
-------------------------------------------------------------------*/
namespace beesoft {
namespace crypto {
using namespace std;

static constexpr int BlockSize = 8;
static constexpr int KeySize = 32;  // in bytes (= 8xu32)


static void print_bytes(void* const data, const int n) {
    const u8* bytes = reinterpret_cast<const u8*>(data);
    for (int i = 0; i < n; i++) {
        printf("0x%02x, ", bytes[i]);
    }
    printf("\n");
}

Gost::Gost(const void* const user_key, const int key_size) {
    if (key_size != KeySize) {
        cerr << "Error (blowfish): invalid key size" << endl;
        return;
    }

    const u8 k8[16] = {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7};
    const u8 k7[16] = {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10};
    const u8 k6[16] = {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8};
    const u8 k5[16] = {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15};
    const u8 k4[16] = {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9};
    const u8 k3[16] = {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11};
    const u8 k2[16] = {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1};
    const u8 k1[16] = {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7};

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
