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

    printf(" k: %x, %x, %x\n", k[0], k[1], k[2]);
    printf("ki: %x, %x, %x\n", ki[0], ki[1], ki[2]);
}

Way3::~Way3() {
    Crypto::clear_bytes(k, 3 * sizeof(u32));
    Crypto::clear_bytes(ki, 3 * sizeof(u32));
}

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
