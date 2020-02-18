#ifndef BEESOFT_CRYPTO_GOST_H
#define BEESOFT_CRYPTO_GOST_H
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
#include <cstdint>
#include <memory>
#include <tuple>

/*------- namespaces:
-------------------------------------------------------------------*/
namespace beesoft {
namespace crypto {

/*------- types:
-------------------------------------------------------------------*/
using u32 = uint32_t;
using u8 = uint8_t;

class Gost {
     u32 k[8];
     u8  k87[256];
     u8  k65[256];
     u8  k43[256];
     u8  k21[256];

public:
    Gost(const void* const, const int);

    void encrypt_block(const u32* const, u32* const) const noexcept;
    void decrypt_block(const u32* const, u32* const) const noexcept;

private:
    u32 f(const u32) const noexcept;
};

}} // namespaces
#endif // BEESOFT_CRYPTO_GOST_H
