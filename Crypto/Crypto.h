#ifndef BEESOFT_CRYPTO_CRYPTO_H
#define BEESOFT_CRYPTO_CRYPTO_H
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

/*------- types:
-------------------------------------------------------------------*/
using u32 = uint32_t;
using u8 = uint8_t;

/*------- namespaces:
-------------------------------------------------------------------*/
namespace beesoft {
namespace crypto {

class Crypto {
public:
    Crypto() = default;
    ~Crypto() = default;

    Crypto(const Crypto&) = delete;
    Crypto& operator=(const Crypto&) = delete;
    Crypto(const Crypto&&) = delete;
    Crypto&& operator=(const Crypto&&) = delete;

    static void random_bytes(void* const, const int) noexcept;
    static void clear_bytes(void* const, const int) noexcept;
    static void print_bytes(void* const, const int) noexcept;
    static int  padding_index(const u8* const, const int) noexcept;
    static bool compare_bytes(const void* const, const void* const, const int) noexcept;
};

}} // namespaces
#endif // BEESOFT_CRYPTO_CRYPTO_H
