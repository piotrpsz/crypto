#ifndef CRYPTO_H
#define CRYPTO_H

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
};

}} // namespaces
#endif // CRYPTO_H
