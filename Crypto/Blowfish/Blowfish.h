#ifndef BEESOFT_CRYPTO_BLOWFISH_H
#define BEESOFT_CRYPTO_BLOWFISH_H

#include <cstdint>
#include <memory>
#include <tuple>

using u32 = uint32_t;
using u8 = uint8_t;

static constexpr int BlockSize = 8;
static constexpr int RoundCount = 16;
static constexpr int MinKeySize = 4;
static constexpr int MaxKeySize = 56;

class Blowfish {
    u32 p[RoundCount+2];
    u32 s[4][256];
public:
    Blowfish(const void* const, const int);

    void encrypt_block(const u32* const, u32* const) const noexcept;
    void decrypt_block(const u32* const, u32* const) const noexcept;
    std::tuple<std::shared_ptr<void>, int> encrypt_ecb(const void* const, const int) const noexcept;
    std::tuple<std::shared_ptr<void>, int> decrypt_ecb(const void* const, int) const noexcept;

    std::tuple<std::shared_ptr<void>, int> encrypt_cbc(const void* const, const int, void* = nullptr) const noexcept;
    std::tuple<std::shared_ptr<void>, int> decrypt_cbc(const void* const, int) const noexcept;

private:
    u32 f(u32) const noexcept;
    int padding_index(const u8* const, const int) const noexcept;
};

#endif // BEESOFT_CRYPTO_BLOWFISH_H
