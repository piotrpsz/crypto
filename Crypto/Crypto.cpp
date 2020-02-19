#include <sys/random.h>
#include <cstring>
#include <cstdio>
#include "Crypto.h"

/*------- namespaces:
-------------------------------------------------------------------*/
namespace beesoft {
namespace crypto {

void Crypto::random_bytes(void* const data, const int nbytes) noexcept {
    while (getrandom(data, nbytes, 0) != nbytes);
}

void Crypto::clear_bytes(void* const data, const int nbytes) noexcept {
    // czterokrotnie wypełniamy bufor liczbami losowymi
    const u8* rnd_buffer = new u8[4 * nbytes];
    for (int i = 0, rnd_idx = 0; i < 4; i++, rnd_idx += nbytes) {
        memcpy(data, rnd_buffer + rnd_idx, nbytes);
    }
    delete[] rnd_buffer;

    memset(data, 0x55, nbytes);
    memset(data, 0xaa, nbytes);
    memset(data, 0xff, nbytes);
    memset(data, 0x00, nbytes);
}

void Crypto::print_bytes(void* const data, const int nbytes) noexcept {
    const u8* const bytes = reinterpret_cast<const u8*>(data);

    printf("{ ");
    if (nbytes > 0) {
        for (int i = 0; i < (nbytes -1); i++) {
            printf("0x%02x, ", bytes[i]);
        }
        printf("0x%02x", bytes[nbytes-1]);
    }
    printf(" }\n");
}


}} // namespaces
