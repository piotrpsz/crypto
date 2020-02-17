#include <iostream>
#include <string>
#include <memory>
#include <cassert>
#include "Crypto/Blowfish/Blowfish.h"

using namespace std;

bool compare_bytes(void* const, void* const, const int);
void print_bytes(void* const, const int);
void test_block();
void test_ecb();
void test_cbc();

int main() {
    test_cbc();
//    test_block();
//    test_ecb();
    return 0;
}

void test_cbc() {
    u8 iv[] = { 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };
    u8 key[] = { 0xa, 0xb, 0xc, 0xd };
    string plain("Beesoft Software");

    Blowfish bf(key, 4);
    auto [cipher, n] = bf.encrypt_cbc(plain.data(), plain.size());
//    print_bytes(cipher.get(), n);
//    cout << endl;

    auto [retv, k] = bf.decrypt_cbc(cipher.get(), n);
//    print_bytes(retv.get(), k);

    string buff(static_cast<char*>(retv.get()), k);
    cout << "|" << buff << "|" << endl;

}


bool compare_bytes(void* const a, void* const b, const int n) {
    const u8* ptra = reinterpret_cast<const u8*>(a);
    const u8* ptrb = reinterpret_cast<const u8*>(b);

    for (int i = 0; i < n; i++) {
        if (ptra[i] != ptrb[i]) {
            return false;
        }
    }
    return true;
}

void test_block() {
    u32 plain[] = {1, 2};
    u32 expected[] = {0xdf333fd2, 0x30a71bb4};
    u32 buffer[] = {0, 0};

    const auto key = string("TESTKEY");
    Blowfish bf(key.data(), key.size());

    bf.encrypt_block(plain, buffer);
    assert(buffer[0] == expected[0]);
    assert(buffer[1] == expected[1]);
//    printf("0x%x, 0x%x\n", buffer[0], buffer[1]);

    bf.decrypt_block(buffer, buffer);
    assert(buffer[0] == plain[0]);
    assert(buffer[1] == plain[1]);
//    printf("0x%x, 0x%x\n", buffer[0], buffer[1]);

    cout << "test_block: OK" << endl;
}

void test_ecb() {
    struct test {
        u8 key[8];
        u8 plain[8];
        u8 cipher[8];
    } tests[] =
    {
        {
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x45, 0x97, 0xf9, 0x4e, 0x78, 0xdd, 0x98, 0x61}
        },
        {
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
            {0xd5, 0x6f, 0x86, 0x51, 0x8a, 0xcb, 0x5e, 0xb8},
        },
        {
            {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
            {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
            {0x87, 0xdd, 0x66, 0x24, 0x9d, 0x3c, 0x96, 0x8b},
        },
        {
            {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
            {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
            {0x80, 0xc3, 0xf9, 0x61, 0x96, 0xb0, 0x81, 0x22},
        },
        {
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x45, 0x97, 0xf9, 0x4e, 0x78, 0xdd, 0x98, 0x61},
        },
        {
            {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
            {0x88, 0x46, 0x59, 0x24, 0x9a, 0x36, 0x54, 0x57},
        },
        {
            {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10},
            {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
            {0x9c, 0x5a, 0x5c, 0x6b, 0x5a, 0x0a, 0x9e, 0x5d},
        },
    };

    for (int i = 0; i < int(sizeof(tests)/sizeof(test)); i++) {
        Blowfish bf(tests[i].key, 8);

        auto [cipher, n] = bf.encrypt_ecb(tests[i].plain, sizeof(tests[i].plain));
        assert(compare_bytes(cipher.get(), tests[i].cipher, n));
        auto [plain, k] = bf.decrypt_ecb(cipher.get(), 8);
        assert(compare_bytes(plain.get(), tests[i].plain, k));
    }
    cout << "test_ecb: OK" << endl;
}



void print_bytes(void* const data, const int n) {
    const u8* bytes = reinterpret_cast<const u8*>(data);
    for (int i = 0; i < n; i++) {
        printf("0x%02x, ", bytes[i]);
    }
    printf("\n");
}
