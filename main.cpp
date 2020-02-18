#include <iostream>
#include <string>
#include <memory>
#include <cassert>
#include <vector>
#include "Crypto/Blowfish/Blowfish.h"
#include "Crypto/Gost/Gost.h"

using namespace std;
using namespace beesoft::crypto;

bool compare_bytes(void* const, void* const, const int);
void print_bytes(void* const, const int);

void test_gost();
void gost_test_block();

void test_blowfish();
void blowfish_test_block();
void blowfish_test_ecb();
void blowfish_test_cbc_with_iv();
void blowfish_test_cbc_without_iv();

int main() {
    test_blowfish();
    cout << endl;
    test_gost();
    return 0;
}

void test_gost() {
    gost_test_block();
}

void gost_test_block() {
    u8 key[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
        1, 2
    };
    struct test {
        u32 plain[2];
        u32 cipher[2];
    } tests[] = {
        {
            {0x0, 0x0},
            {0x9b717f65, 0x32b884d0}
        },
        {
            {0x0, 0x1},
            {0xe5112916, 0xd5620daf}
        },
        {
            {0x1, 0x0},
            {0xd9641556, 0xa0cdcf41}
        },
        {
            {0x1, 0x2},
            {0x60591f3d, 0x5797bf40}
        },
        {
            {0x2510, 0x1959},
            {0x3967d936, 0x1f7af77b}
        },
        {
            {0xabcdef, 0x123456},
            {0x5280fbb5, 0xdd68c520}
        },
        {
            {0xaabbccdd, 0xeeff1122},
            {0xc9379503, 0x626e5b08}
        },
        {
            {0xffffffff, 0xffffffff},
            {0xef9c8b90, 0x70dbbfbf}
        }
    };

    Gost gt(key, 32);
    for (int i = 0; i < int(sizeof(tests)/sizeof(test)); i++) {
        u32 result[2] = {};
        {
            gt.encrypt_block(tests[i].plain, result);
            assert(tests[i].cipher[0] == result[0]);
            assert(tests[i].cipher[1] == result[1]);
        }
        {
            gt.decrypt_block(result, result);
            assert(tests[i].plain[0] == result[0]);
            assert(tests[i].plain[1] == result[1]);
        }
    }

    cout << "gost_test_block: OK" << endl;
}


/********************************************************************
 *                                                                  *
 *                     B L O W F I S H                              *
 *                                                                  *
 ********************************************************************/

void test_blowfish() {
    blowfish_test_block();
    blowfish_test_ecb();
    blowfish_test_cbc_with_iv();
    blowfish_test_cbc_without_iv();
}

/**
 * @brief blowfish_test_block
 */
void blowfish_test_block() {
    u32 plain[] = {1, 2};
    u32 expected[] = {0xdf333fd2, 0x30a71bb4};
    u32 buffer[] = {0, 0};

    const auto key = string("TESTKEY");
    Blowfish bf(key.data(), key.size());

    bf.encrypt_block(plain, buffer);
    assert(buffer[0] == expected[0]);
    assert(buffer[1] == expected[1]);

    bf.decrypt_block(buffer, buffer);
    assert(buffer[0] == plain[0]);
    assert(buffer[1] == plain[1]);

    cout << "tblowfish_test_block: OK" << endl;
}

/**
 * @brief blowfish_test_ecb
 */
void blowfish_test_ecb() {
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
    cout << "blowfish_test_ecb: OK" << endl;
}

/**
 * @brief blowfish_test_cbc_without_iv
 */
void blowfish_test_cbc_without_iv() {
    vector<u8> key[] =
    {
        { 0x00, 0x01, 0x02, 0x03 },
        { 0x00, 0x01, 0x02, 0x03, 0x04 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8, 0x09 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8, 0x09, 0x0a },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8, 0x09, 0x0a, 0x0b },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8, 0x09, 0x0a, 0x0b, 0x0c },
        { 0xff, 0xfe, 0xfd, 0x0c },
        { 0xff, 0xfe, 0xfd, 0xfc, 0xfb },
        { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa },
        { 0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9 },
        { 0xdf, 0xde, 0xdd, 0xdc, 0xdb, 0xda, 0xd9, 0xd8 },
        { 0xcf, 0xce, 0xcd, 0xcc, 0xcb, 0xca, 0xc9, 0xc8, 0xc7 },
        { 0xbf, 0xbe, 0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8, 0xb7, 0xb8 },
        { 0xaf, 0xae, 0xad, 0xac, 0xab, 0xaa, 0xa9, 0xa8, 0xa7, 0xa8, 0xa6 },
        { 0x9f, 0x9e, 0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98, 0x97, 0x98, 0x96, 0x95 },
        { 0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 0x87, 0x88, 0x86, 0x85, 0x84 },
    };
    vector<string> plain = {
        string("Beesoft Software, Piotr Pszczółkowski"),
        string("Beesoft Software, Piotr Pszczółkowsk"),
        string("Beesoft Software, Piotr Pszczółkows"),
        string("Beesoft Software, Piotr Pszczółkow"),
        string("Beesoft Software, Piotr Pszczółko"),
        string("Beesoft Software, Piotr Pszczółk"),
        string("Beesoft Software, Piotr Pszczół"),
        string("Beesoft Software, Piotr Pszczó"),
        string("Beesoft Software, Piotr Pszcz"),
        string("Beesoft Software, Piotr Pszc"),
        string("Beesoft Software, Piotr Psz"),
        string("Beesoft Software, Piotr Ps"),
        string("Beesoft Software, Piotr P"),
        string("Beesoft Software, Piotr "),
        string("Beesoft Software, Piotr"),
        string("Beesoft Software, Piot"),
        string("Beesoft Software, Pio"),
        string("Beesoft Software, Pi"),
        string("Beesoft Software, P"),
        string("Beesoft Software, "),
        string("Beesoft Software,"),
        string("Beesoft Software"),
        string("Beesoft"),
        string("")
    };

    for (int i = 0; i < 20; i++) {
        Blowfish bf(key[i].data(), key[i].size());
        for (int j = 0; j < 24; j++) {
            auto [cipher, n] = bf.encrypt_cbc(plain[j].data(), plain[j].size());
            auto [decipher, k] = bf.decrypt_cbc(cipher.get(), n);
            assert(string(static_cast<char*>(decipher.get()), k) == plain[j]);
        }
    }
    cout << "blowfish_test_cbc_without_iv: OK" << endl;
}

/**
 * @brief blowfish_test_cbc_with_iv
 */
void blowfish_test_cbc_with_iv() {
    vector<u8> key[] = {
        { 0x00, 0x01, 0x02, 0x03 },
        { 0x00, 0x01, 0x02, 0x03, 0x04 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8, 0x09 },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8, 0x09, 0x0a },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8, 0x09, 0x0a, 0x0b },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8, 0x09, 0x0a, 0x0b, 0x0c },
        { 0xff, 0xfe, 0xfd, 0x0c },
        { 0xff, 0xfe, 0xfd, 0xfc, 0xfb },
        { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa },
        { 0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9 },
        { 0xdf, 0xde, 0xdd, 0xdc, 0xdb, 0xda, 0xd9, 0xd8 },
        { 0xcf, 0xce, 0xcd, 0xcc, 0xcb, 0xca, 0xc9, 0xc8, 0xc7 },
        { 0xbf, 0xbe, 0xbd, 0xbc, 0xbb, 0xba, 0xb9, 0xb8, 0xb7, 0xb8 },
        { 0xaf, 0xae, 0xad, 0xac, 0xab, 0xaa, 0xa9, 0xa8, 0xa7, 0xa8, 0xa6 },
        { 0x9f, 0x9e, 0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98, 0x97, 0x98, 0x96, 0x95 },
        { 0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 0x87, 0x88, 0x86, 0x85, 0x84 },
    };
    vector<string> plain = {
        string("Beesoft Software, Piotr Pszczółkowski"),
        string("Beesoft Software, Piotr Pszczółkowsk"),
        string("Beesoft Software, Piotr Pszczółkows"),
        string("Beesoft Software, Piotr Pszczółkow"),
        string("Beesoft Software, Piotr Pszczółko"),
        string("Beesoft Software, Piotr Pszczółk"),
        string("Beesoft Software, Piotr Pszczół"),
        string("Beesoft Software, Piotr Pszczó"),
        string("Beesoft Software, Piotr Pszcz"),
        string("Beesoft Software, Piotr Pszc"),
        string("Beesoft Software, Piotr Psz"),
        string("Beesoft Software, Piotr Ps"),
        string("Beesoft Software, Piotr P"),
        string("Beesoft Software, Piotr "),
        string("Beesoft Software, Piotr"),
        string("Beesoft Software, Piot"),
        string("Beesoft Software, Pio"),
        string("Beesoft Software, Pi"),
        string("Beesoft Software, P"),
        string("Beesoft Software, "),
        string("Beesoft Software,"),
        string("Beesoft Software"),
        string("Beesoft"),
        string("")
    };
    vector<u8> iv[] = {
        { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 },
        { 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 },
        { 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x1a },
        { 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x2b },
        { 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x3c },
        { 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x4d },
        { 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x5e },
        { 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xa0 },
        { 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xb0 },
        { 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xc0 },
        { 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xd0 },
        { 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0xe0 },
    };

    for (int i = 0; i < 20; i++) {
        Blowfish bf(key[i].data(), key[i].size());
        for (int j = 0; j < 24; j++) {
            for (int m = 0; m < 12; m++) {
                auto [cipher, n] = bf.encrypt_cbc(plain[j].data(), plain[j].size(), iv[m].data());
                auto [decipher, k] = bf.decrypt_cbc(cipher.get(), n);
                assert(string(static_cast<char*>(decipher.get()), k) == plain[j]);
            }
        }
    }
    cout << "blowfish_test_cbc_with_iv: OK" << endl;
}

/********************************************************************
 *                                                                  *
 *                         H E L P E R S                            *
 *                                                                  *
 ********************************************************************/

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

void print_bytes(void* const data, const int n) {
    const u8* bytes = reinterpret_cast<const u8*>(data);
    for (int i = 0; i < n; i++) {
        printf("0x%02x, ", bytes[i]);
    }
    printf("\n");
}
