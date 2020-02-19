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
#include <sys/random.h>
#include <cstring>
#include <cstdio>
#include "Crypto.h"

/*------- namespaces:
-------------------------------------------------------------------*/
namespace beesoft {
namespace crypto {

/**
 * @brief random_bytes
 * Losowe wygenerowanie wskazanej liczby bajtów i wpisanie ich
 * do wskazanego bufora.
 *
 * @param data - adres bufora na wygenerowane dane.
 * @param nbytes - rozmiar bufora (w bajtach).
 */
void Crypto::random_bytes(void* const data, const int nbytes) noexcept {
    while (getrandom(data, nbytes, 0) != nbytes);
}

/**
 * @brief clear_bytes
 * Wyczyszczenie wskazanego bufora danych o podanym rozmiarze.
 * Zwyczajowo bufor to tablica zawierająca klucz szyfujący lub IV.
 * Najprawdopodobniej ma zawartość wygenerowaną losowo (@see random_bytes).
 *
 * @param data - adres bufora z danymi.
 * @param nbytes - rozmiar wskazanego bufora (w bajtach).
 */
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

/**
 * @brief print_bytes
 * Wyświetle w konsoli podanej liczby bajtów ze wskazanego bufora.
 *
 * @param data - adres bufora z danymi.
 * @param nbytes - liczba bajtów w buforze (do wyświetlenia).
 */
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

/**
 * @brief padding_index
 * Wyszukiwanie od końca 1-szego wystąpienia bajtu o wartości 128.
 * Szukany bajt może być poprzedzony (od końca) tylko bajtami zerowymi.
 *
 * @param data - adres bufora z danymi.
 * @param nbytes - rozmiar bufora z danymi (w bajtach).
 * @return indeks bajtu w wartości 128, lub -1 jeśli nie znaleziono.
 */
int Crypto::padding_index(const u8* const data, const int nbytes) noexcept {
    for (int i = nbytes - 1; i >= 0; i--) {
        if (data[i] != 0) {
            if (data[i] == 128) {
                return i;
            }
            break;
        }
    }
    return -1;
}

/**
 * @brief compare_bytes
 * Porównanie identyczności bajtów dwóch buforów.
 *
 * @param a - adres pierwszego bufora danych.
 * @param b - adres drugiego bufora danych.
 * @param n - liczba bajtów do sprawdzenia
 * @return true jeśli wszystkie bajty są takie same, false w przeciwnym przypadku.
 */
bool Crypto::compare_bytes(const void* const a, const void* const b, const int n) noexcept {
    return (memcmp(a, b, n) == 0);
}


}} // namespaces
