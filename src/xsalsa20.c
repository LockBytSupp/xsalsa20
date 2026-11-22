/******************************************************************************
 * MIT License
 *
 * Copyright (c) 2026 LB
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

#include "xsalsa20.h"
#include <string.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static const uint8_t SIGMA[16] = "expand 32-byte k";

#define QR(a, b, c, d)            \
    do {                          \
        b ^= ROTL32(a + d, 7);    \
        c ^= ROTL32(b + a, 9);    \
        d ^= ROTL32(c + b, 13);   \
        a ^= ROTL32(d + c, 18);   \
    } while (0)

/* 20 rounds (10 double rounds) over x[16], in place. */
static void salsa20_rounds(uint32_t x[16]) {
    for (int i = 0; i < 10; i++) {
        /* column round */
        QR(x[0],  x[4],  x[8],  x[12]);
        QR(x[5],  x[9],  x[13], x[1]);
        QR(x[10], x[14], x[2],  x[6]);
        QR(x[15], x[3],  x[7],  x[11]);
        /* row round */
        QR(x[0],  x[1],  x[2],  x[3]);
        QR(x[5],  x[6],  x[7],  x[4]);
        QR(x[10], x[11], x[8],  x[9]);
        QR(x[15], x[12], x[13], x[14]);
    }
}

/* Build the initial state: constants on the diagonal, key, 16-byte "input"
 * (nonce||counter) in words 6..9. */
static void init_state(uint32_t s[16], const uint8_t key[32], const uint8_t in[16]) {
    s[0]  = load32_le(SIGMA + 0);
    s[5]  = load32_le(SIGMA + 4);
    s[10] = load32_le(SIGMA + 8);
    s[15] = load32_le(SIGMA + 12);
    for (int i = 0; i < 4; i++) {
        s[1 + i]  = load32_le(key + 4 * i);
        s[11 + i] = load32_le(key + 16 + 4 * i);
        s[6 + i]  = load32_le(in + 4 * i);
    }
}

/* HSalsa20: derives a 32-byte subkey from a 32-byte key and 16-byte input. */
void hsalsa20(uint8_t out[32], const uint8_t in[16], const uint8_t key[32]) {
    uint32_t x[16];
    init_state(x, key, in);
    salsa20_rounds(x);
    /* output words 0,5,10,15,6,7,8,9 (no feed-forward addition) */
    store32_le(out + 0,  x[0]);
    store32_le(out + 4,  x[5]);
    store32_le(out + 8,  x[10]);
    store32_le(out + 12, x[15]);
    store32_le(out + 16, x[6]);
    store32_le(out + 20, x[7]);
    store32_le(out + 24, x[8]);
    store32_le(out + 28, x[9]);
}

/* Salsa20 block function: 64 bytes of keystream. */
static void salsa20_block(uint8_t out[64], const uint8_t key[32],
                          const uint8_t nonce8[8], uint64_t counter) {
    uint8_t in[16];
    uint32_t s[16], x[16];
    memcpy(in, nonce8, 8);
    store32_le(in + 8,  (uint32_t)counter);
    store32_le(in + 12, (uint32_t)(counter >> 32));
    init_state(s, key, in);
    memcpy(x, s, sizeof x);
    salsa20_rounds(x);
    for (int i = 0; i < 16; i++)
        store32_le(out + 4 * i, x[i] + s[i]);
}

/* XSalsa20 encrypt/decrypt `len` bytes starting at 64-byte block `counter`.
 * `in` and `out` may be the same buffer. Pass in == NULL to get raw keystream. */
void xsalsa20_xor_ic(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t nonce[24], uint64_t counter,
                     const uint8_t key[32]) {
    uint8_t subkey[32], block[64];
    hsalsa20(subkey, nonce, key);            /* first 16 nonce bytes */
    const uint8_t *n2 = nonce + 16;          /* last 8 nonce bytes   */

    while (len > 0) {
        size_t n = len < 64 ? len : 64;
        salsa20_block(block, subkey, n2, counter++);
        if (in) {
            for (size_t i = 0; i < n; i++) out[i] = in[i] ^ block[i];
            in += n;
        } else {
            memcpy(out, block, n);
        }
        out += n;
        len -= n;
    }
    /* best-effort wipe of secrets */
    volatile uint8_t *p = subkey;
    for (size_t i = 0; i < sizeof subkey; i++) p[i] = 0;
    p = block;
    for (size_t i = 0; i < sizeof block; i++) p[i] = 0;
}

void xsalsa20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint8_t nonce[24], const uint8_t key[32]) {
    xsalsa20_xor_ic(out, in, len, nonce, 0, key);
}


