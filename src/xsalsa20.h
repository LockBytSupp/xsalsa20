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

#ifndef XSALSA20_H
#define XSALSA20_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XSALSA20_KEY_BYTES    32
#define XSALSA20_NONCE_BYTES  24

/* HSalsa20: derive a 32-byte subkey from a 32-byte key and 16-byte input. */
void hsalsa20(uint8_t out[32], const uint8_t in[16], const uint8_t key[32]);

/* Encrypt/decrypt `len` bytes (same operation). `in` and `out` may alias.
 * Pass in == NULL to write raw keystream to `out`. */
void xsalsa20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint8_t nonce[24], const uint8_t key[32]);

/* Same, but start at 64-byte block number `counter` (for seeking). */
void xsalsa20_xor_ic(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t nonce[24], uint64_t counter,
                     const uint8_t key[32]);

#ifdef __cplusplus
}
#endif

#endif /* XSALSA20_H */

