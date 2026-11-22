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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xsalsa20.h"

#define CHUNK 65536u /* must be a multiple of 64 */

/* ---------- hex helpers ---------- */

static int hex_val(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse exactly 2*n hex chars into n bytes. Returns 0 on success. */
static int parse_hex(uint8_t *out, size_t n, const char *s) {
    if (strlen(s) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_val(s[2 * i]), lo = hex_val(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)(hi * 16 + lo);
    }
    return 0;
}

static void print_hex(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

/* ---------- commands ---------- */

static int cmd_test(void) {
    int fail = 0;

    /* HSalsa20 vector from NaCl's core3 test. */
    {
        uint8_t key[32], in[16], out[32], exp[32];
        parse_hex(key, 32, "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389");
        parse_hex(in,  16, "69696ee955b62b73cd62bda875fc73d6");
        parse_hex(exp, 32, "dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4");
        hsalsa20(out, in, key);
        int ok = memcmp(out, exp, 32) == 0;
        printf("HSalsa20 vector:        %s\n", ok ? "ok" : "FAIL");
        fail |= !ok;
    }

    /* Round trip, and XOR-with-keystream consistency. */
    {
        uint8_t key[32], nonce[24], msg[200], enc[200], dec[200], ks[200];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
        for (int i = 0; i < 24; i++) nonce[i] = (uint8_t)(100 + i);
        for (int i = 0; i < 200; i++) msg[i] = (uint8_t)(i * 7);
        xsalsa20_xor(enc, msg, sizeof msg, nonce, key);
        xsalsa20_xor(dec, enc, sizeof enc, nonce, key);
        xsalsa20_xor(ks, NULL, sizeof ks, nonce, key);
        int ok = memcmp(msg, dec, sizeof msg) == 0;
        for (int i = 0; i < 200; i++) ok &= (enc[i] == (msg[i] ^ ks[i]));
        printf("Round trip / keystream: %s\n", ok ? "ok" : "FAIL");
        fail |= !ok;

        /* Seeking: block 2 via counter must match bytes 128.. of the stream. */
        uint8_t part[72];
        xsalsa20_xor_ic(part, NULL, sizeof part, nonce, 2, key);
        ok = memcmp(part, ks + 128, sizeof part) == 0;
        printf("Counter seek:           %s\n", ok ? "ok" : "FAIL");
        fail |= !ok;
    }

    return fail ? 1 : 0;
}

static int cmd_keygen(void) {
    uint8_t buf[XSALSA20_KEY_BYTES + XSALSA20_NONCE_BYTES];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(buf, 1, sizeof buf, f) != sizeof buf) {
        fprintf(stderr, "error: cannot read /dev/urandom\n");
        if (f) fclose(f);
        return 1;
    }
    fclose(f);
    printf("KEY:   ");   print_hex(buf, XSALSA20_KEY_BYTES);   printf("\n");
    printf("NONCE: ");   print_hex(buf + XSALSA20_KEY_BYTES, XSALSA20_NONCE_BYTES); printf("\n");
    return 0;
}

static int cmd_crypt(const char *keyhex, const char *noncehex,
                     const char *inpath, const char *outpath) {
    uint8_t key[XSALSA20_KEY_BYTES], nonce[XSALSA20_NONCE_BYTES];
    if (parse_hex(key, sizeof key, keyhex)) {
        fprintf(stderr, "error: KEY must be 64 hex characters\n");
        return 2;
    }
    if (parse_hex(nonce, sizeof nonce, noncehex)) {
        fprintf(stderr, "error: NONCE must be 48 hex characters\n");
        return 2;
    }

    FILE *in = stdin, *out = stdout;
    if (inpath && strcmp(inpath, "-") != 0 && !(in = fopen(inpath, "rb"))) {
        perror(inpath);
        return 1;
    }
    if (outpath && strcmp(outpath, "-") != 0 && !(out = fopen(outpath, "wb"))) {
        perror(outpath);
        return 1;
    }

    static uint8_t buf[CHUNK];
    uint64_t counter = 0;
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, CHUNK, in)) > 0) {
        xsalsa20_xor_ic(buf, buf, n, nonce, counter, key);
        counter += CHUNK / 64;
        if (fwrite(buf, 1, n, out) != n) {
            perror("write");
            rc = 1;
            break;
        }
    }
    if (ferror(in)) { perror("read"); rc = 1; }

    if (in != stdin) fclose(in);
    if (out != stdout) { if (fclose(out) != 0) rc = 1; }
    else fflush(out);

    memset(key, 0, sizeof key);
    return rc;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "test") == 0)   return cmd_test();
    if (argc == 2 && strcmp(argv[1], "keygen") == 0) return cmd_keygen();
    if (argc >= 3 && argc <= 5)
        return cmd_crypt(argv[1], argv[2],
                         argc > 3 ? argv[3] : NULL,
                         argc > 4 ? argv[4] : NULL);

    fprintf(stderr,
            "usage:\n"
            "  %s test\n"
            "  %s keygen\n"
            "  %s KEY NONCE [infile [outfile]]\n", argv[0], argv[0], argv[0]);
    return 2;
}

