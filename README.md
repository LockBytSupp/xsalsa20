# XSalsa20 in pure C

A small, dependency-free implementation of the XSalsa20 stream cipher in portable C99, with a command-line tool and a self-test.

## Files

| File         | Purpose                                          |
|--------------|--------------------------------------------------|
| `xsalsa20.h` | Public API                                       |
| `xsalsa20.c` | Cipher implementation (HSalsa20 + Salsa20 core)  |
| `main.c`     | CLI tool and self-test                           |

## Build

```sh
cc -std=c99 -O2 main.c xsalsa20.c -o xsalsa20
```

Use `gcc` or `clang` if `cc` is not available. With MSVC: `cl /O2 main.c xsalsa20.c`.

## Command-line usage

```sh
./xsalsa20 test                           # run the self-test
./xsalsa20 keygen                         # print a random KEY and NONCE
./xsalsa20 KEY NONCE [infile [outfile]]   # encrypt or decrypt
```

- `KEY` is 64 hex characters (32 bytes).
- `NONCE` is 48 hex characters (24 bytes).
- If `infile` / `outfile` are omitted (or `-`), stdin / stdout are used.
- Encryption and decryption are the same operation.

Example:

```sh
./xsalsa20 keygen
./xsalsa20 <KEY> <NONCE> secret.txt secret.enc
./xsalsa20 <KEY> <NONCE> secret.enc secret.dec
```

`keygen` reads from `/dev/urandom`, so it works on Linux, macOS, BSD and Termux, but not on Windows.

## Library usage

Add `xsalsa20.c` and `xsalsa20.h` to your project and include the header:

```c
#include "xsalsa20.h"

uint8_t key[XSALSA20_KEY_BYTES];      /* 32 bytes, secret, random */
uint8_t nonce[XSALSA20_NONCE_BYTES];  /* 24 bytes, unique per message */

/* Encrypt (decrypt is identical). in and out may be the same buffer. */
xsalsa20_xor(out, in, len, nonce, key);
```

### API

```c
void hsalsa20(uint8_t out[32], const uint8_t in[16], const uint8_t key[32]);

void xsalsa20_xor(uint8_t *out, const uint8_t *in, size_t len,
                  const uint8_t nonce[24], const uint8_t key[32]);

void xsalsa20_xor_ic(uint8_t *out, const uint8_t *in, size_t len,
                     const uint8_t nonce[24], uint64_t counter,
                     const uint8_t key[32]);
```

- `xsalsa20_xor` encrypts or decrypts `len` bytes starting at the beginning of the stream.
- `xsalsa20_xor_ic` starts at 64-byte block number `counter`, which allows seeking and chunked processing.
- Pass `in = NULL` to write raw keystream to `out`.
- `hsalsa20` is the subkey-derivation step, exposed for use in other constructions.

## Testing

```sh
./xsalsa20 test
```

Expected output:

```
HSalsa20 vector:        ok
Round trip / keystream: ok
Counter seek:           ok
```

The HSalsa20 check uses a known vector from the NaCl test suite. The full XSalsa20 keystream has not been checked against published test vectors, so verify it against a reference implementation (for example libsodium) before relying on it.

## Security notes

- **Confidentiality only.** XSalsa20 does not authenticate data. Anyone can flip bits in the ciphertext undetected. Pair it with a MAC such as Poly1305 (as in NaCl's `secretbox`) for authenticated encryption.
- **Never reuse a (key, nonce) pair.** Doing so leaks the XOR of the plaintexts. The 24-byte nonce is large enough to be chosen randomly.
- **Keys on the command line** are visible to other users via `ps` and stay in shell history. The CLI is a convenience tool; for real use, call the library with keys held in memory.
- The cipher uses only add, rotate and XOR, with no secret-dependent branches or table lookups. Secrets are wiped on a best-effort basis only.
- This code has not been independently audited.
