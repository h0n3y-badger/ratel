"""Crypto primitive variants (real algorithms; tables generated here so they
are exact)."""
import math
from common import T, c_bytes

CR = "crypto"


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _sbox():
    inv = [0] * 256
    for i in range(1, 256):
        for j in range(1, 256):
            if _gmul(i, j) == 1:
                inv[i] = j
                break
    s = []
    for i in range(256):
        x = inv[i]
        y = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            y ^= x
        s.append(y ^ 0x63)
    return s


SBOX = _sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
TE0 = [(_gmul(s, 2) << 24) | (s << 16) | (s << 8) | _gmul(s, 3) for s in SBOX]
MD5_T = [int(abs(math.sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF for i in range(64)]
SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


def u32s(v):
    return ", ".join("0x%08xu" % x for x in v)


_INPUT = r'''
    unsigned char key[32], blk[64];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)(argc * 31 + i * 7);
    for (int i = 0; i < 64; i++) blk[i] = (unsigned char)(argv[0][i % 4] ^ i);'''

_SINKV = "static volatile unsigned char @F_out[64];"

# ---------------------------------------------------------------- AES
_AES_TABLE = _SINKV + r'''
static const unsigned char @F_sbox[256] = {@SBOX@};
static const unsigned char @F_rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
static unsigned char @F_xt(unsigned char x) { return (unsigned char)((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }
static void @F_expand(const unsigned char *k, unsigned char *rk) {
    memcpy(rk, k, 16);
    for (int i = 4; i < 44; i++) {
        unsigned char t[4]; memcpy(t, rk + (i - 1) * 4, 4);
        if (i % 4 == 0) {
            unsigned char u = t[0]; t[0] = @F_sbox[t[1]] ^ @F_rcon[i / 4]; t[1] = @F_sbox[t[2]]; t[2] = @F_sbox[t[3]]; t[3] = @F_sbox[u];
        }
        for (int j = 0; j < 4; j++) rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j];
    }
}
static void @F_enc(unsigned char *s, const unsigned char *rk) {
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
    for (int r = 1; r <= 10; r++) {
        unsigned char t[16];
        for (int i = 0; i < 16; i++) t[i] = @F_sbox[s[(i + 4 * (i % 4)) % 16]];   /* SubBytes+ShiftRows */
        if (r != 10) for (int c = 0; c < 4; c++) {
            unsigned char *col = t + 4 * c, a = col[0] ^ col[1] ^ col[2] ^ col[3], c0 = col[0];
            col[0] ^= a ^ @F_xt(col[0] ^ col[1]); col[1] ^= a ^ @F_xt(col[1] ^ col[2]);
            col[2] ^= a ^ @F_xt(col[2] ^ col[3]); col[3] ^= a ^ @F_xt(col[3] ^ c0);
        }
        for (int i = 0; i < 16; i++) s[i] = t[i] ^ rk[r * 16 + i];
    }
}
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    unsigned char rk[176];
    @F_expand(key, rk);
    for (int b = 0; b < 4; b++) @F_enc(blk + 16 * b, rk);
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i];
    return blk[0];
}'''
T("crypto.any.aes_table.v1", "crypto.aes", CR, "any", _AES_TABLE.replace("@SBOX@", c_bytes(bytes(SBOX))), inc=("string.h",))

T("crypto.any.aes_ni.v2", "crypto.aes", CR, "any", _SINKV + r'''
static __m128i @F_kx(__m128i k, __m128i g) {
    g = _mm_shuffle_epi32(g, 0xff);
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
    return _mm_xor_si128(k, g);
}
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    __m128i rk[11];
    rk[0] = _mm_loadu_si128((const __m128i *)key);
    rk[1] = @F_kx(rk[0], _mm_aeskeygenassist_si128(rk[0], 0x01));
    rk[2] = @F_kx(rk[1], _mm_aeskeygenassist_si128(rk[1], 0x02));
    rk[3] = @F_kx(rk[2], _mm_aeskeygenassist_si128(rk[2], 0x04));
    rk[4] = @F_kx(rk[3], _mm_aeskeygenassist_si128(rk[3], 0x08));
    rk[5] = @F_kx(rk[4], _mm_aeskeygenassist_si128(rk[4], 0x10));
    rk[6] = @F_kx(rk[5], _mm_aeskeygenassist_si128(rk[5], 0x20));
    rk[7] = @F_kx(rk[6], _mm_aeskeygenassist_si128(rk[6], 0x40));
    rk[8] = @F_kx(rk[7], _mm_aeskeygenassist_si128(rk[7], 0x80));
    rk[9] = @F_kx(rk[8], _mm_aeskeygenassist_si128(rk[8], 0x1b));
    rk[10] = @F_kx(rk[9], _mm_aeskeygenassist_si128(rk[9], 0x36));
    for (int b = 0; b < 4; b++) {
        __m128i s = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(blk + 16 * b)), rk[0]);
        for (int r = 1; r < 10; r++) s = _mm_aesenc_si128(s, rk[r]);
        s = _mm_aesenclast_si128(s, rk[10]);
        _mm_storeu_si128((__m128i *)(blk + 16 * b), s);
    }
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i];
    return blk[3];
}''', inc=("wmmintrin.h", "emmintrin.h"), cflags=("-maes", "-msse2"))

T("crypto.any.aes_runtime_sbox.v3", "crypto.aes", CR, "any", _SINKV + r'''
static unsigned char @F_sb[256];
static unsigned char @F_rotl8(unsigned char x, int s) { return (unsigned char)((x << s) | (x >> (8 - s))); }
static void @F_init(void) {
    unsigned char p = 1, q = 1;
    do {   /* walk the multiplicative group with generator 3 */
        p = p ^ (unsigned char)(p << 1) ^ (p & 0x80 ? 0x1B : 0);
        q ^= q << 1; q ^= q << 2; q ^= q << 4; if (q & 0x80) q ^= 0x09;
        unsigned char x = q ^ @F_rotl8(q, 1) ^ @F_rotl8(q, 2) ^ @F_rotl8(q, 3) ^ @F_rotl8(q, 4);
        @F_sb[p] = x ^ 0x63;
    } while (p != 1);
    @F_sb[0] = 0x63;
}
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    @F_init();
    unsigned char rk[176]; memcpy(rk, key, 16);
    unsigned char rc = 1;
    for (int i = 16; i < 176; i += 4) {
        unsigned char t[4] = {rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1]};
        if (i % 16 == 0) { unsigned char u = t[0]; t[0] = @F_sb[t[1]] ^ rc; t[1] = @F_sb[t[2]]; t[2] = @F_sb[t[3]]; t[3] = @F_sb[u]; rc = (unsigned char)((rc << 1) ^ ((rc >> 7) * 0x1b)); }
        for (int j = 0; j < 4; j++) rk[i + j] = rk[i - 16 + j] ^ t[j];
    }
    for (int r = 0; r < 10; r++)
        for (int i = 0; i < 16; i++) blk[i] = @F_sb[blk[i] ^ rk[r * 16 + i]];
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i];
    return blk[1];
}''', inc=("string.h",))

T("crypto.win.bcrypt_aes.v4", "crypto.aes", CR, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    BCRYPT_ALG_HANDLE alg; BCRYPT_KEY_HANDLE key;
    UCHAR secret[32], iv[16] = {0}, buf[64], out[80]; ULONG n = 0;
    for (int i = 0; i < 32; i++) secret[i] = (UCHAR)(i * argc);
    memset(buf, 0x41, sizeof buf);
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0)) return 0;
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCryptGenerateSymmetricKey(alg, &key, NULL, 0, secret, sizeof secret, 0);
    BCryptEncrypt(key, buf, sizeof buf, NULL, iv, sizeof iv, out, sizeof out, &n, BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(key); BCryptCloseAlgorithmProvider(alg, 0);
    return (int)n;
}''', inc=("windows.h", "bcrypt.h", "string.h"), libs=("bcrypt",))

T("crypto.win.cryptoapi_aes.v5", "crypto.aes", CR, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    HCRYPTPROV prov; HCRYPTHASH hash; HCRYPTKEY key;
    BYTE data[64]; DWORD len = 48;
    memset(data, 'A', sizeof data);
    if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return 0;
    CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash);
    CryptHashData(hash, (const BYTE *)"passphrase", 10, 0);
    CryptDeriveKey(prov, CALG_AES_256, hash, 0, &key);
    CryptEncrypt(key, 0, TRUE, 0, data, &len, sizeof data);
    CryptDestroyKey(key); CryptDestroyHash(hash); CryptReleaseContext(prov, 0);
    return (int)len;
}''', inc=("windows.h", "wincrypt.h", "string.h"), libs=("advapi32",))

T("crypto.any.aes_ttable.v6", "crypto.aes", CR, "any", _SINKV + r'''
static const unsigned int @F_Te0[256] = {%s};
#define @F_ROR8(x) (((x) >> 8) | ((x) << 24))
__attribute__((noinline)) int @F(int argc, char **argv) {''' % u32s(TE0) + _INPUT + r'''
    unsigned int s[4], t[4], rk[4];
    memcpy(s, blk, 16); memcpy(rk, key, 16);
    for (int r = 0; r < 9; r++) {
        for (int c = 0; c < 4; c++)
            t[c] = @F_Te0[s[c] >> 24] ^ @F_ROR8(@F_Te0[(s[(c + 1) & 3] >> 16) & 0xff]) ^
                   @F_ROR8(@F_ROR8(@F_Te0[(s[(c + 2) & 3] >> 8) & 0xff])) ^ @F_ROR8(@F_ROR8(@F_ROR8(@F_Te0[s[(c + 3) & 3] & 0xff]))) ^ rk[c];
        memcpy(s, t, 16);
        rk[0] ^= rk[3] * 0x01000193u; rk[1] ^= rk[0]; rk[2] ^= rk[1]; rk[3] ^= rk[2];
    }
    memcpy(blk, s, 16);
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i];
    return blk[2];
}''', inc=("string.h",))

# ---------------------------------------------------------------- stream ciphers
T("crypto.any.rc4_classic.v1", "crypto.stream", CR, "any", _SINKV + r'''
static void @F_rc4(const unsigned char *k, int kl, unsigned char *d, int n) {
    unsigned char S[256]; int i, j = 0;
    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;
    for (i = 0; i < 256; i++) { j = (j + S[i] + k[i % kl]) & 0xff; unsigned char t = S[i]; S[i] = S[j]; S[j] = t; }
    i = j = 0;
    for (int x = 0; x < n; x++) {
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
        d[x] ^= S[(S[i] + S[j]) & 0xff];
    }
}
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    @F_rc4(key, 16, blk, 64);
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i];
    return blk[0];
}''')

T("crypto.any.rc4_struct.v2", "crypto.stream", CR, "any", _SINKV + r'''
typedef struct { unsigned char s[256]; unsigned char x, y; } @F_ctx;
#define @F_SWAP(a, b) do { unsigned char _t = (a); (a) = (b); (b) = _t; } while (0)
static void @F_setup(@F_ctx *c, const unsigned char *key, size_t len) {
    unsigned char *s = c->s, j = 0;
    for (int i = 0; i < 256; i++) s[i] = (unsigned char)i;
    for (int i = 0; i < 256; i++) { j += s[i] + key[i % len]; @F_SWAP(s[i], s[j]); }
    c->x = c->y = 0;
}
static void @F_crypt(@F_ctx *c, unsigned char *p, size_t n) {
    unsigned char *s = c->s, x = c->x, y = c->y;
    while (n--) { x++; y += s[x]; @F_SWAP(s[x], s[y]); *p++ ^= s[(unsigned char)(s[x] + s[y])]; }
    c->x = x; c->y = y;
}
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    @F_ctx c; @F_setup(&c, key, 8 + (argc & 7));
    @F_crypt(&c, blk, sizeof blk);
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i];
    return blk[5];
}''', inc=("stddef.h",))

_CHACHA_BODY = r'''
#define @F_R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define @F_QR(a, b, c, d) (a += b, d ^= a, d = @F_R(d, 16), c += d, b ^= c, b = @F_R(b, 12), a += b, d ^= a, d = @F_R(d, 8), c += d, b ^= c, b = @F_R(b, 7))
static void @F_block(unsigned int out[16], const unsigned int in[16]) {
    unsigned int x[16];
    for (int i = 0; i < 16; i++) x[i] = in[i];
    for (int i = 0; i < 10; i++) {
        @F_QR(x[0], x[4], x[8], x[12]); @F_QR(x[1], x[5], x[9], x[13]);
        @F_QR(x[2], x[6], x[10], x[14]); @F_QR(x[3], x[7], x[11], x[15]);
        @F_QR(x[0], x[5], x[10], x[15]); @F_QR(x[1], x[6], x[11], x[12]);
        @F_QR(x[2], x[7], x[8], x[13]); @F_QR(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}'''
T("crypto.any.chacha20_words.v3", "crypto.stream", CR, "any", _SINKV + _CHACHA_BODY + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    unsigned int st[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}, ks[16];
    memcpy(st + 4, key, 32); st[12] = 1; st[13] = st[14] = st[15] = (unsigned)argc;
    @F_block(ks, st);
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i] ^ ((unsigned char *)ks)[i];
    return (int)ks[0];
}''', inc=("string.h",))

T("crypto.any.chacha20_sigma.v4", "crypto.stream", CR, "any", _SINKV + _CHACHA_BODY + r'''
static const char @F_sigma[16] = "expand 32-byte k";
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    unsigned int st[16], ks[16];
    memcpy(st, @F_sigma, 16); memcpy(st + 4, key, 32);
    st[12] = 0; st[13] = 0x4a000000u; st[14] = 0; st[15] = (unsigned)argc;
    for (int b = 0; b < 2; b++) { @F_block(ks, st); st[12]++; for (int i = 0; i < 32; i++) @F_out[b * 32 + i] = blk[b * 32 + i] ^ ((unsigned char *)ks)[i]; }
    return 0;
}''', inc=("string.h",))

T("crypto.any.salsa20.v5", "crypto.stream", CR, "any", _SINKV + r'''
#define @F_R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
static void @F_core(unsigned int out[16], const unsigned int in[16]) {
    unsigned int x[16];
    for (int i = 0; i < 16; i++) x[i] = in[i];
    for (int i = 0; i < 20; i += 2) {
        x[4] ^= @F_R(x[0] + x[12], 7);  x[8] ^= @F_R(x[4] + x[0], 9);  x[12] ^= @F_R(x[8] + x[4], 13);  x[0] ^= @F_R(x[12] + x[8], 18);
        x[9] ^= @F_R(x[5] + x[1], 7);  x[13] ^= @F_R(x[9] + x[5], 9);  x[1] ^= @F_R(x[13] + x[9], 13);  x[5] ^= @F_R(x[1] + x[13], 18);
        x[14] ^= @F_R(x[10] + x[6], 7); x[2] ^= @F_R(x[14] + x[10], 9); x[6] ^= @F_R(x[2] + x[14], 13); x[10] ^= @F_R(x[6] + x[2], 18);
        x[3] ^= @F_R(x[15] + x[11], 7); x[7] ^= @F_R(x[3] + x[15], 9); x[11] ^= @F_R(x[7] + x[3], 13); x[15] ^= @F_R(x[11] + x[7], 18);
        x[1] ^= @F_R(x[0] + x[3], 7);  x[2] ^= @F_R(x[1] + x[0], 9);  x[3] ^= @F_R(x[2] + x[1], 13);  x[0] ^= @F_R(x[3] + x[2], 18);
        x[6] ^= @F_R(x[5] + x[4], 7);  x[7] ^= @F_R(x[6] + x[5], 9);  x[4] ^= @F_R(x[7] + x[6], 13);  x[5] ^= @F_R(x[4] + x[7], 18);
        x[11] ^= @F_R(x[10] + x[9], 7); x[8] ^= @F_R(x[11] + x[10], 9); x[9] ^= @F_R(x[8] + x[11], 13); x[10] ^= @F_R(x[9] + x[8], 18);
        x[12] ^= @F_R(x[15] + x[14], 7); x[13] ^= @F_R(x[12] + x[15], 9); x[14] ^= @F_R(x[13] + x[12], 13); x[15] ^= @F_R(x[14] + x[13], 18);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    unsigned int st[16], ks[16]; const unsigned int *k = (const unsigned int *)key;
    st[0] = 0x61707865; st[5] = 0x3320646e; st[10] = 0x79622d32; st[15] = 0x6b206574;
    st[1] = k[0]; st[2] = k[1]; st[3] = k[2]; st[4] = k[3]; st[11] = k[4]; st[12] = k[5]; st[13] = k[6]; st[14] = k[7];
    st[6] = st[7] = (unsigned)argc; st[8] = st[9] = 0;
    @F_core(ks, st);
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i] ^ ((unsigned char *)ks)[i];
    return 0;
}''')

# ---------------------------------------------------------------- hashes
T("crypto.any.sha256.v1", "crypto.hash", CR, "any", _SINKV + r'''
static const unsigned int @F_K[64] = {%s};
#define @F_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void @F_compress(unsigned int h[8], const unsigned char *p) {
    unsigned int w[64], a, b, c, d, e, f, g, hh;
    for (int i = 0; i < 16; i++) w[i] = (unsigned)p[4*i] << 24 | (unsigned)p[4*i+1] << 16 | (unsigned)p[4*i+2] << 8 | p[4*i+3];
    for (int i = 16; i < 64; i++) {
        unsigned s0 = @F_ROR(w[i-15], 7) ^ @F_ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        unsigned s1 = @F_ROR(w[i-2], 17) ^ @F_ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (int i = 0; i < 64; i++) {
        unsigned t1 = hh + (@F_ROR(e, 6) ^ @F_ROR(e, 11) ^ @F_ROR(e, 25)) + ((e & f) ^ (~e & g)) + @F_K[i] + w[i];
        unsigned t2 = (@F_ROR(a, 2) ^ @F_ROR(a, 13) ^ @F_ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}
__attribute__((noinline)) int @F(int argc, char **argv) {''' % u32s(SHA256_K) + _INPUT + r'''
    unsigned int h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    @F_compress(h, blk);
    for (int i = 0; i < 8; i++) @F_out[i] = (unsigned char)h[i];
    return (int)h[0];
}''')

T("crypto.any.md5.v2", "crypto.hash", CR, "any", _SINKV + r'''
static const unsigned int @F_T[64] = {%s};
static const unsigned char @F_S[64] = {7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
__attribute__((noinline)) int @F(int argc, char **argv) {''' % u32s(MD5_T) + _INPUT + r'''
    unsigned int a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476, M[16];
    memcpy(M, blk, 64);
    unsigned A = a0, B = b0, C = c0, D = d0;
    for (int i = 0; i < 64; i++) {
        unsigned F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        F = F + A + @F_T[i] + M[g];
        A = D; D = C; C = B; B = B + ((F << @F_S[i]) | (F >> (32 - @F_S[i])));
    }
    a0 += A; b0 += B; c0 += C; d0 += D;
    @F_out[0] = (unsigned char)a0; @F_out[1] = (unsigned char)d0;
    return (int)(a0 ^ b0 ^ c0 ^ d0);
}''', inc=("string.h",))

T("crypto.any.sha1.v3", "crypto.hash", CR, "any", _SINKV + r'''
#define @F_ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    unsigned int h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0, w[80];
    for (int i = 0; i < 16; i++) w[i] = (unsigned)blk[4*i] << 24 | (unsigned)blk[4*i+1] << 16 | (unsigned)blk[4*i+2] << 8 | blk[4*i+3];
    for (int i = 16; i < 80; i++) w[i] = @F_ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    unsigned a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; i++) {
        unsigned f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        unsigned t = @F_ROL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = @F_ROL(b, 30); b = a; a = t;
    }
    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    @F_out[0] = (unsigned char)h0;
    return (int)(h0 ^ h4);
}''')

T("crypto.win.bcrypt_sha256.v4", "crypto.hash", CR, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    BCRYPT_ALG_HANDLE alg; BCRYPT_HASH_HANDLE h; UCHAR digest[32];
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return 0;
    BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0);
    BCryptHashData(h, (PUCHAR)argv[0], (ULONG)strlen(argv[0]), 0);
    BCryptFinishHash(h, digest, sizeof digest, 0);
    BCryptDestroyHash(h); BCryptCloseAlgorithmProvider(alg, 0);
    return digest[0];
}''', inc=("windows.h", "bcrypt.h", "string.h"), libs=("bcrypt",))

T("crypto.win.cryptoapi_md5.v5", "crypto.hash", CR, "windows", r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    HCRYPTPROV p; HCRYPTHASH h; BYTE d[20]; DWORD n = sizeof d;
    if (!CryptAcquireContextW(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return 0;
    CryptCreateHash(p, (argc & 1) ? CALG_MD5 : CALG_SHA1, 0, 0, &h);
    CryptHashData(h, (const BYTE *)argv[0], (DWORD)lstrlenA(argv[0]), 0);
    CryptGetHashParam(h, HP_HASHVAL, d, &n, 0);
    CryptDestroyHash(h); CryptReleaseContext(p, 0);
    return d[0];
}''', inc=("windows.h", "wincrypt.h"), libs=("advapi32",))

# ---------------------------------------------------------------- block ciphers / bignum
T("crypto.any.tea.v1", "crypto.block", CR, "any", _SINKV + r'''
static void @F_tea(unsigned int v[2], const unsigned int k[4]) {
    unsigned int v0 = v[0], v1 = v[1], sum = 0, delta = 0x9E3779B9;
    for (int i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0; v[1] = v1;
}
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    unsigned int *w = (unsigned int *)blk;
    for (int i = 0; i < 16; i += 2) @F_tea(w + i, (const unsigned int *)key);
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i];
    return (int)w[0];
}''')

T("crypto.any.xtea.v2", "crypto.block", CR, "any", _SINKV + r'''
static void @F_xtea_dec(unsigned rounds, unsigned int v[2], const unsigned int key[4]) {
    unsigned int v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * rounds;
    for (unsigned i = 0; i < rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    for (int i = 0; i < 64; i += 8) @F_xtea_dec(32, (unsigned int *)(blk + i), (const unsigned int *)key);
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i];
    return blk[0];
}''')

T("crypto.any.xxtea.v3", "crypto.block", CR, "any", _SINKV + r'''
#define @F_MX (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))
static void @F_btea(unsigned int *v, int n, const unsigned int key[4]) {
    unsigned int y, z, sum = 0, e; unsigned p, rounds = 6 + 52 / n;
    z = v[n - 1];
    do {
        sum += 0x9e3779b9; e = (sum >> 2) & 3;
        for (p = 0; p < (unsigned)n - 1; p++) { y = v[p + 1]; z = v[p] += @F_MX; }
        y = v[0]; z = v[n - 1] += @F_MX;
    } while (--rounds);
}
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    @F_btea((unsigned int *)blk, 16, (const unsigned int *)key);
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i];
    return blk[9];
}''')

T("crypto.any.rc5.v4", "crypto.block", CR, "any", _SINKV + r'''
#define @F_ROTL(x, y) (((x) << ((y) & 31)) | ((x) >> (32 - ((y) & 31))))
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    unsigned int S[26], L[4], A = 0, B = 0;
    memcpy(L, key, 16);
    S[0] = 0xB7E15163u;
    for (int i = 1; i < 26; i++) S[i] = S[i - 1] + 0x9E3779B9u;
    for (int k = 0, i = 0, j = 0; k < 78; k++, i = (i + 1) % 26, j = (j + 1) % 4) {
        A = S[i] = @F_ROTL(S[i] + A + B, 3);
        B = L[j] = @F_ROTL(L[j] + A + B, A + B);
    }
    unsigned int a = ((unsigned int *)blk)[0] + S[0], b = ((unsigned int *)blk)[1] + S[1];
    for (int i = 1; i <= 12; i++) { a = @F_ROTL(a ^ b, b) + S[2 * i]; b = @F_ROTL(b ^ a, a) + S[2 * i + 1]; }
    @F_out[0] = (unsigned char)a; @F_out[1] = (unsigned char)b;
    return (int)(a ^ b);
}''', inc=("string.h",))

T("crypto.any.speck.v5", "crypto.block", CR, "any", _SINKV + r'''
#define @F_ROR(x, r) ((x >> r) | (x << (64 - r)))
#define @F_ROL(x, r) ((x << r) | (x >> (64 - r)))
#define @F_RND(x, y, k) (x = @F_ROR(x, 8), x += y, x ^= k, y = @F_ROL(y, 3), y ^= x)
__attribute__((noinline)) int @F(int argc, char **argv) {''' + _INPUT + r'''
    unsigned long long pt[2], k[2], ct[2];
    memcpy(pt, blk, 16); memcpy(k, key, 16);
    unsigned long long y = pt[0], x = pt[1], b = k[0], a = k[1];
    @F_RND(x, y, b);
    for (unsigned long long i = 0; i < 31; i++) { @F_RND(a, b, i); @F_RND(x, y, b); }
    ct[0] = y; ct[1] = x;
    memcpy(blk, ct, 16);
    for (int i = 0; i < 64; i++) @F_out[i] = blk[i];
    return blk[0];
}''', inc=("string.h",))

T("crypto.any.rsa_modexp.v6", "crypto.block", CR, "any", r'''
static unsigned long long @F_mulmod(unsigned long long a, unsigned long long b, unsigned long long m) {
    unsigned long long r = 0; a %= m;
    while (b) { if (b & 1) { r += a; if (r >= m) r -= m; } a <<= 1; if (a >= m) a -= m; b >>= 1; }
    return r;
}
static unsigned long long @F_powmod(unsigned long long b, unsigned long long e, unsigned long long m) {
    unsigned long long r = 1;
    while (e) { if (e & 1) r = @F_mulmod(r, b, m); b = @F_mulmod(b, b, m); e >>= 1; }
    return r;
}
static volatile unsigned long long @F_res;
__attribute__((noinline)) int @F(int argc, char **argv) {
    const unsigned long long n = 0xC2B5A4B1F7E3D2C1ULL | 1, e = 65537;   /* public modulus/exponent */
    unsigned long long m = 0;
    for (int i = 0; argv[0][i] && i < 7; i++) m = (m << 8) | (unsigned char)argv[0][i];
    @F_res = @F_powmod(m, e, n);
    return (int)(@F_res & 0xff);
}''')
