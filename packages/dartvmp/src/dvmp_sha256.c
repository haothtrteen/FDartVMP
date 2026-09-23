/*
 * dvmp_sha256.c - SHA-256, and the keyed keystream built on it.
 *
 * WHY THIS EXISTS AT ALL
 * ----------------------
 * The static image used to be masked with `mask_word(key, index)` =
 * SplitMix64-finalise(key + index + G0). That is a *bijection in the key* for every
 * fixed index, and the shipped image starts with eight bytes of known plaintext (the
 * magic "DVMP" plus a version), so `tool/recover_from_shipped.py` recovered the mask
 * key straight out of the release APK by inverting the finaliser - no disassembly, no
 * guessing, about thirty lines of Python:
 *
 *     mask_word(key, 0) = stored_word[0] XOR known_header
 *     unmix(both sides) -> key + G0 -> key
 *
 * Worse, because it was a *stream* - word i+1 derived from the state that produced
 * word i - recovering the key recovered all 196 words. The whole container came out,
 * which is exactly what that script demonstrates.
 *
 * Two properties are needed, and they are different properties:
 *
 *   1. **Knowing one keystream word must not reveal the key.** That rules out any
 *      construction that is a bijection of the key, which is what every mix-function
 *      is. Only a function that discards information can do it. SHA-256 truncated to
 *      64 bits does: inverting one output costs ~2^64 work.
 *
 *   2. **Knowing one keystream word must not reveal the others.** A stream cipher
 *      fails this by definition - that is what a stream is - so this is not a
 *      stronger cipher, it is a different *shape*: each word is an independent
 *      keyed function of its own index,
 *
 *          keystream(key, index) = SHA256(le64(key) || le64(index))[0..8)
 *
 *      so known plaintext at index 0 exposes the keystream at index 0 and nothing
 *      else. The eight known words of the header no longer open the body.
 *
 * WHAT THIS DOES NOT DO, because overstating it would be worse than not doing it:
 *
 *   * The key still ships in `libdartvmp.so`. Offline distribution means it has to.
 *     An attacker who reads `unmask_image_into` and this file can reimplement the
 *     keystream and decrypt the image. What changed is that this now requires
 *     *reading the runtime* rather than doing algebra on data the binary hands over.
 *     That is the whole gain, and it is a real one: it moves the cheapest attack from
 *     "a script anyone can run" to "reverse engineer the loader".
 *   * It does nothing for the interpreter, which is the other half of the problem -
 *     recovering bytecode is only useful if you can read the ISA, and the ISA is
 *     readable in the shipped AArch64. See the README on C-layer virtualization.
 *
 * SHA-256 rather than something cheaper because it has published test vectors, which
 * makes it checkable rather than merely plausible: dvmp_sha256_selftest() runs them,
 * and `image_contract_test.dart` diffs this implementation against Dart's `crypto`
 * package through the mask probe. Three implementations (C, Dart, Python) have to
 * agree on the keystream, and a hand-rolled hash is exactly the kind of thing that
 * agrees with itself and with nothing else.
 */
#include "dvmp_internal.h"
#include "dvmp_vmpacker.h"

#include <string.h>

/* ---- SHA-256 ------------------------------------------------------------ */

static const uint32_t kSha256K[64] = {
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
  0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
  0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
  0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
  0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
  0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
  0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
  0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
  0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

static uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32u - n));
}

/* One compression round. `block` is 64 bytes, big-endian. */
static void sha256_block(uint32_t h[8], const uint8_t block[64]) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
           ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
  }
  for (int i = 16; i < 64; i++) {
    const uint32_t s0 =
        rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const uint32_t s1 =
        rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
  uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
  for (int i = 0; i < 64; i++) {
    const uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    const uint32_t ch = (e & f) ^ ((~e) & g);
    const uint32_t t1 = hh + s1 + ch + kSha256K[i] + w[i];
    const uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const uint32_t t2 = s0 + maj;
    hh = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
  h[5] += f;
  h[6] += g;
  h[7] += hh;
}

DVMP_NO_BUILTIN void dvmp_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
  /*
   * Assignments rather than `uint32_t h[8] = {...}`. A brace initialiser of eight
   * constants is copied into the frame as 32 bytes, and clang does that with
   * `ldp q0, q1` / `stp q0, q1` - SIMD. VMPacker 1.3 cannot translate it, so the
   * whole target was refused (64/70) until this was written out. Eight scalar
   * stores cost nothing measurable: this is the SHA-256 of a 16-byte input, run once
   * per 8 bytes of image at open time.
   */
  uint32_t h[8];
  h[0] = 0x6a09e667u;
  h[1] = 0xbb67ae85u;
  h[2] = 0x3c6ef372u;
  h[3] = 0xa54ff53au;
  h[4] = 0x510e527fu;
  h[5] = 0x9b05688cu;
  h[6] = 0x1f83d9abu;
  h[7] = 0x5be0cd19u;

  /*
   * Padding is built in a local buffer instead of being appended to the caller's
   * data: this is called with a 16-byte stack input, and writing the 0x80 terminator
   * and the length field past the end of it would corrupt the caller's frame. The
   * buffer is sized for one full block plus the 9 bytes of padding that can overflow
   * into a second, which is the standard tail construction and nothing more.
   */
  size_t full = len / 64u;
  for (size_t i = 0; i < full; i++) {
    sha256_block(h, data + i * 64u);
  }

  uint8_t tail[128];
  const size_t rem = len - full * 64u;
  memcpy(tail, data + full * 64u, rem);
  tail[rem] = 0x80u;
  const size_t tail_len = (rem < 56u) ? 64u : 128u;
  memset(tail + rem + 1u, 0, tail_len - rem - 1u);
  const uint64_t bits = (uint64_t)len * 8u;
  for (int i = 0; i < 8; i++) {
    tail[tail_len - 8 + i] = (uint8_t)((bits >> (56 - 8 * i)) & 0xFFu);
  }
  sha256_block(h, tail);
  if (tail_len == 128u) sha256_block(h, tail + 64);

  for (int i = 0; i < 8; i++) {
    out[i * 4] = (uint8_t)(h[i] >> 24);
    out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
    out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
    out[i * 4 + 3] = (uint8_t)h[i];
  }
}

/* ---- the keyed keystream ------------------------------------------------ */

/*
 * Deliberately NOT `DVMP_VMPACKER_LINKAGE`.
 *
 * That macro is `static` when the hand-off is off, and this function is called from
 * dvmp_module.c, so using it here breaks the link in every non-VMPacker build with
 * "unresolved external symbol dvmp_mask_keystream" - which is exactly what happened, and
 * only on MSVC/desktop, because the Android build has the hand-off on and gets the empty
 * expansion. The linkage must stay external in all builds; the only thing the tool needs
 * is `noinline` + `used`, which is what DVMP_VMPACKER_TARGET provides.
 */
DVMP_VMPACKER_TARGET uint64_t dvmp_mask_keystream(
    uint64_t key, uint64_t index) {
  uint8_t in[16];
  uint8_t out[32];
  for (int i = 0; i < 8; i++) {
    in[i] = (uint8_t)((key >> (8 * i)) & 0xFFu);
    in[8 + i] = (uint8_t)((index >> (8 * i)) & 0xFFu);
  }
  dvmp_sha256(in, sizeof(in), out);
  /* Little-endian, matching the byte order the generator writes and the mask
   * apply/unapply loops consume one byte at a time. */
  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) {
    v = (v << 8) | (uint64_t)out[i];
  }
  return v;
}

/* ---- test hook ---------------------------------------------------------- */

int32_t dvmp_sha256_probe(const uint8_t *data, uint32_t len, uint8_t out[32]) {
  /*
   * A plain "hash this" entry point, so the NIST vectors can be checked from the test
   * suite rather than asserted in a comment.
   *
   * The first version of this file exposed a bespoke out-parameter self-test that
   * could only ever report its first vector, which is the kind of check that passes
   * for reasons unrelated to what it is checking. One function that does the obvious
   * thing lets the *caller* decide which vectors matter:
   *
   *   dvmp_sha256_probe("",     0, out) -> e3b0c442...b855
   *   dvmp_sha256_probe("abc",  3, out) -> ba7816bf...15ad
   *
   * Without this, a hand-written SHA-256 that is subtly wrong would still produce a
   * consistent keystream on both sides of the build, because the Dart side would be
   * changed to match it - and the container would be masked with a function of
   * unknown strength. `tool/verify_crypto.ps1` runs the vectors.
   */
  if (data == NULL && len != 0u) return DARTVMP_ERR_BAD_ARGUMENT;
  if (out == NULL) return DARTVMP_ERR_BAD_ARGUMENT;
  dvmp_sha256(data, (size_t)len, out);
  return DARTVMP_OK;
}

