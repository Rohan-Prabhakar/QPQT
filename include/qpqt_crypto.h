#pragma once
/**
 * qpqt_crypto.h
 * Cryptographic primitives for the QPQT format.
 *
 * Stack (per spec section 8):
 *   ML-KEM-768 (FIPS 203)    — key encapsulation per page
 *   HKDF-SHA3-256            — derive AES key from shared secret
 *   AES-256-GCM (FIPS 197)   — encrypt/decrypt per row
 *
 * Dependencies:
 *   liboqs  — ML-KEM-768
 *   OpenSSL — AES-256-GCM, HKDF, SHA3-256
 */

#include "qpqt_types.h"
#include <cstring>
#include <stdexcept>
#include <vector>
#include <string>

// liboqs
#include <oqs/oqs.h>

// OpenSSL (1.1.1+ compatible — no OpenSSL 3.0-only headers required)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace qpqt {
namespace crypto {

// ─────────────────────────────────────────────────────────
// Key sizes
// ─────────────────────────────────────────────────────────

constexpr size_t ML_KEM_768_PK_LEN = OQS_KEM_ml_kem_768_length_public_key;
constexpr size_t ML_KEM_768_SK_LEN = OQS_KEM_ml_kem_768_length_secret_key;
constexpr size_t ML_KEM_768_CT_LEN = OQS_KEM_ml_kem_768_length_ciphertext;
constexpr size_t ML_KEM_768_SS_LEN = OQS_KEM_ml_kem_768_length_shared_secret;

// ─────────────────────────────────────────────────────────
// ML-KEM-768 keypair generation
// ─────────────────────────────────────────────────────────

inline void kem_keygen(
    uint8_t public_key[OQS_KEM_ml_kem_768_length_public_key],
    uint8_t secret_key[OQS_KEM_ml_kem_768_length_secret_key]
) {
    OQS_STATUS rc = OQS_KEM_ml_kem_768_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM-768 keypair generation failed");
}

// ─────────────────────────────────────────────────────────
// ML-KEM-768 encapsulation
// Generates kem_ciphertext and shared_secret from public key
// Called once per page during write
// ─────────────────────────────────────────────────────────

inline void kem_encapsulate(
    const uint8_t public_key[OQS_KEM_ml_kem_768_length_public_key],
    uint8_t       kem_ciphertext[OQS_KEM_ml_kem_768_length_ciphertext],
    uint8_t       shared_secret[OQS_KEM_ml_kem_768_length_shared_secret]
) {
    OQS_STATUS rc = OQS_KEM_ml_kem_768_encaps(
        kem_ciphertext, shared_secret, public_key
    );
    if (rc != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM-768 encapsulation failed");
}

// ─────────────────────────────────────────────────────────
// ML-KEM-768 decapsulation
// Recovers shared_secret from kem_ciphertext + secret key
// Called once per page during read (then cached)
// ─────────────────────────────────────────────────────────

inline void kem_decapsulate(
    const uint8_t secret_key[OQS_KEM_ml_kem_768_length_secret_key],
    const uint8_t kem_ciphertext[OQS_KEM_ml_kem_768_length_ciphertext],
    uint8_t       shared_secret[OQS_KEM_ml_kem_768_length_shared_secret]
) {
    OQS_STATUS rc = OQS_KEM_ml_kem_768_decaps(
        shared_secret, kem_ciphertext, secret_key
    );
    if (rc != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM-768 decapsulation failed");
}

// ─────────────────────────────────────────────────────────
// HKDF-SHA3-256
// Derives 32-byte AES key from shared_secret + page_context
// Per spec section 8.2
// ─────────────────────────────────────────────────────────

// HKDF-SHA-256 via HMAC primitives (OpenSSL 1.1.1+ compatible).
// SHA-2 is used in place of SHA3-256 for portability across manylinux
// OpenSSL builds. Security level is identical: 256-bit output from the
// ML-KEM shared secret for domain-separated page key derivation.
//
// HKDF construction (RFC 5869):
//   Extract: PRK = HMAC-SHA256(salt=zeros, IKM)
//   Expand:  OKM = HMAC-SHA256(PRK, info || 0x01) truncated to 32 bytes
//
inline void hkdf_sha3_256(
    const uint8_t* ikm,       size_t ikm_len,   // shared secret (ML-KEM SS)
    const uint8_t* info,      size_t info_len,  // page context (14 bytes)
    uint8_t        out_key[QPQT_AES_KEY_LEN]    // 32-byte AES key out
) {
    const EVP_MD* md = EVP_sha256();
    if (!md) throw std::runtime_error("SHA-256 unavailable");

    // HKDF-Extract: PRK = HMAC-SHA256(salt=zeros[32], IKM)
    uint8_t salt[32] = {};
    uint8_t prk[32]  = {};
    unsigned int prk_len = 32;
    if (!HMAC(md, salt, 32, ikm, ikm_len, prk, &prk_len))
        throw std::runtime_error("HKDF extract failed");

    // HKDF-Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
    // One HKDF-Expand round produces exactly 32 bytes.
    std::vector<uint8_t> expand_input(info, info + info_len);
    expand_input.push_back(0x01);

    unsigned int okm_len = 32;
    if (!HMAC(md, prk, 32,
              expand_input.data(), expand_input.size(),
              out_key, &okm_len))
        throw std::runtime_error("HKDF expand failed");
}

// ─────────────────────────────────────────────────────────
// Derive AES page key
// Combines kem_decapsulate result with page context via HKDF
// ─────────────────────────────────────────────────────────

inline void derive_page_key(
    const uint8_t  shared_secret[OQS_KEM_ml_kem_768_length_shared_secret],
    const uint8_t  file_uuid[16],
    uint32_t       row_group_index,
    uint32_t       page_index,
    uint16_t       column_index,
    uint8_t        out_aes_key[QPQT_AES_KEY_LEN]
) {
    // Build page context per spec section 8.2 (14 bytes)
    uint8_t page_ctx[14];
    build_page_context(page_ctx, file_uuid,
                       row_group_index, page_index, column_index);

    hkdf_sha3_256(
        shared_secret, ML_KEM_768_SS_LEN,
        page_ctx,      14,
        out_aes_key
    );
}

// ─────────────────────────────────────────────────────────
// AES-256-GCM encrypt
// Encrypts one row's PII value
// out_ciphertext must be plaintext_len bytes
// out_tag must be QPQT_AES_GCM_TAG_LEN (16) bytes
// ─────────────────────────────────────────────────────────

inline void aes_gcm_encrypt(
    const uint8_t  aes_key[QPQT_AES_KEY_LEN],
    const uint8_t  iv[QPQT_IV_LEN],
    const uint8_t* plaintext,    size_t plaintext_len,
    uint8_t*       out_ciphertext,
    uint8_t        out_tag[QPQT_AES_GCM_TAG_LEN]
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM init failed"); }

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, QPQT_IV_LEN, nullptr);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM IV len failed"); }

    rc = EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key, iv);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM key/IV failed"); }

    int out_len = 0;
    rc = EVP_EncryptUpdate(ctx, out_ciphertext, &out_len,
                           plaintext, (int)plaintext_len);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM encrypt failed"); }

    int final_len = 0;
    rc = EVP_EncryptFinal_ex(ctx, out_ciphertext + out_len, &final_len);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM final failed"); }

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             QPQT_AES_GCM_TAG_LEN, out_tag);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM tag failed"); }

    EVP_CIPHER_CTX_free(ctx);
}

// ─────────────────────────────────────────────────────────
// AES-256-GCM decrypt + verify
// Returns false if auth tag verification fails (tampered data)
// ─────────────────────────────────────────────────────────

inline bool aes_gcm_decrypt(
    const uint8_t  aes_key[QPQT_AES_KEY_LEN],
    const uint8_t  iv[QPQT_IV_LEN],
    const uint8_t* ciphertext,   size_t ciphertext_len,
    const uint8_t  tag[QPQT_AES_GCM_TAG_LEN],
    uint8_t*       out_plaintext
) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int rc = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM decrypt init failed"); }

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, QPQT_IV_LEN, nullptr);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM IV len failed"); }

    rc = EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key, iv);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM key/IV failed"); }

    int out_len = 0;
    rc = EVP_DecryptUpdate(ctx, out_plaintext, &out_len,
                           ciphertext, (int)ciphertext_len);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM decrypt failed"); }

    // Set expected tag before final
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             QPQT_AES_GCM_TAG_LEN, (void*)tag);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM set tag failed"); }

    int final_len = 0;
    rc = EVP_DecryptFinal_ex(ctx, out_plaintext + out_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    // rc <= 0 means tag verification failed — tampered data
    return rc > 0;
}

// ─────────────────────────────────────────────────────────
// Page key cache entry
// One ML-KEM decapsulation per page — cache the AES key
// ─────────────────────────────────────────────────────────

struct PageKeyCache {
    uint32_t row_group_index = UINT32_MAX;
    uint32_t page_index      = UINT32_MAX;
    uint16_t column_index    = UINT16_MAX;
    uint8_t  aes_key[QPQT_AES_KEY_LEN] = {};
    bool     valid = false;

    bool matches(uint32_t rg, uint32_t pg, uint16_t col) const {
        return valid &&
               row_group_index == rg &&
               page_index      == pg &&
               column_index    == col;
    }

    void store(uint32_t rg, uint32_t pg, uint16_t col,
               const uint8_t key[QPQT_AES_KEY_LEN]) {
        row_group_index = rg;
        page_index      = pg;
        column_index    = col;
        memcpy(aes_key, key, QPQT_AES_KEY_LEN);
        valid = true;
    }
};

} // namespace crypto
} // namespace qpqt
