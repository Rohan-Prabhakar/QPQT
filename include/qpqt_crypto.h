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

// OpenSSL
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

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

inline void hkdf_sha3_256(
    const uint8_t* ikm,       size_t ikm_len,   // shared secret
    const uint8_t* info,      size_t info_len,  // page context (14 bytes)
    uint8_t        out_key[QPQT_AES_KEY_LEN]    // 32-byte AES key
) {
    EVP_KDF*       kdf    = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX*   kctx   = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (!kctx)
        throw std::runtime_error("HKDF context creation failed");

    // Salt = empty (use HKDF default — zeroed salt of hash length)
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST, (char*)"SHA3-256", 0
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, (void*)ikm, ikm_len
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, (void*)info, info_len
        ),
        OSSL_PARAM_END
    };

    int rc = EVP_KDF_derive(kctx, out_key, QPQT_AES_KEY_LEN, params);
    EVP_KDF_CTX_free(kctx);

    if (rc <= 0)
        throw std::runtime_error("HKDF-SHA3-256 derivation failed");
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
