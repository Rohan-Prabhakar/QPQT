#pragma once
/**
 * qpqt_types.h
 * All binary layout structs for the QPQT format.
 * Every struct maps 1:1 to the v1 spec byte layout.
 * All fields little-endian. No padding between fields (packed).
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// ─────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────

constexpr uint32_t QPQT_MAGIC           = 0x51505154; // "QPQT"
constexpr uint32_t QPQT_MAGIC_END       = 0x54515051; // "TQPQ"
constexpr uint32_t QPQT_KR_MAGIC        = 0x4B455952; // "KEYR"
constexpr uint16_t QPQT_VERSION_MAJOR   = 1;
constexpr uint16_t QPQT_VERSION_MINOR   = 0;
constexpr uint32_t QPQT_KEM_ML_KEM_768  = 0x00000003;

constexpr uint32_t QPQT_ROWS_PER_PAGE       = 4096;
constexpr uint32_t QPQT_ROWS_PER_ROW_GROUP  = 100000;
constexpr uint32_t QPQT_PAGES_PER_RG        = 25; // ceil(100000/4096)
constexpr uint32_t QPQT_OS_PAGE_SIZE        = 4096; // bytes

constexpr size_t   QPQT_ML_KEM_768_CT_LEN   = 1088;
constexpr size_t   QPQT_AES_GCM_TAG_LEN     = 16;
constexpr size_t   QPQT_AES_KEY_LEN         = 32;
constexpr size_t   QPQT_IV_LEN              = 12;
constexpr size_t   QPQT_MANIFEST_ENTRY_SIZE = 4+4+2+1088+12; // 1110 bytes

// ─────────────────────────────────────────────────────────
// Column types
// ─────────────────────────────────────────────────────────

enum class QpqtColumnType : uint8_t {
    INT32   = 0x01,
    INT64   = 0x02,
    FLOAT32 = 0x03,
    FLOAT64 = 0x04,
    STRING  = 0x05,
    DATE32  = 0x06
};

// ─────────────────────────────────────────────────────────
// File Header — 48 bytes fixed
// ─────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct QpqtFileHeader {
    uint32_t magic_number;      // 0x51505154
    uint16_t version_major;     // 1
    uint16_t version_minor;     // 0
    uint8_t  file_uuid[16];     // random, generated at write time
    uint64_t total_rows;
    uint32_t row_group_count;
    uint32_t schema_offset;     // byte offset from file start
    uint32_t footer_offset;     // byte offset from file start (backfilled)
    uint32_t reserved;          // = 0

    static constexpr size_t SIZE = 48;
};
static_assert(sizeof(QpqtFileHeader) == 48, "FileHeader must be 48 bytes");
#pragma pack(pop)

// ─────────────────────────────────────────────────────────
// Schema Column Entry (variable length on disk)
// ─────────────────────────────────────────────────────────

struct QpqtColumnSchema {
    std::string      name;
    QpqtColumnType   type;
    bool             is_pqc_encrypted;
    uint32_t         max_value_bytes;  // max plaintext bytes for PQC cols
};

// In-memory schema (decoded from disk)
struct QpqtSchema {
    uint16_t                     column_count;
    std::vector<QpqtColumnSchema> columns;

    // Helper: how many structural columns
    uint16_t structural_count() const {
        uint16_t n = 0;
        for (auto& c : columns) if (!c.is_pqc_encrypted) ++n;
        return n;
    }

    // Helper: how many PQC columns
    uint16_t pqc_count() const {
        uint16_t n = 0;
        for (auto& c : columns) if (c.is_pqc_encrypted) ++n;
        return n;
    }

    // Helper: position of column C among PQC columns (0-indexed)
    int16_t pqc_position(uint16_t col_index) const {
        int16_t pos = 0;
        for (uint16_t i = 0; i < columns.size(); ++i) {
            if (!columns[i].is_pqc_encrypted) continue;
            if (i == col_index) return pos;
            ++pos;
        }
        return -1; // not a PQC column
    }
};

// ─────────────────────────────────────────────────────────
// Key Reference Block — 32 bytes fixed
// ─────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct QpqtKeyRefBlock {
    uint32_t kr_magic;          // 0x4B455952 "KEYR"
    uint8_t  key_id[16];        // UUID referencing public key in KMS
    uint32_t kem_algorithm;     // 0x00000003 = ML-KEM-768
    uint64_t reserved;          // = 0

    static constexpr size_t SIZE = 32;
};
static_assert(sizeof(QpqtKeyRefBlock) == 32, "KeyRefBlock must be 32 bytes");
#pragma pack(pop)

// ─────────────────────────────────────────────────────────
// Row Group Header — 28 bytes fixed
// ─────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct QpqtRowGroupHeader {
    uint32_t row_group_index;
    uint32_t row_count;         // <= 100,000
    uint64_t section1_offset;   // absolute byte offset from file start
    uint64_t section2_offset;   // absolute byte offset from file start
    uint16_t section1_padding;  // zero-pad bytes after section 1
    uint16_t reserved;          // = 0

    static constexpr size_t SIZE = 28;
};
static_assert(sizeof(QpqtRowGroupHeader) == 28, "RGHeader must be 28 bytes");
#pragma pack(pop)

// ─────────────────────────────────────────────────────────
// Page Header (Section 2) — 12 bytes fixed
// ─────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct QpqtPageHeader {
    uint32_t page_index;
    uint32_t row_count;             // <= 4096
    uint32_t max_plaintext_len;     // from schema, stored once per page

    static constexpr size_t SIZE = 12;
};
static_assert(sizeof(QpqtPageHeader) == 12, "PageHeader must be 12 bytes");
#pragma pack(pop)

// ─────────────────────────────────────────────────────────
// Crypto Manifest Entry — 1110 bytes fixed
// ─────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct QpqtManifestEntry {
    uint32_t row_group_index;
    uint32_t page_index;
    uint16_t column_index;
    uint8_t  kem_ciphertext[QPQT_ML_KEM_768_CT_LEN]; // 1088 bytes
    uint8_t  aes_iv_base[QPQT_IV_LEN];               // 12 bytes

    static constexpr size_t SIZE = 1110;
};
static_assert(sizeof(QpqtManifestEntry) == 1110,
              "ManifestEntry must be 1110 bytes");
#pragma pack(pop)

// ─────────────────────────────────────────────────────────
// Row Group Offset Table Entry
// ─────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct QpqtRGOffsetEntry {
    uint32_t row_group_index;
    uint32_t reserved;
    uint64_t file_byte_offset;   // RG header start
    uint64_t section1_offset;    // absolute
    uint64_t section2_offset;    // absolute

    static constexpr size_t SIZE = 32;
};
static_assert(sizeof(QpqtRGOffsetEntry) == 32, "RGOffsetEntry must be 32 bytes");
#pragma pack(pop)

// ─────────────────────────────────────────────────────────
// Footer Header — 40 bytes fixed
// ─────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct QpqtFooterHeader {
    uint32_t magic_end;                 // 0x54515051 "TQPQ"
    uint32_t reserved0;
    uint64_t offset_table_offset;       // absolute byte offset
    uint64_t manifest_offset;           // absolute byte offset
    uint32_t manifest_entry_count;
    uint16_t pqc_column_count;
    uint32_t pages_per_rg;              // = 25
    uint32_t footer_checksum;           // CRC32 of footer (excl this field)
    uint16_t reserved1;

    static constexpr size_t SIZE = 40;
};
static_assert(sizeof(QpqtFooterHeader) == 40, "FooterHeader must be 40 bytes");
#pragma pack(pop)

// ─────────────────────────────────────────────────────────
// Typed structural column value (C++17 variant)
// ─────────────────────────────────────────────────────────

#include <variant>
#include <optional>

using QpqtScalarValue = std::variant<
    int32_t,      // INT32, DATE32
    int64_t,      // INT64
    float,        // FLOAT32
    double,       // FLOAT64
    std::string   // STRING (structural)
>;

struct QpqtColValue {
    QpqtColumnType  type;
    bool            is_null = false;
    QpqtScalarValue value   = int32_t{0};
};

// ─────────────────────────────────────────────────────────
// Query result row — typed structural + PQC values
// ─────────────────────────────────────────────────────────

struct QpqtResultRow {
    uint64_t                  row_index;
    // INT32 values in schema order — retained for API compatibility
    std::vector<int32_t>      int32_values;
    // New: all structural columns typed, in schema order (non-pqc cols only)
    std::vector<QpqtColValue> structural_values;
    // PQC columns (decrypted strings) in schema order
    std::vector<std::string>  pqc_values;
};

// ─────────────────────────────────────────────────────────
// Predicate on a structural column (used by QpqtReader::query)
// ─────────────────────────────────────────────────────────

#include <functional>

struct QpqtPredicate {
    uint16_t col_index;
    std::function<bool(int32_t)> test;  // value cast to int32 for comparison
};

// ─────────────────────────────────────────────────────────
// In-memory row batch (used by writer)
// ─────────────────────────────────────────────────────────

struct QpqtRowBatch {
    uint64_t                              row_count;
    // structural: column_index → flat byte buffer
    std::vector<std::vector<uint8_t>>     structural_data;
    // pqc: column_index → vector of plaintext strings
    std::vector<std::vector<std::string>> pqc_data;
};
