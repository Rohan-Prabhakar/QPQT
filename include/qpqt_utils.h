#pragma once
/**
 * qpqt_utils.h
 * UUID generation, CRC32, IV construction, schema serialization.
 * These are pure utility functions with no side effects.
 */

#include "qpqt_types.h"
#include <cstdint>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <random>

namespace qpqt {

// ─────────────────────────────────────────────────────────
// UUID — 16 random bytes
// ─────────────────────────────────────────────────────────

inline void generate_uuid(uint8_t out[16]) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t a = dist(gen);
    uint64_t b = dist(gen);
    memcpy(out,     &a, 8);
    memcpy(out + 8, &b, 8);
}

// ─────────────────────────────────────────────────────────
// CRC32 (IEEE 802.3 polynomial)
// ─────────────────────────────────────────────────────────

inline uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return crc ^ 0xFFFFFFFF;
}

// ─────────────────────────────────────────────────────────
// IV Construction — deterministic 12 bytes
// Per spec section 8.3
// ─────────────────────────────────────────────────────────

inline void build_iv(
    uint8_t       out_iv[QPQT_IV_LEN],
    const uint8_t file_uuid[16],
    uint32_t      page_index,
    uint16_t      row_index_within_page,
    uint16_t      column_index
) {
    // IV = file_uuid[0..3](4) | page_index(4) | row_within_page(2) | col_index(2)
    memcpy(out_iv, file_uuid, 4);
    memcpy(out_iv + 4, &page_index,            4);
    memcpy(out_iv + 8, &row_index_within_page, 2);
    memcpy(out_iv + 10, &column_index,         2);
}

// ─────────────────────────────────────────────────────────
// Page context for HKDF — 14 bytes
// Per spec section 8.2
// ─────────────────────────────────────────────────────────

inline void build_page_context(
    uint8_t       out_ctx[14],
    const uint8_t file_uuid[16],
    uint32_t      row_group_index,
    uint32_t      page_index,
    uint16_t      column_index
) {
    memcpy(out_ctx,      file_uuid,         4);
    memcpy(out_ctx + 4,  &row_group_index,  4);
    memcpy(out_ctx + 8,  &page_index,       4);
    memcpy(out_ctx + 12, &column_index,     2);
}

// ─────────────────────────────────────────────────────────
// Schema serialization / deserialization
// ─────────────────────────────────────────────────────────

// Returns byte buffer of serialized schema
inline std::vector<uint8_t> serialize_schema(const QpqtSchema& schema) {
    std::vector<uint8_t> buf;

    // column_count uint16
    uint16_t cc = schema.column_count;
    buf.push_back(cc & 0xFF);
    buf.push_back((cc >> 8) & 0xFF);

    for (auto& col : schema.columns) {
        // name_length uint8
        uint8_t nlen = (uint8_t)col.name.size();
        buf.push_back(nlen);

        // column_name utf-8
        for (char c : col.name) buf.push_back((uint8_t)c);

        // column_type uint8
        buf.push_back((uint8_t)col.type);

        // is_pqc_encrypted uint8
        buf.push_back(col.is_pqc_encrypted ? 1 : 0);

        // max_value_bytes uint32 little-endian
        uint32_t mvb = col.max_value_bytes;
        buf.push_back( mvb        & 0xFF);
        buf.push_back((mvb >>  8) & 0xFF);
        buf.push_back((mvb >> 16) & 0xFF);
        buf.push_back((mvb >> 24) & 0xFF);

        // nullable flag (absent in format version 1.0, defaults to false)
        buf.push_back(col.nullable ? 1 : 0);
    }
    return buf;
}

inline QpqtSchema deserialize_schema(const uint8_t* data, size_t len) {
    QpqtSchema schema;
    size_t pos = 0;

    if (pos + 2 > len) throw std::runtime_error("Schema truncated at column_count");
    schema.column_count = data[pos] | (data[pos+1] << 8);
    pos += 2;

    for (uint16_t i = 0; i < schema.column_count; ++i) {
        if (pos + 1 > len) throw std::runtime_error("Schema truncated at name_length");
        uint8_t nlen = data[pos++];

        if (pos + nlen > len) throw std::runtime_error("Schema truncated at name");
        QpqtColumnSchema col;
        col.name = std::string(reinterpret_cast<const char*>(data + pos), nlen);
        pos += nlen;

        if (pos + 1 > len) throw std::runtime_error("Schema truncated at type");
        col.type = (QpqtColumnType)data[pos++];

        if (pos + 1 > len) throw std::runtime_error("Schema truncated at is_pqc");
        col.is_pqc_encrypted = (data[pos++] != 0);

        if (pos + 4 > len) throw std::runtime_error("Schema truncated at max_value_bytes");
        col.max_value_bytes = data[pos]
                            | (data[pos+1] << 8)
                            | (data[pos+2] << 16)
                            | (data[pos+3] << 24);
        pos += 4;

        // nullable flag — absent in format version 1.0 files, defaults to false
        col.nullable = false;
        if (pos < len) col.nullable = (data[pos++] != 0);

        schema.columns.push_back(col);
    }
    return schema;
}

// ─────────────────────────────────────────────────────────
// Padding helpers
// ─────────────────────────────────────────────────────────

// How many zero bytes needed to align offset to 4KB boundary
inline uint16_t padding_to_4kb(uint64_t current_offset) {
    uint64_t rem = current_offset % QPQT_OS_PAGE_SIZE;
    if (rem == 0) return 0;
    return (uint16_t)(QPQT_OS_PAGE_SIZE - rem);
}

// ─────────────────────────────────────────────────────────
// File I/O helpers
// ─────────────────────────────────────────────────────────

inline void write_bytes(std::fstream& f, const void* data, size_t len) {
    f.write(reinterpret_cast<const char*>(data), len);
    if (!f) throw std::runtime_error("Write failed");
}

inline void read_bytes(std::fstream& f, void* data, size_t len) {
    f.read(reinterpret_cast<char*>(data), len);
    if (!f) throw std::runtime_error("Read failed");
}

inline uint64_t file_tell(std::fstream& f) {
    return (uint64_t)f.tellp();
}

inline void file_seek(std::fstream& f, uint64_t offset) {
    f.seekp(offset);
    f.seekg(offset);
}

} // namespace qpqt
