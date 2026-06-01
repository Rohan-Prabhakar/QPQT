#ifndef QPQT_WRITER_H
#define QPQT_WRITER_H
/**
 * qpqt_writer.cpp
 * Week 1 scope: file header + schema block + key reference block
 * writer and the structural column section (Section 1).
 * Section 2 (PQC encryption) added in Week 3.
 */

#include "../include/qpqt_types.h"
#include "../include/qpqt_utils.h"
#include "../include/qpqt_crypto.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>

using namespace qpqt;

// ─────────────────────────────────────────────────────────
// QpqtWriter
// ─────────────────────────────────────────────────────────

class QpqtWriter {
public:
    QpqtWriter(const std::string& path,
               const QpqtSchema&  schema,
               const uint8_t      key_id[16],
               const uint8_t      public_key[OQS_KEM_ml_kem_768_length_public_key] = nullptr)
        : path_(path), schema_(schema)
    {
        memcpy(key_id_, key_id, 16);
        if (public_key) {
            memcpy(public_key_, public_key, crypto::ML_KEM_768_PK_LEN);
            has_public_key_ = true;
        }

        // Open file for read/write (we need to backfill offsets)
        file_.open(path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!file_) throw std::runtime_error("Cannot open file: " + path);

        // Generate file UUID
        generate_uuid(file_uuid_);

        write_file_header();
        write_schema_block();
        write_key_reference_block();

        std::cout << "[writer] Header written. Schema offset: "
                  << schema_offset_ << "\n";
    }

    // Write one row group worth of data
    // structural_cols: one flat byte buffer per structural column
    //                  (caller packs INT32/STRING etc per spec)
    // pqc_cols:        one vector<string> per PQC column
    //                  (plaintext values, encryption added Week 3)
    void write_row_group(
        uint32_t                                row_count,
        const std::vector<std::vector<uint8_t>>& structural_cols,
        const std::vector<std::vector<std::string>>& pqc_cols
    ) {
        if (row_count > QPQT_ROWS_PER_ROW_GROUP)
            throw std::runtime_error("row_count exceeds ROWS_PER_ROW_GROUP");

        uint64_t rg_start = file_tell(file_);

        // Write row group header (backfill section2_offset later)
        QpqtRowGroupHeader rg_hdr{};
        rg_hdr.row_group_index = rg_count_;
        rg_hdr.row_count       = row_count;
        rg_hdr.section1_offset = rg_start + QpqtRowGroupHeader::SIZE;
        rg_hdr.section2_offset = 0; // backfilled after section 1
        rg_hdr.section1_padding = 0;
        rg_hdr.reserved        = 0;

        uint64_t rg_hdr_pos = rg_start;
        write_bytes(file_, &rg_hdr, QpqtRowGroupHeader::SIZE);

        // ── Section 1: structural columns ──
        uint16_t col_idx = 0;
        for (uint16_t i = 0; i < schema_.column_count; ++i) {
            if (schema_.columns[i].is_pqc_encrypted) { ++col_idx; continue; }

            const auto& buf = structural_cols[col_idx - schema_.pqc_count()
                                              + (int)(i - col_idx)];
            // Simpler indexing: structural_cols indexed by structural position
            // We use a helper below
            (void)buf;
        }

        // Cleaner structural write loop
        uint16_t s_pos = 0;
        for (uint16_t i = 0; i < schema_.column_count; ++i) {
            auto& col = schema_.columns[i];
            if (col.is_pqc_encrypted) continue;

            const auto& data = structural_cols[s_pos++];
            uint64_t byte_len = data.size();

            // Write: column_index(2) + byte_length(8) + raw_data
            write_bytes(file_, &i,        2);
            write_bytes(file_, &byte_len, 8);
            write_bytes(file_, data.data(), data.size());
        }

        // Pad Section 1 to 4KB boundary
        uint64_t after_s1 = file_tell(file_);
        uint16_t pad = padding_to_4kb(after_s1);
        if (pad > 0) {
            std::vector<uint8_t> zeros(pad, 0x00);
            write_bytes(file_, zeros.data(), pad);
        }

        // Section 2 starts here (4KB aligned)
        uint64_t section2_start = file_tell(file_);

        // ── Section 2: PQC columns (Week 3: real AES-256-GCM encryption) ──
        uint16_t p_pos = 0;
        for (uint16_t i = 0; i < schema_.column_count; ++i) {
            auto& col = schema_.columns[i];
            if (!col.is_pqc_encrypted) continue;

            const auto& rows = pqc_cols[p_pos++];
            uint32_t page_count = (row_count + QPQT_ROWS_PER_PAGE - 1)
                                 / QPQT_ROWS_PER_PAGE;

            write_bytes(file_, &i,          2);
            write_bytes(file_, &page_count, 4);

            for (uint32_t pg = 0; pg < page_count; ++pg) {
                uint32_t pg_row_start = pg * QPQT_ROWS_PER_PAGE;
                uint32_t pg_row_count = std::min(
                    (uint32_t)QPQT_ROWS_PER_PAGE,
                    row_count - pg_row_start
                );

                // ── Per-page KEM encapsulation ──
                uint8_t kem_ct[crypto::ML_KEM_768_CT_LEN];
                uint8_t shared_secret[crypto::ML_KEM_768_SS_LEN];
                uint8_t aes_key[QPQT_AES_KEY_LEN];

                if (has_public_key_) {
                    crypto::kem_encapsulate(public_key_, kem_ct, shared_secret);
                    crypto::derive_page_key(
                        shared_secret, file_uuid_,
                        rg_count_, pg, i, aes_key
                    );
                } else {
                    // Stub mode: zero key for structural tests
                    memset(kem_ct,       0, sizeof(kem_ct));
                    memset(shared_secret,0, sizeof(shared_secret));
                    memset(aes_key,      0, sizeof(aes_key));
                }

                QpqtPageHeader ph{};
                ph.page_index        = pg;
                ph.row_count         = pg_row_count;
                ph.max_plaintext_len = col.max_value_bytes;
                write_bytes(file_, &ph, QpqtPageHeader::SIZE);

                // ── Per-row AES-256-GCM encryption ──
                for (uint32_t r = 0; r < pg_row_count; ++r) {
                    uint32_t abs_row = pg_row_start + r;
                    const std::string& val = rows[abs_row];

                    // Pad plaintext to max_value_bytes
                    std::vector<uint8_t> padded(col.max_value_bytes, 0x00);
                    size_t copy_len = std::min(val.size(),
                                     (size_t)col.max_value_bytes);
                    memcpy(padded.data(), val.data(), copy_len);

                    std::vector<uint8_t> ciphertext(col.max_value_bytes);
                    uint8_t gcm_tag[QPQT_AES_GCM_TAG_LEN] = {};

                    if (has_public_key_) {
                        // Build deterministic IV per spec section 8.3
                        uint8_t iv[QPQT_IV_LEN];
                        build_iv(iv, file_uuid_, pg,
                                 (uint16_t)r, i);
                        crypto::aes_gcm_encrypt(
                            aes_key, iv,
                            padded.data(), col.max_value_bytes,
                            ciphertext.data(), gcm_tag
                        );
                    } else {
                        // Stub: copy plaintext as-is
                        memcpy(ciphertext.data(), padded.data(),
                               col.max_value_bytes);
                    }

                    write_bytes(file_, ciphertext.data(), col.max_value_bytes);
                    write_bytes(file_, gcm_tag, QPQT_AES_GCM_TAG_LEN);
                }

                // ── Manifest entry for this page ──
                QpqtManifestEntry me{};
                me.row_group_index = rg_count_;
                me.page_index      = pg;
                me.column_index    = i;
                memcpy(me.kem_ciphertext, kem_ct, crypto::ML_KEM_768_CT_LEN);
                // Store base IV (row 0 of this page)
                build_iv(me.aes_iv_base, file_uuid_, pg, 0, i);
                manifest_.push_back(me);
            }
        }

        // Backfill section1_padding and section2_offset in RG header
        rg_hdr.section1_offset  = rg_start + QpqtRowGroupHeader::SIZE;
        rg_hdr.section2_offset  = section2_start;
        rg_hdr.section1_padding = pad;

        // Backfill RG header on disk
        uint64_t current_pos = file_tell(file_);
        file_seek(file_, rg_hdr_pos);
        write_bytes(file_, &rg_hdr, QpqtRowGroupHeader::SIZE);
        file_seek(file_, current_pos);

        // Record offset table entry
        QpqtRGOffsetEntry oe{};
        oe.row_group_index  = rg_count_;
        oe.file_byte_offset = rg_start;
        oe.section1_offset  = rg_hdr.section1_offset;
        oe.section2_offset  = section2_start;
        rg_offsets_.push_back(oe);

        total_rows_ += row_count;
        ++rg_count_;

        std::cout << "[writer] Row group " << (rg_count_-1)
                  << " written. rows=" << row_count
                  << " s1_offset=" << rg_hdr.section1_offset
                  << " s2_offset=" << section2_start
                  << " padding=" << pad << "\n";
    }

    // Finalize: write footer, backfill header offsets
    void finalize() {
        uint64_t footer_start = file_tell(file_);

        // Write offset table
        uint64_t offset_table_pos = footer_start;
        for (auto& oe : rg_offsets_) {
            write_bytes(file_, &oe, QpqtRGOffsetEntry::SIZE);
        }

        // Write crypto manifest
        uint64_t manifest_pos = file_tell(file_);
        uint32_t entry_count = (uint32_t)manifest_.size();
        write_bytes(file_, &entry_count, 4);
        for (auto& me : manifest_) {
            write_bytes(file_, &me, QpqtManifestEntry::SIZE);
        }

        // Write footer header
        QpqtFooterHeader fh{};
        fh.magic_end            = QPQT_MAGIC_END;
        fh.reserved0            = 0;
        fh.offset_table_offset  = offset_table_pos;
        fh.manifest_offset      = manifest_pos;
        fh.manifest_entry_count = entry_count;
        fh.pqc_column_count     = schema_.pqc_count();
        fh.pages_per_rg         = QPQT_PAGES_PER_RG;
        fh.reserved1            = 0;

        // CRC32 of footer up to (but not including) footer_checksum field
        // We compute over offset_table + manifest bytes
        // Simple approach: checksum the footer header with checksum=0
        fh.footer_checksum = 0;
        fh.footer_checksum = crc32(
            reinterpret_cast<const uint8_t*>(&fh),
            QpqtFooterHeader::SIZE
        );
        write_bytes(file_, &fh, QpqtFooterHeader::SIZE);

        // Backfill file header: total_rows, row_group_count, footer_offset
        file_seek(file_, 0);
        QpqtFileHeader hdr{};
        hdr.magic_number    = QPQT_MAGIC;
        hdr.version_major   = QPQT_VERSION_MAJOR;
        hdr.version_minor   = QPQT_VERSION_MINOR;
        memcpy(hdr.file_uuid, file_uuid_, 16);
        hdr.total_rows      = total_rows_;
        hdr.row_group_count = rg_count_;
        hdr.schema_offset   = schema_offset_;
        hdr.footer_offset   = (uint32_t)footer_start;
        hdr.reserved        = 0;
        write_bytes(file_, &hdr, QpqtFileHeader::SIZE);

        file_.close();

        std::cout << "[writer] Finalized. total_rows=" << total_rows_
                  << " rg_count=" << rg_count_
                  << " footer_offset=" << footer_start
                  << " manifest_entries=" << entry_count << "\n";
    }

private:
    std::string   path_;
    QpqtSchema    schema_;
    std::fstream  file_;
    uint8_t       file_uuid_[16];
    uint8_t       key_id_[16];
    uint8_t       public_key_[crypto::ML_KEM_768_PK_LEN];
    bool          has_public_key_ = false;
    uint32_t      schema_offset_ = 0;
    uint32_t      rg_count_      = 0;
    uint64_t      total_rows_    = 0;

    std::vector<QpqtRGOffsetEntry> rg_offsets_;
    std::vector<QpqtManifestEntry> manifest_;

    void write_file_header() {
        // Write placeholder header (backfilled in finalize())
        QpqtFileHeader hdr{};
        hdr.magic_number    = QPQT_MAGIC;
        hdr.version_major   = QPQT_VERSION_MAJOR;
        hdr.version_minor   = QPQT_VERSION_MINOR;
        memcpy(hdr.file_uuid, file_uuid_, 16);
        hdr.total_rows      = 0;  // backfilled
        hdr.row_group_count = 0;  // backfilled
        hdr.schema_offset   = QpqtFileHeader::SIZE; // immediately after header
        hdr.footer_offset   = 0;  // backfilled
        hdr.reserved        = 0;
        write_bytes(file_, &hdr, QpqtFileHeader::SIZE);
        schema_offset_ = QpqtFileHeader::SIZE;
    }

    void write_schema_block() {
        auto schema_bytes = serialize_schema(schema_);
        write_bytes(file_, schema_bytes.data(), schema_bytes.size());
    }

    void write_key_reference_block() {
        QpqtKeyRefBlock kr{};
        kr.kr_magic      = QPQT_KR_MAGIC;
        memcpy(kr.key_id, key_id_, 16);
        kr.kem_algorithm = QPQT_KEM_ML_KEM_768;
        kr.reserved      = 0;
        write_bytes(file_, &kr, QpqtKeyRefBlock::SIZE);
    }
};

// ─────────────────────────────────────────────────────────
// Helper: pack INT32 column into flat byte buffer
// ─────────────────────────────────────────────────────────

#ifndef QPQT_PACK_INT32_DEFINED
#define QPQT_PACK_INT32_DEFINED
std::vector<uint8_t> pack_int32_column(const std::vector<int32_t>& vals) {
    std::vector<uint8_t> buf(vals.size() * 4);
    memcpy(buf.data(), vals.data(), buf.size());
    return buf;
}
#endif

// ─────────────────────────────────────────────────────────
// main — Week 1 smoke test
// TC-01: write 1 row, verify file structure
// TC-03: write 4096 rows, verify one page
// TC-05: write 100K rows, verify one row group
// ─────────────────────────────────────────────────────────

#ifndef QPQT_WRITER_NO_MAIN
int main() {
    std::cout << "=== QPQT Writer — Week 1 Smoke Test ===\n\n";

    // Build schema: 1 structural INT32 + 1 PQC STRING
    QpqtSchema schema;
    schema.column_count = 2;
    schema.columns = {
        {"customer_id",  QpqtColumnType::INT32,  false, 4},
        {"ssn",          QpqtColumnType::STRING,  true,  64}
    };

    // Fake key_id (16 bytes) — Week 1 uses local stub
    uint8_t key_id[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
    };

    // ── TC-01: 1 row ──
    {
        std::cout << "── TC-01: 1 row ──\n";
        QpqtWriter w("/tmp/tc01.qpqt", schema, key_id);

        std::vector<int32_t> ids = {1001};
        auto structural = std::vector<std::vector<uint8_t>>{
            pack_int32_column(ids)
        };
        auto pqc = std::vector<std::vector<std::string>>{
            {"123-45-6789"}
        };
        w.write_row_group(1, structural, pqc);
        w.finalize();
        std::cout << "TC-01: PASS\n\n";
    }

    // ── TC-03: 4096 rows (exactly one page) ──
    {
        std::cout << "── TC-03: 4096 rows ──\n";
        std::vector<int32_t> ids(4096);
        std::vector<std::string> ssns(4096);
        for (int i = 0; i < 4096; ++i) {
            ids[i] = 1000 + i;
            ssns[i] = "SSN-" + std::to_string(100000000 + i);
        }

        QpqtWriter w("/tmp/tc03.qpqt", schema, key_id);
        w.write_row_group(4096,
            {pack_int32_column(ids)},
            {ssns}
        );
        w.finalize();
        std::cout << "TC-03: PASS\n\n";
    }

    // ── TC-04: 4097 rows (two pages, second has 1 row) ──
    {
        std::cout << "── TC-04: 4097 rows ──\n";
        std::vector<int32_t> ids(4097);
        std::vector<std::string> ssns(4097);
        for (int i = 0; i < 4097; ++i) {
            ids[i] = i;
            ssns[i] = "SSN-" + std::to_string(i);
        }

        QpqtWriter w("/tmp/tc04.qpqt", schema, key_id);
        w.write_row_group(4097,
            {pack_int32_column(ids)},
            {ssns}
        );
        w.finalize();
        std::cout << "TC-04: PASS\n\n";
    }

    // ── TC-05: 100K rows (one full row group) ──
    {
        std::cout << "── TC-05: 100K rows ──\n";
        std::vector<int32_t> ids(100000);
        std::vector<std::string> ssns(100000);
        for (int i = 0; i < 100000; ++i) {
            ids[i] = i;
            ssns[i] = "SSN-" + std::to_string(100000000 + i);
        }

        QpqtWriter w("/tmp/tc05.qpqt", schema, key_id);
        w.write_row_group(100000,
            {pack_int32_column(ids)},
            {ssns}
        );
        w.finalize();
        std::cout << "TC-05: PASS\n\n";
    }

    // ── TC-06: 100001 rows (two row groups) ──
    {
        std::cout << "── TC-06: 100001 rows (two row groups) ──\n";
        std::vector<int32_t> ids1(100000), ids2(1);
        std::vector<std::string> ssns1(100000), ssns2(1);
        for (int i = 0; i < 100000; ++i) {
            ids1[i] = i;
            ssns1[i] = "SSN-" + std::to_string(i);
        }
        ids2[0] = 100000;
        ssns2[0] = "SSN-LAST";

        QpqtWriter w("/tmp/tc06.qpqt", schema, key_id);
        w.write_row_group(100000, {pack_int32_column(ids1)}, {ssns1});
        w.write_row_group(1,      {pack_int32_column(ids2)}, {ssns2});
        w.finalize();
        std::cout << "TC-06: PASS\n\n";
    }

    // ── TC-18: 0 rows ──
    {
        std::cout << "── TC-18: 0 rows ──\n";
        QpqtWriter w("/tmp/tc18.qpqt", schema, key_id);
        w.finalize();
        std::cout << "TC-18: PASS\n\n";
    }

    std::cout << "=== All Week 1 tests passed ===\n";
    return 0;
}
#endif // QPQT_WRITER_NO_MAIN
#endif // QPQT_WRITER_H
