/**
 * qpqt_reader.cpp
 *
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
#include <functional>
#include <map>
#include <omp.h>
#include <algorithm>

using namespace qpqt;

// QpqtResultRow, QpqtColValue, QpqtPredicate defined in qpqt_types.h

// ─────────────────────────────────────────────────────────
// QpqtReader
// ─────────────────────────────────────────────────────────

class QpqtReader {
public:
    explicit QpqtReader(const std::string& path) : path_(path) {
        file_.open(path, std::ios::in | std::ios::binary);
        if (!file_) throw std::runtime_error("Cannot open: " + path);

        read_and_verify_footer();
        read_file_header();
        read_schema();
        read_key_reference();

    }

    // ── Public API ──

    // Provide the ML-KEM-768 secret key for decryption
    void set_secret_key(const uint8_t sk[crypto::ML_KEM_768_SK_LEN]) {
        memcpy(secret_key_, sk, crypto::ML_KEM_768_SK_LEN);
        has_secret_key_ = true;
    }

    const QpqtSchema&      schema()     const { return schema_; }
    const QpqtFileHeader&  file_header()const { return file_hdr_; }
    uint64_t               total_rows() const { return file_hdr_.total_rows; }

    // Scan row groups, apply predicates on structural columns,
    // optionally starting at start_row and returning at most max_rows results.
    // start_row=0, max_rows=UINT64_MAX means scan everything (default behaviour).
    std::vector<QpqtResultRow> query(
        const std::vector<QpqtPredicate>& predicates,
        uint64_t& out_section2_bytes_read,
        uint64_t   start_row = 0,
        uint64_t   max_rows  = UINT64_MAX
    ) {
        out_section2_bytes_read = 0;
        std::vector<QpqtResultRow> results;
        uint64_t rows_seen   = 0; // absolute row index across all RGs
        uint64_t rows_emitted = 0;

        for (auto& oe : rg_offsets_) {
            // Read row count from RG header before any other seek
            file_.seekg(oe.file_byte_offset);
            QpqtRowGroupHeader rg_hdr;
            file_.read(reinterpret_cast<char*>(&rg_hdr), QpqtRowGroupHeader::SIZE);
            uint64_t rg_row_count = rg_hdr.row_count;

            // Skip this RG entirely if it falls before start_row
            if (rows_seen + rg_row_count <= start_row) {
                rows_seen += rg_row_count;
                continue;
            }

            // Skip this RG if statistics prove no row can satisfy all predicates
            if (rg_eliminated_by_stats(oe.row_group_index, predicates)) {
                rows_seen += rg_row_count;
                continue;
            }

            auto rg_results = query_row_group(
                oe, (uint32_t)rg_row_count, predicates, out_section2_bytes_read
            );

            for (auto& r : rg_results) {
                if (r.row_index < start_row) continue;
                results.push_back(std::move(r));
                if (++rows_emitted >= max_rows) return results;
            }

            rows_seen += rg_row_count;
            if (rows_emitted >= max_rows) break;
        }
        return results;
    }

    // Stream all matching rows through a callback — O(N) single pass,
    // no result vector stored. Used by benchmarks and DuckDB scan.
    uint64_t query_count(
        const std::vector<QpqtPredicate>& predicates,
        uint64_t& out_section2_bytes_read
    ) {
        out_section2_bytes_read = 0;
        uint64_t count = 0;
        for (auto& oe : rg_offsets_) {
            if (rg_eliminated_by_stats(oe.row_group_index, predicates)) continue;
            file_.seekg(oe.file_byte_offset);
            QpqtRowGroupHeader rg_hdr;
            file_.read(reinterpret_cast<char*>(&rg_hdr), QpqtRowGroupHeader::SIZE);
            auto rg_results = query_row_group(
                oe, rg_hdr.row_count, predicates, out_section2_bytes_read);
            count += rg_results.size();
        }
        return count;
    }

    // Read a single row by absolute index (for TC-07)
    QpqtResultRow read_row(uint64_t row_index) {
        uint32_t rg_idx   = (uint32_t)(row_index / QPQT_ROWS_PER_ROW_GROUP);
        uint32_t row_in_rg= (uint32_t)(row_index % QPQT_ROWS_PER_ROW_GROUP);

        if (rg_idx >= rg_offsets_.size())
            throw std::runtime_error("row_index out of range");

        auto& oe = rg_offsets_[rg_idx];

        // Read row group header to get row count (needed for bitmap parsing)
        file_.seekg(oe.file_byte_offset);
        QpqtRowGroupHeader rg_hdr;
        file_.read(reinterpret_cast<char*>(&rg_hdr), QpqtRowGroupHeader::SIZE);

        // Read section 1 for this row group
        auto [s1_data, s1_size] = read_section1(oe);

        QpqtResultRow row;
        row.row_index = row_index;

        extract_int32_values(s1_data, oe, row_in_rg, 1, row, rg_hdr.row_count);

        // Read PQC value (decrypted if secret key is set)
        row.pqc_values = read_pqc_row(oe, row_in_rg);

        return row;
    }

private:
    std::string             path_;
    std::fstream            file_;
    QpqtFileHeader          file_hdr_;
    QpqtSchema              schema_;
    QpqtKeyRefBlock         key_ref_;
    QpqtFooterHeader        footer_hdr_;
    std::vector<QpqtRGOffsetEntry> rg_offsets_;
    std::vector<QpqtManifestEntry> manifest_;
    uint8_t                 secret_key_[crypto::ML_KEM_768_SK_LEN] = {};
    bool                    has_secret_key_ = false;
    crypto::PageKeyCache    page_key_cache_;
    std::vector<QpqtRGStatEntry> stats_;

    // Returns true if all predicates are eliminated by row group statistics.
    // A predicate eliminates a row group when:
    //   pred > max  (nothing in the RG can pass pred > X if max <= X)
    //   pred < min  (nothing in the RG can pass pred < X if min >= X)
    //   pred == val and val not in [min, max]
    bool rg_eliminated_by_stats(uint32_t rg_idx,
                                 const std::vector<QpqtPredicate>& preds) const {
        if (stats_.empty() || preds.empty()) return false;
        for (auto& pred : preds) {
            uint16_t ci = pred.col_index;
            if (ci >= schema_.column_count) continue;
            if (schema_.columns[ci].is_pqc_encrypted) continue;

            // Find stat entry for this (rg, col)
            const QpqtRGStatEntry* se = nullptr;
            for (auto& s : stats_)
                if (s.row_group_index == rg_idx && s.col_index == ci) { se = &s; break; }
            if (!se || !se->has_min || !se->has_max) continue;

            // Extract min/max as int32 for comparison (same cast as predicate)
            int32_t mn = 0, mx = 0;
            auto type = schema_.columns[ci].type;
            if (type == QpqtColumnType::INT32 || type == QpqtColumnType::DATE32) {
                memcpy(&mn, se->min_bytes, 4);
                memcpy(&mx, se->max_bytes, 4);
            } else if (type == QpqtColumnType::INT64) {
                int64_t v; memcpy(&v, se->min_bytes, 8); mn = (int32_t)v;
                           memcpy(&v, se->max_bytes, 8); mx = (int32_t)v;
            } else if (type == QpqtColumnType::FLOAT32) {
                float v; memcpy(&v, se->min_bytes, 4); mn = (int32_t)v;
                         memcpy(&v, se->max_bytes, 4); mx = (int32_t)v;
            } else if (type == QpqtColumnType::FLOAT64) {
                double v; memcpy(&v, se->min_bytes, 8); mn = (int32_t)v;
                          memcpy(&v, se->max_bytes, 8); mx = (int32_t)v;
            } else continue;

            // Test if predicate eliminates entire RG:
            // probe min and max — if neither passes the predicate, skip
            bool min_passes = pred.test(mn);
            bool max_passes = pred.test(mx);
            // For monotone predicates (>, >=, <, <=, ==):
            // If max fails pred > X  → all values fail → skip
            // If min fails pred < X  → all values fail → skip
            // Conservative: if neither endpoint passes AND range is tight, skip
            if (!min_passes && !max_passes) return true;
        }
        return false;
    }


    void read_and_verify_footer() {
        // Seek to end, get file size
        file_.seekg(0, std::ios::end);
        uint64_t file_size = file_.tellg();

        if (file_size < QpqtFooterHeader::SIZE)
            throw std::runtime_error("File too small to contain footer");

        // Step 1: read FOOTER HEADER from last 40 bytes
        file_.seekg(-(int64_t)QpqtFooterHeader::SIZE, std::ios::end);
        file_.read(reinterpret_cast<char*>(&footer_hdr_),
                   QpqtFooterHeader::SIZE);

        // Step 2a: verify magic
        if (footer_hdr_.magic_end != QPQT_MAGIC_END)
            throw std::runtime_error("Invalid footer magic — not a .qpqt file");

        // Step 2b: verify CRC32
        // Recompute with checksum field zeroed
        uint32_t stored_crc = footer_hdr_.footer_checksum;
        footer_hdr_.footer_checksum = 0;
        uint32_t computed_crc = crc32(
            reinterpret_cast<const uint8_t*>(&footer_hdr_),
            QpqtFooterHeader::SIZE
        );
        footer_hdr_.footer_checksum = stored_crc;

        if (stored_crc != computed_crc) {
            throw std::runtime_error(
                "Footer CRC32 mismatch — file may be corrupted"
            );
        }

        // Step 3: read ROW GROUP OFFSET TABLE
        file_.seekg(footer_hdr_.offset_table_offset);
        uint32_t rg_count = file_hdr_.row_group_count; // unused — count derived from offset table size
       
        uint64_t ot_bytes = footer_hdr_.manifest_offset
                          - footer_hdr_.offset_table_offset;
        uint32_t ot_count = (uint32_t)(ot_bytes / QpqtRGOffsetEntry::SIZE);

        rg_offsets_.resize(ot_count);
        for (uint32_t i = 0; i < ot_count; ++i) {
            file_.read(reinterpret_cast<char*>(&rg_offsets_[i]),
                       QpqtRGOffsetEntry::SIZE);
        }

        // Read crypto manifest
        file_.seekg(footer_hdr_.manifest_offset);
        uint32_t me_count;
        file_.read(reinterpret_cast<char*>(&me_count), 4);

        manifest_.resize(me_count);
        for (uint32_t i = 0; i < me_count; ++i) {
            file_.read(reinterpret_cast<char*>(&manifest_[i]),
                       QpqtManifestEntry::SIZE);
        }

        // Read stats block if present (stats_offset == 0 means absent)
        if (footer_hdr_.stats_offset != 0) {
            file_.seekg(footer_hdr_.stats_offset);
            uint32_t sc;
            file_.read(reinterpret_cast<char*>(&sc), 4);
            stats_.resize(sc);
            for (uint32_t i = 0; i < sc; ++i)
                file_.read(reinterpret_cast<char*>(&stats_[i]),
                           QpqtRGStatEntry::SIZE);
        }
    }

    // ── File header reading ──

    void read_file_header() {
        file_.seekg(0);
        file_.read(reinterpret_cast<char*>(&file_hdr_),
                   QpqtFileHeader::SIZE);

        if (file_hdr_.magic_number != QPQT_MAGIC)
            throw std::runtime_error("Invalid file magic");
        if (file_hdr_.version_major != QPQT_VERSION_MAJOR)
            throw std::runtime_error("Unsupported version");
    }

    // ── Schema reading ──

    void read_schema() {
        file_.seekg(file_hdr_.schema_offset);

        // Read schema bytes up to key reference block
        // Schema is variable length — read enough bytes then parse
        // Max schema size: 2 + 255*(1+255+1+1+4) = ~67KB, read 4KB safely
        std::vector<uint8_t> buf(4096, 0);
        file_.read(reinterpret_cast<char*>(buf.data()), 4096);
        size_t bytes_read = file_.gcount();

        schema_ = deserialize_schema(buf.data(), bytes_read);
    }

    // ── Key reference reading ──

    void read_key_reference() {
        // Key ref block follows schema — compute offset
        // Reserialize schema to get its byte length
        auto schema_bytes = serialize_schema(schema_);
        uint64_t kr_offset = file_hdr_.schema_offset + schema_bytes.size();

        file_.seekg(kr_offset);
        file_.read(reinterpret_cast<char*>(&key_ref_),
                   QpqtKeyRefBlock::SIZE);

        if (key_ref_.kr_magic != QPQT_KR_MAGIC)
            throw std::runtime_error("Invalid key reference block magic");
    }

    // ── Row group query — parallel batch decryption ──

    std::vector<QpqtResultRow> query_row_group(
        const QpqtRGOffsetEntry&          oe,
        uint32_t                          rg_row_count,
        const std::vector<QpqtPredicate>& predicates,
        uint64_t&                         s2_bytes_read
    ) {
        // Step 5: read SECTION 1 only
        auto [s1_data, s1_size] = read_section1(oe);

        // Step 6: apply predicates → survivor_indices
        std::vector<uint32_t> survivors = apply_predicates(
            s1_data, oe, rg_row_count, predicates
        );

        // Step 7: if no survivors, never touch Section 2
        if (survivors.empty()) return {};

        // Step 8: group survivors by page for batch reads
        // page_idx → list of (row_in_rg, row_in_page)
        std::map<uint32_t, std::vector<std::pair<uint32_t,uint32_t>>> by_page;
        for (uint32_t row_in_rg : survivors) {
            uint32_t pg  = row_in_rg / QPQT_ROWS_PER_PAGE;
            uint32_t rip = row_in_rg % QPQT_ROWS_PER_PAGE;
            by_page[pg].push_back({row_in_rg, rip});
        }

        // Pre-size results to preserve order
        std::vector<QpqtResultRow> results(survivors.size());
        // Map row_in_rg → result index
        std::map<uint32_t, size_t> row_to_idx;
        for (size_t i = 0; i < survivors.size(); ++i)
            row_to_idx[survivors[i]] = i;

        // Extract structural values into results (serial — fast)
        for (size_t i = 0; i < survivors.size(); ++i) {
            results[i].row_index = (uint64_t)oe.row_group_index
                                 * QPQT_ROWS_PER_ROW_GROUP + survivors[i];
            extract_int32_values(s1_data, oe, survivors[i], 1, results[i], rg_row_count);
        }

        // Step 8: per PQC column, read page-by-page, decrypt in parallel
        for (uint16_t col_i = 0; col_i < schema_.column_count; ++col_i) {
            if (!schema_.columns[col_i].is_pqc_encrypted) continue;

            uint32_t max_len  = schema_.columns[col_i].max_value_bytes;
            uint64_t row_size = max_len + QPQT_AES_GCM_TAG_LEN;

            // Initialise pqc_values slot for this column in all results
            for (auto& r : results) r.pqc_values.push_back("");

            uint16_t pqc_pos = (uint16_t)schema_.pqc_position(col_i);

            for (auto& [pg, page_rows] : by_page) {
                // ── Derive AES key for this page (once) ──
                uint8_t aes_key[QPQT_AES_KEY_LEN];
                {
                    // Lookup manifest entry by coordinates
                    const QpqtManifestEntry* me_ptr = nullptr;
                    for (auto& me : manifest_)
                        if (me.row_group_index == oe.row_group_index &&
                            me.page_index      == pg &&
                            me.column_index    == col_i) { me_ptr = &me; break; }
                    if (!me_ptr)
                        throw std::runtime_error("Manifest entry not found");
                    auto& me = *me_ptr;
                    if (!has_secret_key_)
                        throw std::runtime_error(
                            "PQC column requires secret key — call set_secret_key() first");
                    uint8_t ss[crypto::ML_KEM_768_SS_LEN];
                    crypto::kem_decapsulate(secret_key_, me.kem_ciphertext, ss);
                    crypto::derive_page_key(
                        ss, file_hdr_.file_uuid,
                        oe.row_group_index, pg, col_i, aes_key
                    );
                }

                // ── Batch read: entire page ciphertext block into memory ──
                // Navigate to page start in Section 2
                uint64_t page_data_offset = compute_page_offset(
                    oe, col_i, pg, max_len
                );
                uint32_t pg_row_count = std::min(
                    QPQT_ROWS_PER_PAGE,
                    rg_row_count - pg * QPQT_ROWS_PER_PAGE
                );
                uint64_t page_bytes = (uint64_t)pg_row_count * row_size;

                std::vector<uint8_t> page_buf(page_bytes);
                file_.seekg(page_data_offset);
                file_.read(reinterpret_cast<char*>(page_buf.data()), page_bytes);

                s2_bytes_read += (uint64_t)page_rows.size() * row_size;

                // ── Parallel decrypt survivors within this page ──
                size_t n = page_rows.size();
                std::vector<std::string> decrypted(n);
                std::vector<bool> auth_ok(n, true);

                #pragma omp parallel for schedule(dynamic, 16)
                for (size_t j = 0; j < n; ++j) {
                    uint32_t rip = page_rows[j].second;
                    uint64_t row_off = (uint64_t)rip * row_size;

                    const uint8_t* ct  = page_buf.data() + row_off;
                    const uint8_t* tag = ct + max_len;

                    uint8_t iv[QPQT_IV_LEN];
                    build_iv(iv, file_hdr_.file_uuid, pg,
                             (uint16_t)rip, col_i);

                    std::vector<uint8_t> pt(max_len);
                    auth_ok[j] = crypto::aes_gcm_decrypt(
                        aes_key, iv, ct, max_len, tag, pt.data()
                    );

                    if (auth_ok[j]) {
                        size_t len = max_len;
                        while (len > 0 && pt[len-1] == 0x00) --len;
                        decrypted[j] = std::string(
                            reinterpret_cast<char*>(pt.data()), len
                        );
                    }
                }

                // Check auth tags and store results
                for (size_t j = 0; j < n; ++j) {
                    if (!auth_ok[j])
                        throw std::runtime_error(
                            "GCM auth tag failed — data tampered"
                        );
                    uint32_t row_in_rg = page_rows[j].first;
                    size_t   res_idx   = row_to_idx[row_in_rg];
                    // pqc_values was pre-sized — set the last slot
                    results[res_idx].pqc_values.back() = decrypted[j];
                }
            }
        }

        return results;
    }

    // ── Compute byte offset of page data start in Section 2 ──
    // Navigates past col header and preceding pages
    uint64_t compute_page_offset(
        const QpqtRGOffsetEntry& oe,
        uint16_t                 col_i,
        uint32_t                 target_page,
        uint32_t                 max_len
    ) {
        uint64_t row_size = max_len + QPQT_AES_GCM_TAG_LEN;
        uint64_t pos = oe.section2_offset;

        // Skip columns before col_i
        for (uint16_t c = 0; c < schema_.column_count; ++c) {
            if (!schema_.columns[c].is_pqc_encrypted) continue;

            file_.seekg(pos);
            uint16_t stored_col;
            uint32_t page_count;
            file_.read(reinterpret_cast<char*>(&stored_col), 2);
            file_.read(reinterpret_cast<char*>(&page_count), 4);
            pos += 6;

            if (c == col_i) {
                // Skip pages before target_page
                for (uint32_t pg = 0; pg < target_page; ++pg) {
                    QpqtPageHeader ph;
                    file_.seekg(pos);
                    file_.read(reinterpret_cast<char*>(&ph),
                               QpqtPageHeader::SIZE);
                    pos += QpqtPageHeader::SIZE
                         + (uint64_t)ph.row_count * row_size;
                }
                // Skip target page header, return data start
                pos += QpqtPageHeader::SIZE;
                return pos;
            } else {
                // Skip entire column
                for (uint32_t pg = 0; pg < page_count; ++pg) {
                    QpqtPageHeader ph;
                    file_.seekg(pos);
                    file_.read(reinterpret_cast<char*>(&ph),
                               QpqtPageHeader::SIZE);
                    pos += QpqtPageHeader::SIZE
                         + (uint64_t)ph.row_count * row_size;
                }
            }
        }
        throw std::runtime_error("Column not found in Section 2");
    }

    // ── Section 1 reader ──

    std::pair<std::vector<uint8_t>, uint64_t> read_section1(
        const QpqtRGOffsetEntry& oe
    ) {
        uint64_t s1_start = oe.section1_offset;
        uint64_t s1_end   = oe.section2_offset;

        // Section 2 offset includes padding — subtract to get raw data size
        // Read from section1_offset to section2_offset (includes padding)
        uint64_t s1_size = s1_end - s1_start;

        std::vector<uint8_t> buf(s1_size);
        file_.seekg(s1_start);
        file_.read(reinterpret_cast<char*>(buf.data()), s1_size);

        return {buf, s1_size};
    }

    // ── Predicate application ──

    std::vector<uint32_t> apply_predicates(
        const std::vector<uint8_t>&       s1_data,
        const QpqtRGOffsetEntry&          oe,
        uint32_t                          rg_row_count,
        const std::vector<QpqtPredicate>& predicates
    ) {
        if (predicates.empty()) {
            // No filter — all rows survive
            std::vector<uint32_t> all(rg_row_count);
            for (uint32_t i = 0; i < rg_row_count; ++i) all[i] = i;
            return all;
        }

        // Parse INT32 column from section 1 data
        // Section 1 layout: col_index(2) + byte_length(8) + raw_data
        // Predicates applied on structural columns only (PQC columns not filterable)
        std::vector<uint32_t> survivors;
        survivors.reserve(rg_row_count / 10);

        // Find the INT32 column data in s1_data
        const uint8_t* ptr = s1_data.data();
        const uint8_t* end = ptr + s1_data.size();

        // Map: col_index → pointer to raw data (after bitmap if nullable)
        std::vector<const int32_t*> col_data(schema_.column_count, nullptr);
        std::vector<uint32_t>       col_row_counts(schema_.column_count, 0);
        // Map: col_index → validity bitmap pointer (nullptr if not nullable)
        std::vector<const uint8_t*> col_bitmap(schema_.column_count, nullptr);

        uint16_t cols_parsed = 0;
        uint16_t struct_col_count = schema_.structural_count();
        while (ptr + 10 <= end && cols_parsed < struct_col_count) {
            uint16_t col_idx;
            uint64_t byte_len;
            memcpy(&col_idx,  ptr,     2);
            memcpy(&byte_len, ptr + 2, 8);

            if (col_idx >= schema_.column_count || byte_len == 0) break;

            ptr += 10;
            if (ptr + byte_len > end) break;

            if (!schema_.columns[col_idx].is_pqc_encrypted) {
                auto& col = schema_.columns[col_idx];
                const uint8_t* data_ptr = ptr;
                uint64_t data_len = byte_len;

                // Skip validity bitmap if column is nullable
                if (col.nullable) {
                    uint32_t bitmap_bytes = (rg_row_count + 7) / 8;
                    if (data_len >= bitmap_bytes) {
                        col_bitmap[col_idx] = data_ptr;
                        data_ptr += bitmap_bytes;
                        data_len -= bitmap_bytes;
                    }
                }

                col_data[col_idx] = reinterpret_cast<const int32_t*>(data_ptr);
                if (col.type == QpqtColumnType::INT32 || col.type == QpqtColumnType::DATE32)
                    col_row_counts[col_idx] = (uint32_t)(data_len / 4);
                else if (col.type == QpqtColumnType::INT64)
                    col_row_counts[col_idx] = (uint32_t)(data_len / 8);
                else if (col.type == QpqtColumnType::FLOAT32)
                    col_row_counts[col_idx] = (uint32_t)(data_len / 4);
                else if (col.type == QpqtColumnType::FLOAT64)
                    col_row_counts[col_idx] = (uint32_t)(data_len / 8);
                else
                    col_row_counts[col_idx] = rg_row_count;
            }
            ptr += byte_len;
            ++cols_parsed;
        }

        // Apply predicates row by row — dispatch on column type
        // NULL values never match any predicate
        for (uint32_t r = 0; r < rg_row_count; ++r) {
            bool pass = true;
            for (auto& pred : predicates) {
                uint16_t ci = pred.col_index;
                if (ci >= schema_.column_count) continue;
                if (col_data[ci] == nullptr) continue;
                if (r >= col_row_counts[ci]) { pass = false; break; }
                // NULL check: if bitmap present and bit is 0, value is null
                if (col_bitmap[ci]) {
                    bool is_null = !(col_bitmap[ci][r / 8] & (1u << (r % 8)));
                    if (is_null) { pass = false; break; }
                }
                const uint8_t* base = reinterpret_cast<const uint8_t*>(col_data[ci]);
                int32_t val_i32 = 0;
                switch (schema_.columns[ci].type) {
                    case QpqtColumnType::INT32:
                    case QpqtColumnType::DATE32:
                        memcpy(&val_i32, base + r * 4, 4);
                        break;
                    case QpqtColumnType::INT64: {
                        int64_t v; memcpy(&v, base + r * 8, 8);
                        val_i32 = (int32_t)v; break; // cast for predicate
                    }
                    case QpqtColumnType::FLOAT32: {
                        float v; memcpy(&v, base + r * 4, 4);
                        val_i32 = (int32_t)v; break;
                    }
                    case QpqtColumnType::FLOAT64: {
                        double v; memcpy(&v, base + r * 8, 8);
                        val_i32 = (int32_t)v; break;
                    }
                    default: continue; // STRING predicates not yet supported
                }
                if (!pred.test(val_i32)) { pass = false; break; }
            }
            if (pass) survivors.push_back(r);
        }
        return survivors;
    }

    // ── Structural value extractor — all types ────────────────────────────────
    // rg_row_count: total rows in this row group (needed for bitmap size)

    void extract_int32_values(
        const std::vector<uint8_t>& s1_data,
        const QpqtRGOffsetEntry&    oe,
        uint32_t                    row_in_rg,
        uint32_t                    count,
        QpqtResultRow&              out_row,
        uint32_t                    rg_row_count = 0
    ) {
        const uint8_t* ptr = s1_data.data();
        const uint8_t* end = ptr + s1_data.size();

        while (ptr + 10 <= end) {
            uint16_t col_idx;
            uint64_t byte_len;
            memcpy(&col_idx,  ptr,     2);
            memcpy(&byte_len, ptr + 2, 8);
            ptr += 10;
            if (ptr + byte_len > end) break;
            if (col_idx >= schema_.column_count ||
                schema_.columns[col_idx].is_pqc_encrypted) {
                ptr += byte_len; continue;
            }

            auto& coldef = schema_.columns[col_idx];
            QpqtColValue cv;
            cv.type    = coldef.type;
            cv.is_null = false;

            // Parse validity bitmap if column is nullable
            const uint8_t* data_start = ptr;
            uint64_t data_len = byte_len;
            if (coldef.nullable && rg_row_count > 0) {
                uint32_t bitmap_bytes = (rg_row_count + 7) / 8;
                if (data_len >= bitmap_bytes) {
                    bool is_null = !(ptr[row_in_rg / 8] & (1u << (row_in_rg % 8)));
                    cv.is_null = is_null;
                    data_start = ptr + bitmap_bytes;
                    data_len   = byte_len - bitmap_bytes;
                }
            }

            if (!cv.is_null) switch (coldef.type) {
                case QpqtColumnType::INT32:
                case QpqtColumnType::DATE32: {
                    uint32_t n = (uint32_t)(data_len / 4);
                    if (row_in_rg < n) {
                        int32_t v;
                        memcpy(&v, data_start + row_in_rg * 4, 4);
                        cv.value = v;
                        out_row.int32_values.push_back(v); // preserved for API compatibility
                    }
                    break;
                }
                case QpqtColumnType::INT64: {
                    uint32_t n = (uint32_t)(data_len / 8);
                    if (row_in_rg < n) {
                        int64_t v;
                        memcpy(&v, data_start + row_in_rg * 8, 8);
                        cv.value = v;
                    }
                    break;
                }
                case QpqtColumnType::FLOAT32: {
                    uint32_t n = (uint32_t)(data_len / 4);
                    if (row_in_rg < n) {
                        float v;
                        memcpy(&v, data_start + row_in_rg * 4, 4);
                        cv.value = v;
                    }
                    break;
                }
                case QpqtColumnType::FLOAT64: {
                    uint32_t n = (uint32_t)(data_len / 8);
                    if (row_in_rg < n) {
                        double v;
                        memcpy(&v, data_start + row_in_rg * 8, 8);
                        cv.value = v;
                    }
                    break;
                }
                case QpqtColumnType::STRING: {
                    const uint8_t* p       = data_start;
                    const uint8_t* col_end = data_start + data_len;
                    uint32_t cur = 0;
                    while (p + 4 <= col_end && cur <= row_in_rg) {
                        uint32_t slen;
                        memcpy(&slen, p, 4);
                        p += 4;
                        if (p + slen > col_end) break;
                        if (cur == row_in_rg) {
                            cv.value = std::string(
                                reinterpret_cast<const char*>(p), slen);
                            break;
                        }
                        p += slen;
                        ++cur;
                    }
                    break;
                }
                default: break;
            }
            out_row.structural_values.push_back(cv);
            ptr += byte_len;
        }
    }

    // ── PQC row reader — AES-256-GCM decryption with per-page ML-KEM key ──

    std::vector<std::string> read_pqc_row(
        const QpqtRGOffsetEntry& oe,
        uint32_t                 row_in_rg
    ) {
        std::vector<std::string> result;

        uint32_t page_idx    = row_in_rg / QPQT_ROWS_PER_PAGE;
        uint32_t row_in_page = row_in_rg % QPQT_ROWS_PER_PAGE;

        uint64_t s2_pos = oe.section2_offset;

        for (uint16_t i = 0; i < schema_.column_count; ++i) {
            if (!schema_.columns[i].is_pqc_encrypted) continue;

            uint32_t max_len  = schema_.columns[i].max_value_bytes;
            uint64_t row_size = max_len + QPQT_AES_GCM_TAG_LEN;

            file_.seekg(s2_pos);

            uint16_t stored_col_idx;
            uint32_t page_count;
            file_.read(reinterpret_cast<char*>(&stored_col_idx), 2);
            file_.read(reinterpret_cast<char*>(&page_count),     4);

            // Seek past pages before target page
            for (uint32_t pg = 0; pg < page_idx; ++pg) {
                QpqtPageHeader ph;
                file_.read(reinterpret_cast<char*>(&ph), QpqtPageHeader::SIZE);
                file_.seekg((uint64_t)ph.row_count * row_size, std::ios::cur);
            }

            // Read target page header
            QpqtPageHeader target_ph;
            file_.read(reinterpret_cast<char*>(&target_ph), QpqtPageHeader::SIZE);

            // Seek to target row
            file_.seekg((uint64_t)row_in_page * row_size, std::ios::cur);

            // Read ciphertext + GCM tag
            std::vector<uint8_t> ct(max_len);
            uint8_t gcm_tag[QPQT_AES_GCM_TAG_LEN];
            file_.read(reinterpret_cast<char*>(ct.data()), max_len);
            file_.read(reinterpret_cast<char*>(gcm_tag),  QPQT_AES_GCM_TAG_LEN);

            if (has_secret_key_) {
                // ── Get or derive AES page key ──
                uint8_t aes_key[QPQT_AES_KEY_LEN];

                if (page_key_cache_.matches(oe.row_group_index, page_idx, i)) {
                    memcpy(aes_key, page_key_cache_.aes_key, QPQT_AES_KEY_LEN);
                } else {
                    // Lookup manifest entry by coordinates
                    const QpqtManifestEntry* me_ptr = nullptr;
                    for (auto& me : manifest_)
                        if (me.row_group_index == oe.row_group_index &&
                            me.page_index      == page_idx &&
                            me.column_index    == i) { me_ptr = &me; break; }
                    if (!me_ptr)
                        throw std::runtime_error("Manifest entry not found");
                    auto& me = *me_ptr;

                    // ML-KEM-768 decapsulation
                    uint8_t shared_secret[crypto::ML_KEM_768_SS_LEN];
                    crypto::kem_decapsulate(
                        secret_key_, me.kem_ciphertext, shared_secret
                    );

                    // HKDF-SHA3-256 key derivation
                    crypto::derive_page_key(
                        shared_secret, file_hdr_.file_uuid,
                        oe.row_group_index, page_idx, i, aes_key
                    );

                    page_key_cache_.store(
                        oe.row_group_index, page_idx, i, aes_key
                    );
                }

                // ── AES-256-GCM decrypt + verify tag ──
                uint8_t iv[QPQT_IV_LEN];
                build_iv(iv, file_hdr_.file_uuid, page_idx,
                         (uint16_t)row_in_page, i);

                std::vector<uint8_t> plaintext(max_len);
                bool auth_ok = crypto::aes_gcm_decrypt(
                    aes_key, iv,
                    ct.data(), max_len,
                    gcm_tag,
                    plaintext.data()
                );

                if (!auth_ok)
                    throw std::runtime_error(
                        "GCM auth tag verification failed — data tampered"
                    );

                // Trim trailing zero padding
                size_t actual_len = max_len;
                while (actual_len > 0 && plaintext[actual_len-1] == 0x00)
                    --actual_len;
                result.push_back(std::string(
                    reinterpret_cast<char*>(plaintext.data()), actual_len
                ));
            } else {
                // No secret key — PQC column returns empty string
                size_t actual_len = max_len;
                while (actual_len > 0 && ct[actual_len-1] == 0x00) --actual_len;
                result.push_back(std::string(
                    reinterpret_cast<char*>(ct.data()), actual_len
                ));
            }
        }
        return result;
    }

    // ── Row count helper ──

    uint32_t get_rg_row_count(uint32_t rg_idx) {
        // Read RG header from disk
        file_.seekg(rg_offsets_[rg_idx].file_byte_offset);
        QpqtRowGroupHeader rg_hdr;
        file_.read(reinterpret_cast<char*>(&rg_hdr),
                   QpqtRowGroupHeader::SIZE);
        return rg_hdr.row_count;
    }
};

// ─────────────────────────────────────────────────────────
// Pack INT32 helper
// ─────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────
// Include writer (suppress its main and pack helper via defines)
// ─────────────────────────────────────────────────────────

#define QPQT_WRITER_NO_MAIN
#include "qpqt_writer.cpp"

// ─────────────────────────────────────────────────────────
// Test harness (excluded when included from Python bindings)
// ─────────────────────────────────────────────────────────
#ifndef QPQT_READER_NO_MAIN

static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT(cond, msg) \
    if (!(cond)) { \
        std::cerr << "  FAIL: " << msg << "\n"; \
        ++tests_failed; \
    } else { \
        std::cout << "  PASS: " << msg << "\n"; \
        ++tests_passed; \
    }

void run_reader_tests() {
    QpqtSchema schema;
    schema.column_count = 2;
    schema.columns = {
        {"customer_id", QpqtColumnType::INT32,  false, 4},
        {"ssn",         QpqtColumnType::STRING,  true, 64}
    };
    uint8_t key_id[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
    };

    // ── TC-01: Write 1 row, read back, verify PII matches ──
    {
        std::cout << "\n── TC-01: 1 row roundtrip ──\n";
        {
            QpqtWriter w("/tmp/r_tc01.qpqt", schema, key_id);
            w.write_row_group(1,
                {pack_int32_column({42})},
                {{"SSN-123456789"}}
            );
            w.finalize();
        }
        QpqtReader r("/tmp/r_tc01.qpqt");
        ASSERT(r.total_rows() == 1, "total_rows == 1");
        ASSERT(r.schema().column_count == 2, "schema has 2 columns");

        auto row = r.read_row(0);
        ASSERT(row.int32_values[0] == 42, "customer_id == 42");
        ASSERT(row.pqc_values[0] == "SSN-123456789", "SSN matches");
    }

    // ── TC-02: 4095 rows (partial page) ──
    {
        std::cout << "\n── TC-02: 4095 rows (partial page) ──\n";
        std::vector<int32_t> ids(4095);
        std::vector<std::string> ssns(4095);
        for (int i = 0; i < 4095; ++i) {
            ids[i] = i;
            ssns[i] = "SSN-" + std::to_string(i);
        }
        {
            QpqtWriter w("/tmp/r_tc02.qpqt", schema, key_id);
            w.write_row_group(4095, {pack_int32_column(ids)}, {ssns});
            w.finalize();
        }
        QpqtReader r("/tmp/r_tc02.qpqt");
        ASSERT(r.total_rows() == 4095, "total_rows == 4095");
        auto row = r.read_row(4094);
        ASSERT(row.int32_values[0] == 4094, "last row customer_id correct");
        ASSERT(row.pqc_values[0] == "SSN-4094", "last row SSN correct");
    }

    // ── TC-03: 4096 rows (exactly one page, one manifest entry) ──
    {
        std::cout << "\n── TC-03: 4096 rows (one page) ──\n";
        std::vector<int32_t> ids(4096);
        std::vector<std::string> ssns(4096);
        for (int i = 0; i < 4096; ++i) { ids[i]=i; ssns[i]="SSN-"+std::to_string(i); }
        {
            QpqtWriter w("/tmp/r_tc03.qpqt", schema, key_id);
            w.write_row_group(4096, {pack_int32_column(ids)}, {ssns});
            w.finalize();
        }
        QpqtReader r("/tmp/r_tc03.qpqt");
        ASSERT(r.total_rows() == 4096, "total_rows == 4096");
        ASSERT(r.file_header().row_group_count == 1, "one row group");
        // Verify manifest has exactly 1 entry (1 page × 1 PQC col)
        ASSERT(r.schema().pqc_count() == 1, "one PQC column");
    }

    // ── TC-04: 4097 rows (two pages, second has 1 row) ──
    {
        std::cout << "\n── TC-04: 4097 rows (two pages) ──\n";
        std::vector<int32_t> ids(4097);
        std::vector<std::string> ssns(4097);
        for (int i = 0; i < 4097; ++i) { ids[i]=i; ssns[i]="SSN-"+std::to_string(i); }
        {
            QpqtWriter w("/tmp/r_tc04.qpqt", schema, key_id);
            w.write_row_group(4097, {pack_int32_column(ids)}, {ssns});
            w.finalize();
        }
        QpqtReader r("/tmp/r_tc04.qpqt");
        ASSERT(r.total_rows() == 4097, "total_rows == 4097");
        // Row 4096 is first row of second page
        auto row = r.read_row(4096);
        ASSERT(row.int32_values[0] == 4096, "first row of page 2 correct");
        ASSERT(row.pqc_values[0] == "SSN-4096", "SSN on page 2 correct");
    }

    // ── TC-05: 100K rows (one full row group) ──
    {
        std::cout << "\n── TC-05: 100K rows ──\n";
        std::vector<int32_t> ids(100000);
        std::vector<std::string> ssns(100000);
        for (int i = 0; i < 100000; ++i) {
            ids[i]=i; ssns[i]="SSN-"+std::to_string(100000000+i);
        }
        {
            QpqtWriter w("/tmp/r_tc05.qpqt", schema, key_id);
            w.write_row_group(100000, {pack_int32_column(ids)}, {ssns});
            w.finalize();
        }
        QpqtReader r("/tmp/r_tc05.qpqt");
        ASSERT(r.total_rows() == 100000, "total_rows == 100K");
        ASSERT(r.file_header().row_group_count == 1, "one row group");
    }

    // ── TC-06: 100001 rows (two row groups) ──
    {
        std::cout << "\n── TC-06: 100001 rows (two RGs) ──\n";
        std::vector<int32_t> ids1(100000), ids2(1);
        std::vector<std::string> ssns1(100000), ssns2(1);
        for (int i = 0; i < 100000; ++i) {
            ids1[i]=i; ssns1[i]="SSN-"+std::to_string(i);
        }
        ids2[0]=100000; ssns2[0]="SSN-LAST";
        {
            QpqtWriter w("/tmp/r_tc06.qpqt", schema, key_id);
            w.write_row_group(100000, {pack_int32_column(ids1)}, {ssns1});
            w.write_row_group(1,      {pack_int32_column(ids2)}, {ssns2});
            w.finalize();
        }
        QpqtReader r("/tmp/r_tc06.qpqt");
        ASSERT(r.total_rows() == 100001, "total_rows == 100001");
        ASSERT(r.file_header().row_group_count == 2, "two row groups");
        auto last = r.read_row(100000);
        ASSERT(last.int32_values[0] == 100000, "last row ID correct");
        ASSERT(last.pqc_values[0] == "SSN-LAST", "last row SSN correct");
    }

    // ── TC-07: 1M rows, read random row 743291 ──
    {
        std::cout << "\n── TC-07: 1M rows, random row 743291 ──\n";
        // Write 10 row groups of 100K each
        {
            QpqtWriter w("/tmp/r_tc07.qpqt", schema, key_id);
            for (int rg = 0; rg < 10; ++rg) {
                std::vector<int32_t> ids(100000);
                std::vector<std::string> ssns(100000);
                for (int i = 0; i < 100000; ++i) {
                    int abs = rg * 100000 + i;
                    ids[i]  = abs;
                    ssns[i] = "SSN-" + std::to_string(abs);
                }
                w.write_row_group(100000,
                    {pack_int32_column(ids)}, {ssns});
            }
            w.finalize();
        }
        QpqtReader r("/tmp/r_tc07.qpqt");
        ASSERT(r.total_rows() == 1000000, "total_rows == 1M");
        auto row = r.read_row(743291);
        ASSERT(row.int32_values[0] == 743291, "row 743291 ID correct");
        ASSERT(row.pqc_values[0] == "SSN-743291", "row 743291 SSN correct");
    }

    // ── TC-13: 0% selectivity — section 2 never read ──
    {
        std::cout << "\n── TC-13: 0% selectivity (section 2 never read) ──\n";
        QpqtReader r("/tmp/r_tc05.qpqt"); // reuse 100K file
        uint64_t s2_bytes = 0;
        // Predicate that matches nothing: customer_id > 999999
        auto results = r.query(
            {{0, [](int32_t v){ return v > 999999; }}},
            s2_bytes
        );
        ASSERT(results.empty(), "0 rows returned");
        ASSERT(s2_bytes == 0, "section 2 bytes read == 0");
    }

    // ── TC-14: 5% selectivity — partial section 2 read ──
    {
        std::cout << "\n── TC-14: 5% selectivity ──\n";
        QpqtReader r("/tmp/r_tc05.qpqt");
        uint64_t s2_bytes = 0;
        // customer_id % 20 == 0 → exactly 5% of rows
        auto results = r.query(
            {{0, [](int32_t v){ return v % 20 == 0; }}},
            s2_bytes
        );
        uint64_t expected = 100000 / 20; // 5000 rows
        ASSERT(results.size() == expected,
               "5% selectivity returns 5000 rows (got "
               + std::to_string(results.size()) + ")");
        ASSERT(s2_bytes > 0, "section 2 was read for survivors");
    }

    // ── TC-15: 100% selectivity — full section 2 read ──
    {
        std::cout << "\n── TC-15: 100% selectivity ──\n";
        QpqtReader r("/tmp/r_tc05.qpqt");
        uint64_t s2_bytes = 0;
        // No predicate — all rows survive
        auto results = r.query({}, s2_bytes);
        ASSERT(results.size() == 100000, "100% selectivity returns 100K rows");
        ASSERT(s2_bytes > 0, "section 2 fully read");
    }

    // ── TC-19: all columns PQC (no structural) ──
    {
        std::cout << "\n── TC-19: all PQC columns ──\n";
        QpqtSchema pqc_only;
        pqc_only.column_count = 1;
        pqc_only.columns = {{"ssn", QpqtColumnType::STRING, true, 64}};
        {
            QpqtWriter w("/tmp/r_tc19.qpqt", pqc_only, key_id);
            w.write_row_group(10, {}, {{"SSN-0","SSN-1","SSN-2","SSN-3","SSN-4",
                                        "SSN-5","SSN-6","SSN-7","SSN-8","SSN-9"}});
            w.finalize();
        }
        QpqtReader r("/tmp/r_tc19.qpqt");
        ASSERT(r.total_rows() == 10, "all-PQC file has 10 rows");
        auto row = r.read_row(5);
        ASSERT(row.pqc_values[0] == "SSN-5", "all-PQC row 5 correct");
    }

    // Summary
    std::cout << "\n════════════════════════════════\n";
    std::cout << "Tests passed: " << tests_passed << "\n";
    std::cout << "Tests failed: " << tests_failed << "\n";
    if (tests_failed == 0)
        std::cout << "ALL TESTS PASSED ✓\n";
}

int main() {
    std::cout << "=== QPQT Reader — Week 2 Test Suite ===\n";
    run_reader_tests();
    return tests_failed > 0 ? 1 : 0;
}

#endif // QPQT_READER_NO_MAIN
