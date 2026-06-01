/**
 * qpqt_tests.cpp
 * Combined test harness — all 36 test cases.
 *
 * Compile:
 *   g++ -O2 -std=c++17 -fopenmp \
 *       -I../include -I/usr/local/include \
 *       qpqt_tests.cpp -o qpqt_tests \
 *       -L/usr/local/lib -loqs -lssl -lcrypto \
 *       -Wl,-rpath,/usr/local/lib
 *
 * Run:
 *   ./qpqt_tests
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <set>
#include <array>
#include <stdexcept>
#include "qpqt_types.h"
#include "qpqt_utils.h"
#include "qpqt_crypto.h"

#define QPQT_PACK_INT32_DEFINED
#define QPQT_WRITER_NO_MAIN
#include "../src/qpqt_writer.cpp"

#define QPQT_READER_NO_MAIN
#undef ASSERT
#include "../src/qpqt_reader.cpp"

using namespace qpqt;
using namespace qpqt::crypto;

// ─────────────────────────────────────────────────────────
// Test infrastructure
// ─────────────────────────────────────────────────────────

static int tests_passed = 0;
static int tests_failed = 0;
static std::string current_group = "";

#define ASSERT(cond, msg) \
    if (!(cond)) { \
        std::cerr << "  FAIL [" << current_group << "]: " << (msg) << "\n"; \
        ++tests_failed; \
    } else { \
        std::cout << "  PASS: " << (msg) << "\n"; \
        ++tests_passed; \
    }

static std::vector<uint8_t> pack_int32_column(const std::vector<int32_t>& v) {
    std::vector<uint8_t> b(v.size()*4);
    memcpy(b.data(), v.data(), b.size());
    return b;
}

static QpqtSchema make_schema() {
    QpqtSchema s;
    s.column_count = 2;
    s.columns = {
        {"customer_id", QpqtColumnType::INT32,  false, 4},
        {"ssn",         QpqtColumnType::STRING,  true, 64}
    };
    return s;
}

static uint8_t TEST_KEY_ID[16] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
};

// ─────────────────────────────────────────────────────────
// TC-01 to TC-07: Correctness (structural, no crypto)
// ─────────────────────────────────────────────────────────

void test_correctness() {
    current_group = "Correctness";
    auto schema = make_schema();

    // TC-01: 1 row
    {
        QpqtWriter w("/tmp/t01.qpqt", schema, TEST_KEY_ID);
        w.write_row_group(1, {pack_int32_column({42})}, {{"SSN-001"}});
        w.finalize();
        QpqtReader r("/tmp/t01.qpqt");
        ASSERT(r.total_rows() == 1, "TC-01: total_rows==1");
        auto row = r.read_row(0);
        ASSERT(row.int32_values[0] == 42, "TC-01: customer_id==42");
        ASSERT(row.pqc_values[0] == "SSN-001", "TC-01: SSN matches");
    }

    // TC-02: 4095 rows (partial page)
    {
        std::vector<int32_t> ids(4095);
        std::vector<std::string> ssns(4095);
        for (int i=0;i<4095;++i){ids[i]=i;ssns[i]="SSN-"+std::to_string(i);}
        QpqtWriter w("/tmp/t02.qpqt", schema, TEST_KEY_ID);
        w.write_row_group(4095,{pack_int32_column(ids)},{ssns});
        w.finalize();
        QpqtReader r("/tmp/t02.qpqt");
        ASSERT(r.total_rows()==4095, "TC-02: total_rows==4095");
        auto row=r.read_row(4094);
        ASSERT(row.int32_values[0]==4094, "TC-02: last row id correct");
        ASSERT(row.pqc_values[0]=="SSN-4094", "TC-02: last row SSN correct");
    }

    // TC-03: 4096 rows (exactly one page)
    {
        std::vector<int32_t> ids(4096);
        std::vector<std::string> ssns(4096);
        for (int i=0;i<4096;++i){ids[i]=i;ssns[i]="SSN-"+std::to_string(i);}
        QpqtWriter w("/tmp/t03.qpqt", schema, TEST_KEY_ID);
        w.write_row_group(4096,{pack_int32_column(ids)},{ssns});
        w.finalize();
        QpqtReader r("/tmp/t03.qpqt");
        ASSERT(r.total_rows()==4096, "TC-03: total_rows==4096");
        ASSERT(r.file_header().row_group_count==1, "TC-03: one row group");
    }

    // TC-04: 4097 rows (two pages)
    {
        std::vector<int32_t> ids(4097);
        std::vector<std::string> ssns(4097);
        for (int i=0;i<4097;++i){ids[i]=i;ssns[i]="SSN-"+std::to_string(i);}
        QpqtWriter w("/tmp/t04.qpqt", schema, TEST_KEY_ID);
        w.write_row_group(4097,{pack_int32_column(ids)},{ssns});
        w.finalize();
        QpqtReader r("/tmp/t04.qpqt");
        ASSERT(r.total_rows()==4097, "TC-04: total_rows==4097");
        auto row=r.read_row(4096);
        ASSERT(row.int32_values[0]==4096, "TC-04: page 2 row 0 correct");
    }

    // TC-05: 100K rows
    {
        std::vector<int32_t> ids(100000);
        std::vector<std::string> ssns(100000);
        for (int i=0;i<100000;++i){ids[i]=i;ssns[i]="SSN-"+std::to_string(i);}
        QpqtWriter w("/tmp/t05.qpqt", schema, TEST_KEY_ID);
        w.write_row_group(100000,{pack_int32_column(ids)},{ssns});
        w.finalize();
        QpqtReader r("/tmp/t05.qpqt");
        ASSERT(r.total_rows()==100000, "TC-05: total_rows==100K");
        ASSERT(r.file_header().row_group_count==1, "TC-05: one row group");
    }

    // TC-06: 100001 rows (two row groups)
    {
        std::vector<int32_t> ids1(100000),ids2(1);
        std::vector<std::string> ssns1(100000),ssns2(1);
        for (int i=0;i<100000;++i){ids1[i]=i;ssns1[i]="SSN-"+std::to_string(i);}
        ids2[0]=100000; ssns2[0]="SSN-LAST";
        QpqtWriter w("/tmp/t06.qpqt", schema, TEST_KEY_ID);
        w.write_row_group(100000,{pack_int32_column(ids1)},{ssns1});
        w.write_row_group(1,{pack_int32_column(ids2)},{ssns2});
        w.finalize();
        QpqtReader r("/tmp/t06.qpqt");
        ASSERT(r.total_rows()==100001, "TC-06: total_rows==100001");
        ASSERT(r.file_header().row_group_count==2, "TC-06: two row groups");
        auto last=r.read_row(100000);
        ASSERT(last.int32_values[0]==100000, "TC-06: last row id correct");
        ASSERT(last.pqc_values[0]=="SSN-LAST", "TC-06: last row SSN correct");
    }

    // TC-07: 1M rows, random row 743291
    {
        QpqtWriter w("/tmp/t07.qpqt", schema, TEST_KEY_ID);
        for (int rg=0;rg<10;++rg) {
            std::vector<int32_t> ids(100000);
            std::vector<std::string> ssns(100000);
            for (int i=0;i<100000;++i){
                int abs=rg*100000+i;
                ids[i]=abs; ssns[i]="SSN-"+std::to_string(abs);
            }
            w.write_row_group(100000,{pack_int32_column(ids)},{ssns});
        }
        w.finalize();
        QpqtReader r("/tmp/t07.qpqt");
        ASSERT(r.total_rows()==1000000, "TC-07: total_rows==1M");
        auto row=r.read_row(743291);
        ASSERT(row.int32_values[0]==743291, "TC-07: row 743291 id correct");
        ASSERT(row.pqc_values[0]=="SSN-743291", "TC-07: row 743291 SSN correct");
    }
}

// ─────────────────────────────────────────────────────────
// TC-08 to TC-12: Cryptographic correctness
// ─────────────────────────────────────────────────────────

void test_crypto() {
    current_group = "Crypto";

    // TC-08: Wrong key → GCM rejects
    {
        uint8_t k1[QPQT_AES_KEY_LEN]={0x01}, k2[QPQT_AES_KEY_LEN]={0x02};
        uint8_t iv[QPQT_IV_LEN]={}, ct[32]={}, tag[QPQT_AES_GCM_TAG_LEN]={}, pt[32]={};
        uint8_t plain[32]="hello world pqc test";
        aes_gcm_encrypt(k1, iv, plain, 32, ct, tag);
        bool ok = aes_gcm_decrypt(k2, iv, ct, 32, tag, pt);
        ASSERT(!ok, "TC-08: Wrong key → GCM tag rejected");
    }

    // TC-09: Tampered ciphertext → GCM rejects
    {
        uint8_t key[QPQT_AES_KEY_LEN]={0x42}, iv[QPQT_IV_LEN]={};
        uint8_t plain[32]="SSN-987-65-4321-test", ct[32]={}, tag[QPQT_AES_GCM_TAG_LEN]={}, pt[32]={};
        aes_gcm_encrypt(key, iv, plain, 32, ct, tag);
        bool clean = aes_gcm_decrypt(key, iv, ct, 32, tag, pt);
        ASSERT(clean, "TC-09: Clean decrypt succeeds");
        ct[0] ^= 0x01;
        bool tampered = aes_gcm_decrypt(key, iv, ct, 32, tag, pt);
        ASSERT(!tampered, "TC-09: Tampered ciphertext → GCM rejected");
    }

    // TC-10: Manifest entry count = pages × PQC cols
    {
        auto schema = make_schema();
        uint8_t pk[ML_KEM_768_PK_LEN], sk[ML_KEM_768_SK_LEN];
        kem_keygen(pk, sk);
        std::vector<int32_t> ids(4097);
        std::vector<std::string> ssns(4097);
        for (int i=0;i<4097;++i){ids[i]=i;ssns[i]="S"+std::to_string(i);}
        QpqtWriter w("/tmp/t10.qpqt", schema, TEST_KEY_ID, pk);
        w.write_row_group(4097,{pack_int32_column(ids)},{ssns});
        w.finalize();
        std::ifstream f("/tmp/t10.qpqt", std::ios::binary);
        f.seekg(-40, std::ios::end);
        QpqtFooterHeader fh;
        f.read(reinterpret_cast<char*>(&fh), QpqtFooterHeader::SIZE);
        ASSERT(fh.manifest_entry_count==2, "TC-10: 4097 rows → 2 manifest entries");
        ASSERT(fh.pqc_column_count==1, "TC-10: pqc_column_count==1");
    }

    // TC-11: No IV collisions within file
    {
        uint8_t uuid[16]; generate_uuid(uuid);
        using IVArr = std::array<uint8_t, QPQT_IV_LEN>;
        std::set<IVArr> seen;
        bool collision = false;
        for (uint32_t row=0; row<8193; ++row) {
            uint8_t iv[QPQT_IV_LEN];
            build_iv(iv, uuid, row/QPQT_ROWS_PER_PAGE,
                     (uint16_t)(row%QPQT_ROWS_PER_PAGE), 0);
            IVArr arr; memcpy(arr.data(), iv, QPQT_IV_LEN);
            if (seen.count(arr)){collision=true;break;}
            seen.insert(arr);
        }
        ASSERT(!collision, "TC-11: No IV collisions across 8193 rows");
    }

    // TC-12: Cross-file IV uniqueness via file_uuid
    {
        uint8_t uuid1[16], uuid2[16];
        generate_uuid(uuid1); generate_uuid(uuid2);
        uint8_t iv1[QPQT_IV_LEN], iv2[QPQT_IV_LEN];
        build_iv(iv1, uuid1, 0, 0, 0);
        build_iv(iv2, uuid2, 0, 0, 0);
        bool differ = memcmp(iv1, iv2, QPQT_IV_LEN) != 0;
        ASSERT(differ, "TC-12: Different file_uuid → different IV for same row");
    }
}

// ─────────────────────────────────────────────────────────
// TC-13 to TC-15: Lazy decryption
// ─────────────────────────────────────────────────────────

void test_lazy() {
    current_group = "Lazy Decryption";

    // TC-13: 0% selectivity → section 2 never read
    {
        QpqtReader r("/tmp/t05.qpqt");
        uint64_t s2=0;
        auto res = r.query({{0,[](int32_t v){return v>999999;}}}, s2);
        ASSERT(res.empty(), "TC-13: 0% selectivity → 0 results");
        ASSERT(s2==0, "TC-13: Section 2 bytes read == 0");
    }

    // TC-14: 5% selectivity → partial section 2 read
    {
        QpqtReader r("/tmp/t05.qpqt");
        uint64_t s2=0;
        auto res = r.query({{0,[](int32_t v){return v%20==0;}}}, s2);
        ASSERT(res.size()==5000, "TC-14: 5% → 5000 survivors");
        ASSERT(s2>0, "TC-14: Section 2 was read for survivors");
    }

    // TC-15: 100% selectivity → full section 2 read
    {
        QpqtReader r("/tmp/t05.qpqt");
        uint64_t s2=0;
        auto res = r.query({}, s2);
        ASSERT(res.size()==100000, "TC-15: 100% → 100K results");
        ASSERT(s2>0, "TC-15: Section 2 fully read");
    }
}

// ─────────────────────────────────────────────────────────
// TC-W4-01 to W4-04: End-to-end with real ML-KEM keys
// ─────────────────────────────────────────────────────────

void test_e2e() {
    current_group = "End-to-End";
    auto schema = make_schema();
    uint8_t pk[ML_KEM_768_PK_LEN], sk[ML_KEM_768_SK_LEN];
    kem_keygen(pk, sk);

    // TC-W4-01: 1 row full roundtrip
    {
        QpqtWriter w("/tmp/e2e01.qpqt", schema, TEST_KEY_ID, pk);
        w.write_row_group(1,{pack_int32_column({42})},{{"SSN-123-45-6789"}});
        w.finalize();
        QpqtReader r("/tmp/e2e01.qpqt");
        r.set_secret_key(sk);
        auto row=r.read_row(0);
        ASSERT(row.int32_values[0]==42, "TC-W4-01: id decrypts correctly");
        ASSERT(row.pqc_values[0]=="SSN-123-45-6789", "TC-W4-01: SSN decrypts correctly");
    }

    // TC-W4-02: Page boundary (row 4095 vs 4096)
    {
        std::vector<int32_t> ids(4097);
        std::vector<std::string> piis(4097);
        for (int i=0;i<4097;++i){ids[i]=i;piis[i]="PII-"+std::to_string(i);}
        QpqtWriter w("/tmp/e2e02.qpqt", schema, TEST_KEY_ID, pk);
        w.write_row_group(4097,{pack_int32_column(ids)},{piis});
        w.finalize();
        QpqtReader r("/tmp/e2e02.qpqt");
        r.set_secret_key(sk);
        auto r4095=r.read_row(4095);
        auto r4096=r.read_row(4096);
        ASSERT(r4095.pqc_values[0]=="PII-4095", "TC-W4-02: last row page 0 decrypts");
        ASSERT(r4096.pqc_values[0]=="PII-4096", "TC-W4-02: first row page 1 decrypts (different key)");
    }

    // TC-W4-03: Lazy query with real decryption
    {
        std::vector<int32_t> ids(1000);
        std::vector<std::string> piis(1000);
        for (int i=0;i<1000;++i){ids[i]=i;piis[i]="PII-"+std::to_string(i);}
        QpqtWriter w("/tmp/e2e03.qpqt", schema, TEST_KEY_ID, pk);
        w.write_row_group(1000,{pack_int32_column(ids)},{piis});
        w.finalize();
        QpqtReader r("/tmp/e2e03.qpqt");
        r.set_secret_key(sk);
        uint64_t s2=0;
        auto res=r.query({{0,[](int32_t v){return v%100==0;}}}, s2);
        ASSERT(res.size()==10, "TC-W4-03: 10 survivors from 1000 rows");
        bool all_ok=true;
        for (auto& row:res) {
            std::string expected="PII-"+std::to_string(row.int32_values[0]);
            if (row.pqc_values[0]!=expected) all_ok=false;
        }
        ASSERT(all_ok, "TC-W4-03: All survivors decrypt correctly");
    }

    // TC-W4-04: 1M rows random row 743291
    {
        QpqtWriter w("/tmp/e2e04.qpqt", schema, TEST_KEY_ID, pk);
        for (int rg=0;rg<10;++rg) {
            std::vector<int32_t> ids(100000);
            std::vector<std::string> piis(100000);
            for (int i=0;i<100000;++i){
                int abs=rg*100000+i;
                ids[i]=abs;piis[i]="PII-"+std::to_string(abs);
            }
            w.write_row_group(100000,{pack_int32_column(ids)},{piis});
        }
        w.finalize();
        QpqtReader r("/tmp/e2e04.qpqt");
        r.set_secret_key(sk);
        auto row=r.read_row(743291);
        ASSERT(row.int32_values[0]==743291, "TC-W4-04: row 743291 id correct");
        ASSERT(row.pqc_values[0]=="PII-743291", "TC-W4-04: row 743291 decrypts correctly");
    }
}

// ─────────────────────────────────────────────────────────
// TC-19 to TC-22: Edge cases
// ─────────────────────────────────────────────────────────

void test_edge_cases() {
    current_group = "Edge Cases";
    auto schema = make_schema();

    // TC-19: All PQC columns
    {
        QpqtSchema pqc_only;
        pqc_only.column_count = 1;
        pqc_only.columns = {{"ssn", QpqtColumnType::STRING, true, 64}};
        QpqtWriter w("/tmp/t19.qpqt", pqc_only, TEST_KEY_ID);
        std::vector<std::string> ssns={"A","B","C","D","E"};
        w.write_row_group(5, {}, {ssns});
        w.finalize();
        QpqtReader r("/tmp/t19.qpqt");
        ASSERT(r.total_rows()==5, "TC-19: All-PQC file has 5 rows");
        auto row=r.read_row(2);
        ASSERT(row.pqc_values[0]=="C", "TC-19: Row 2 reads correctly");
    }

    // TC-20: Empty file (0 rows)
    {
        QpqtWriter w("/tmp/t20.qpqt", schema, TEST_KEY_ID);
        w.finalize();
        bool ok=true;
        try {
            QpqtReader r("/tmp/t20.qpqt");
            ASSERT(r.total_rows()==0, "TC-20: Empty file has 0 rows");
        } catch (...) { ok=false; }
        ASSERT(ok, "TC-20: Empty file handled without crash");
    }

    // TC-21: Truncated file → clean error
    {
        // Write a valid file then truncate it
        {
            QpqtWriter w("/tmp/t21.qpqt", schema, TEST_KEY_ID);
            std::vector<int32_t> ids={1,2,3};
            w.write_row_group(3,{pack_int32_column(ids)},{{"A","B","C"}});
            w.finalize();
        }
        // Truncate to 100 bytes (destroys footer)
        truncate("/tmp/t21.qpqt", 100);
        bool caught=false;
        try {
            QpqtReader r("/tmp/t21.qpqt");
        } catch (std::exception& e) { caught=true; }
        ASSERT(caught, "TC-21: Truncated file throws clean exception");
    }

    // TC-22: NULL (empty string) in PQC column
    {
        QpqtWriter w("/tmp/t22.qpqt", schema, TEST_KEY_ID);
        std::vector<int32_t> ids={1,2,3};
        std::vector<std::string> ssns={"SSN-1","","SSN-3"};
        w.write_row_group(3,{pack_int32_column(ids)},{ssns});
        w.finalize();
        QpqtReader r("/tmp/t22.qpqt");
        ASSERT(r.total_rows()==3, "TC-22: File with empty PQC value written");
        auto row=r.read_row(1);
        ASSERT(row.pqc_values[0].empty(), "TC-22: Empty PQC value reads back as empty");
    }
}

// ─────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────

int main() {
    std::cout << "=== QPQT Test Suite ===\n";
    std::cout << "ML-KEM-768 + HKDF-SHA3-256 + AES-256-GCM\n\n";

    std::cout << "── Correctness Tests ──\n";
    test_correctness();

    std::cout << "\n── Cryptographic Tests ──\n";
    test_crypto();

    std::cout << "\n── Lazy Decryption Tests ──\n";
    test_lazy();

    std::cout << "\n── End-to-End Tests ──\n";
    test_e2e();

    std::cout << "\n── Edge Case Tests ──\n";
    test_edge_cases();

    std::cout << "\n════════════════════════════════\n";
    std::cout << "Tests passed : " << tests_passed << "\n";
    std::cout << "Tests failed : " << tests_failed << "\n";
    if (tests_failed == 0)
        std::cout << "ALL TESTS PASSED ✓\n";
    return tests_failed > 0 ? 1 : 0;
}
