/**
 * qpqt_tests.cpp
 * Combined test harness — 39 test cases.
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
#include <unistd.h>
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

    // Write a shared encrypted file for TC-13/14/15
    auto schema = make_schema();
    uint8_t pk[ML_KEM_768_PK_LEN], sk[ML_KEM_768_SK_LEN];
    kem_keygen(pk, sk);
    {
        std::vector<int32_t> ids(100000);
        std::vector<std::string> ssns(100000);
        for (int i = 0; i < 100000; ++i) { ids[i]=i; ssns[i]="SSN-"+std::to_string(i); }
        QpqtWriter w("/tmp/t_lazy.qpqt", schema, TEST_KEY_ID, pk);
        w.write_row_group(100000, {pack_int32_column(ids)}, {ssns});
        w.finalize();
    }

    // TC-13: 0% selectivity → section 2 never read
    {
        QpqtReader r("/tmp/t_lazy.qpqt");
        r.set_secret_key(sk);
        uint64_t s2=0;
        auto res = r.query({{0,[](int32_t v){return v>999999;}}}, s2);
        ASSERT(res.empty(), "TC-13: 0% selectivity → 0 results");
        ASSERT(s2==0, "TC-13: Section 2 bytes read == 0");
    }

    // TC-14: 5% selectivity → partial section 2 read
    {
        QpqtReader r("/tmp/t_lazy.qpqt");
        r.set_secret_key(sk);
        uint64_t s2=0;
        auto res = r.query({{0,[](int32_t v){return v%20==0;}}}, s2);
        ASSERT(res.size()==5000, "TC-14: 5% → 5000 survivors");
        ASSERT(s2>0, "TC-14: Section 2 was read for survivors");
    }

    // TC-15: 100% selectivity → full section 2 read
    {
        QpqtReader r("/tmp/t_lazy.qpqt");
        r.set_secret_key(sk);
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
        { int r = truncate("/tmp/t21.qpqt", 100); (void)r; }
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
// Key file helpers (mirrors CLI implementation)
// ─────────────────────────────────────────────────────────

static void write_key_file(const std::string& path,
                           const uint8_t* data, size_t len) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write key file: " + path);
    f.write(reinterpret_cast<const char*>(data), len);
}

static std::vector<uint8_t> read_key_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("Cannot read key file: " + path);
    size_t size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> data(size);
    f.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

// ─────────────────────────────────────────────────────────
// TC-KEYS: Key persistence — simulates real usage where
// write and read are separate processes with keys on disk
// ─────────────────────────────────────────────────────────

void test_key_persistence() {
    current_group = "Key Persistence";

    uint8_t pk[ML_KEM_768_PK_LEN], sk[ML_KEM_768_SK_LEN];
    kem_keygen(pk, sk);

    // TC-KEYS-01: Keys survive disk roundtrip
    {
        write_key_file("/tmp/test_pub.bin", pk, ML_KEM_768_PK_LEN);
        write_key_file("/tmp/test_sec.bin", sk, ML_KEM_768_SK_LEN);

        auto pk2 = read_key_file("/tmp/test_pub.bin");
        auto sk2 = read_key_file("/tmp/test_sec.bin");

        ASSERT(pk2.size() == ML_KEM_768_PK_LEN,
               "TC-KEYS-01: Public key file correct size");
        ASSERT(sk2.size() == ML_KEM_768_SK_LEN,
               "TC-KEYS-01: Secret key file correct size");
        ASSERT(memcmp(pk, pk2.data(), ML_KEM_768_PK_LEN) == 0,
               "TC-KEYS-01: Public key bytes survive disk roundtrip");
        ASSERT(memcmp(sk, sk2.data(), ML_KEM_768_SK_LEN) == 0,
               "TC-KEYS-01: Secret key bytes survive disk roundtrip");
    }

    // TC-KEYS-02: Encrypt with key loaded from disk,
    //             decrypt with key loaded from disk
    //             (separate load calls — simulates separate processes)
    {
        auto schema = make_schema();
        uint8_t key_id[16] = {0xAA,0xBB,0xCC,0xDD,
                              0xEE,0xFF,0x11,0x22,
                              0x33,0x44,0x55,0x66,
                              0x77,0x88,0x99,0x00};

        // WRITE PROCESS: load public key from disk, encrypt
        {
            auto pk_from_disk = read_key_file("/tmp/test_pub.bin");
            QpqtWriter w("/tmp/tc_keys.qpqt", schema,
                         key_id, pk_from_disk.data());
            w.write_row_group(3,
                {pack_int32_column({10, 20, 30})},
                {{"SSN-KEY-A", "SSN-KEY-B", "SSN-KEY-C"}}
            );
            w.finalize();
        }

        // READ PROCESS: load secret key from disk, decrypt
        {
            auto sk_from_disk = read_key_file("/tmp/test_sec.bin");
            QpqtReader r("/tmp/tc_keys.qpqt");
            r.set_secret_key(sk_from_disk.data());

            auto row0 = r.read_row(0);
            auto row1 = r.read_row(1);
            auto row2 = r.read_row(2);

            ASSERT(row0.int32_values[0] == 10,
                   "TC-KEYS-02: Row 0 structural correct");
            ASSERT(row0.pqc_values[0] == "SSN-KEY-A",
                   "TC-KEYS-02: Row 0 PII decrypts with disk-loaded key");
            ASSERT(row1.pqc_values[0] == "SSN-KEY-B",
                   "TC-KEYS-02: Row 1 PII decrypts with disk-loaded key");
            ASSERT(row2.pqc_values[0] == "SSN-KEY-C",
                   "TC-KEYS-02: Row 2 PII decrypts with disk-loaded key");
        }
    }

    // TC-KEYS-03: Wrong key file → GCM rejects cleanly
    {
        // Generate a second keypair — wrong keys
        uint8_t pk2[ML_KEM_768_PK_LEN], sk2[ML_KEM_768_SK_LEN];
        kem_keygen(pk2, sk2);
        write_key_file("/tmp/test_wrong_sec.bin", sk2, ML_KEM_768_SK_LEN);

        // Try to decrypt tc_keys.qpqt (encrypted with pk) using sk2
        auto wrong_sk = read_key_file("/tmp/test_wrong_sec.bin");
        QpqtReader r("/tmp/tc_keys.qpqt");
        r.set_secret_key(wrong_sk.data());

        bool caught = false;
        try {
            auto row = r.read_row(0);
            // If we get here without exception, check value is wrong
            // (ML-KEM decaps always returns something, but AES-GCM tag fails)
        } catch (std::exception& e) {
            caught = true;
        }
        ASSERT(caught,
               "TC-KEYS-03: Wrong key file → GCM auth tag throws exception");

        // Cleanup
        std::remove("/tmp/test_pub.bin");
        std::remove("/tmp/test_sec.bin");
        std::remove("/tmp/test_wrong_sec.bin");
        std::remove("/tmp/tc_keys.qpqt");
    }
}

// ─────────────────────────────────────────────────────────
// TC-TYPES: All column types + mixed schema
// ─────────────────────────────────────────────────────────

void test_all_types() {
    current_group = "All Types";

    uint8_t pk[ML_KEM_768_PK_LEN], sk[ML_KEM_768_SK_LEN];
    kem_keygen(pk, sk);
    uint8_t kid[16] = {};

    // TC-TYPES-01: INT64 structural column
    {
        QpqtSchema s;
        s.column_count = 1;
        s.columns = {{"ts", QpqtColumnType::INT64, false, 8}};
        std::vector<int64_t> vals = {INT64_MAX, 0LL, -1LL, 1234567890123LL};
        QpqtWriter w("/tmp/tt01.qpqt", s, kid);
        w.write_row_group(4, {pack_int64_column(vals)}, {});
        w.finalize();
        QpqtReader r("/tmp/tt01.qpqt");
        ASSERT(r.total_rows() == 4, "TC-TYPES-01: total_rows == 4");
        auto row = r.read_row(0);
        ASSERT(!row.structural_values.empty(), "TC-TYPES-01: structural_values populated");
        ASSERT(std::get<int64_t>(row.structural_values[0].value) == INT64_MAX,
               "TC-TYPES-01: INT64_MAX roundtrip");
        auto row3 = r.read_row(3);
        ASSERT(std::get<int64_t>(row3.structural_values[0].value) == 1234567890123LL,
               "TC-TYPES-01: large INT64 roundtrip");
    }

    // TC-TYPES-02: FLOAT32 structural column
    {
        QpqtSchema s;
        s.column_count = 1;
        s.columns = {{"score", QpqtColumnType::FLOAT32, false, 4}};
        std::vector<float> vals = {3.14f, -1.5f, 0.0f, 1e10f};
        QpqtWriter w("/tmp/tt02.qpqt", s, kid);
        w.write_row_group(4, {pack_float32_column(vals)}, {});
        w.finalize();
        QpqtReader r("/tmp/tt02.qpqt");
        auto row = r.read_row(0);
        float got = std::get<float>(row.structural_values[0].value);
        ASSERT(std::abs(got - 3.14f) < 0.001f, "TC-TYPES-02: FLOAT32 3.14 roundtrip");
        auto row1 = r.read_row(1);
        float got1 = std::get<float>(row1.structural_values[0].value);
        ASSERT(std::abs(got1 - (-1.5f)) < 0.001f, "TC-TYPES-02: FLOAT32 negative roundtrip");
    }

    // TC-TYPES-03: FLOAT64 structural column
    {
        QpqtSchema s;
        s.column_count = 1;
        s.columns = {{"lat", QpqtColumnType::FLOAT64, false, 8}};
        std::vector<double> vals = {51.5074, -0.1278, 40.7128, -74.0060};
        QpqtWriter w("/tmp/tt03.qpqt", s, kid);
        w.write_row_group(4, {pack_float64_column(vals)}, {});
        w.finalize();
        QpqtReader r("/tmp/tt03.qpqt");
        auto row = r.read_row(0);
        double got = std::get<double>(row.structural_values[0].value);
        ASSERT(std::abs(got - 51.5074) < 1e-6, "TC-TYPES-03: FLOAT64 roundtrip London lat");
    }

    // TC-TYPES-04: Structural STRING column
    {
        QpqtSchema s;
        s.column_count = 1;
        s.columns = {{"city", QpqtColumnType::STRING, false, 0}};
        std::vector<std::string> vals = {"London", "New York", "Tokyo", ""};
        QpqtWriter w("/tmp/tt04.qpqt", s, kid);
        w.write_row_group(4, {pack_string_column(vals)}, {});
        w.finalize();
        QpqtReader r("/tmp/tt04.qpqt");
        ASSERT(r.total_rows() == 4, "TC-TYPES-04: total_rows == 4");
        auto row0 = r.read_row(0);
        ASSERT(std::get<std::string>(row0.structural_values[0].value) == "London",
               "TC-TYPES-04: structural STRING 'London' roundtrip");
        auto row2 = r.read_row(2);
        ASSERT(std::get<std::string>(row2.structural_values[0].value) == "Tokyo",
               "TC-TYPES-04: structural STRING 'Tokyo' roundtrip");
        auto row3 = r.read_row(3);
        ASSERT(std::get<std::string>(row3.structural_values[0].value).empty(),
               "TC-TYPES-04: empty structural STRING roundtrip");
    }

    // TC-TYPES-05: DATE32 column
    {
        QpqtSchema s;
        s.column_count = 1;
        s.columns = {{"dob", QpqtColumnType::DATE32, false, 4}};
        // Days since epoch: 2000-01-01 = 10957, 1990-06-15 = 7470
        std::vector<int32_t> vals = {10957, 7470, 0, -365};
        QpqtWriter w("/tmp/tt05.qpqt", s, kid);
        w.write_row_group(4, {pack_date32_column(vals)}, {});
        w.finalize();
        QpqtReader r("/tmp/tt05.qpqt");
        auto row = r.read_row(0);
        ASSERT(std::get<int32_t>(row.structural_values[0].value) == 10957,
               "TC-TYPES-05: DATE32 roundtrip 2000-01-01");
    }

    // TC-TYPES-06: Mixed schema — INT32 + INT64 + FLOAT64 + STRING(struct) + STRING(pqc)
    {
        QpqtSchema s;
        s.column_count = 5;
        s.columns = {
            {"id",      QpqtColumnType::INT32,  false, 4},
            {"amount",  QpqtColumnType::INT64,  false, 8},
            {"score",   QpqtColumnType::FLOAT64, false, 8},
            {"city",    QpqtColumnType::STRING,  false, 0},
            {"ssn",     QpqtColumnType::STRING,  true,  16},
        };
        std::vector<int32_t>     ids    = {1, 2, 3};
        std::vector<int64_t>     amts   = {100000LL, 200000LL, 300000LL};
        std::vector<double>      scores = {9.5, 7.2, 8.8};
        std::vector<std::string> cities = {"NYC", "LON", "TYO"};
        std::vector<std::string> ssns   = {"SSN-A", "SSN-B", "SSN-C"};

        QpqtWriter w("/tmp/tt06.qpqt", s, kid, pk);
        w.write_row_group(3,
            {pack_int32_column(ids),
             pack_int64_column(amts),
             pack_float64_column(scores),
             pack_string_column(cities)},
            {ssns});
        w.finalize();

        QpqtReader r("/tmp/tt06.qpqt");
        r.set_secret_key(sk);
        ASSERT(r.total_rows() == 3, "TC-TYPES-06: total_rows == 3");

        auto row1 = r.read_row(0);
        ASSERT(row1.int32_values[0] == 1,              "TC-TYPES-06: row0 INT32 id");
        ASSERT(std::get<int64_t>(row1.structural_values[1].value) == 100000LL,
               "TC-TYPES-06: row0 INT64 amount");
        ASSERT(std::abs(std::get<double>(row1.structural_values[2].value) - 9.5) < 1e-9,
               "TC-TYPES-06: row0 FLOAT64 score");
        ASSERT(std::get<std::string>(row1.structural_values[3].value) == "NYC",
               "TC-TYPES-06: row0 STRING city");
        ASSERT(row1.pqc_values[0] == "SSN-A",          "TC-TYPES-06: row0 PQC SSN-A");

        auto row2 = r.read_row(2);
        ASSERT(std::get<std::string>(row2.structural_values[3].value) == "TYO",
               "TC-TYPES-06: row2 STRING city TYO");
        ASSERT(row2.pqc_values[0] == "SSN-C",          "TC-TYPES-06: row2 PQC SSN-C");
    }

    // TC-TYPES-07: Predicate on INT64 column in mixed schema
    {
        QpqtSchema s;
        s.column_count = 3;
        s.columns = {
            {"id",     QpqtColumnType::INT32,  false, 4},
            {"amount", QpqtColumnType::INT64,  false, 8},
            {"ssn",    QpqtColumnType::STRING,  true,  16},
        };
        std::vector<int32_t> ids(1000);
        std::vector<int64_t> amts(1000);
        std::vector<std::string> ssns(1000);
        for (int i = 0; i < 1000; ++i) {
            ids[i] = i;
            amts[i] = (int64_t)i * 1000;
            ssns[i] = "SSN-" + std::to_string(i);
        }
        QpqtWriter w("/tmp/tt07.qpqt", s, kid, pk);
        w.write_row_group(1000,
            {pack_int32_column(ids), pack_int64_column(amts)}, {ssns});
        w.finalize();

        QpqtReader r("/tmp/tt07.qpqt");
        r.set_secret_key(sk);
        uint64_t s2 = 0;
        // Filter: amount > 900000 → ids 901..999 = 99 survivors
        // INT64 values cast to int32_t in predicate (valid since all < INT32_MAX)
        auto results = r.query(
            {{1, [](int32_t v){ return v > 900000; }}}, s2);
        ASSERT(results.size() == 99, "TC-TYPES-07: INT64 predicate 99 survivors");
        ASSERT(s2 > 0, "TC-TYPES-07: Section 2 read for survivors");
    }
}

// ─────────────────────────────────────────────────────────
// TC-NULL: Validity bitmaps
// ─────────────────────────────────────────────────────────

void test_nulls() {
    current_group = "NULL Handling";

    uint8_t pk[ML_KEM_768_PK_LEN], sk[ML_KEM_768_SK_LEN];
    kem_keygen(pk, sk);
    uint8_t kid[16] = {};

    // TC-NULL-01: 50% nulls in INT32 column
    {
        QpqtSchema s;
        s.column_count = 1;
        s.columns = {{"score", QpqtColumnType::INT32, false, 4}};
        s.columns[0].nullable = true;

        std::vector<int32_t> vals   = {10, 0, 30, 0, 50};  // 0 = placeholder for null
        std::vector<bool>    mask   = {true, false, true, false, true}; // true=non-null

        QpqtWriter w("/tmp/tn01.qpqt", s, kid);
        w.write_row_group(5, {pack_int32_column(vals)}, {}, {mask});
        w.finalize();

        QpqtReader r("/tmp/tn01.qpqt");
        auto row0 = r.read_row(0);
        auto row1 = r.read_row(1);
        auto row2 = r.read_row(2);

        ASSERT(!row0.structural_values[0].is_null, "TC-NULL-01: row 0 is non-null");
        ASSERT(std::get<int32_t>(row0.structural_values[0].value) == 10,
               "TC-NULL-01: row 0 value == 10");
        ASSERT(row1.structural_values[0].is_null, "TC-NULL-01: row 1 is null");
        ASSERT(!row2.structural_values[0].is_null, "TC-NULL-01: row 2 is non-null");
        ASSERT(std::get<int32_t>(row2.structural_values[0].value) == 30,
               "TC-NULL-01: row 2 value == 30");
    }

    // TC-NULL-02: NULL rows do not match predicates
    {
        QpqtSchema s;
        s.column_count = 2;
        s.columns = {
            {"id",  QpqtColumnType::INT32, false, 4},
            {"ssn", QpqtColumnType::STRING, true, 16},
        };
        s.columns[0].nullable = true;

        // 10 rows: even rows have null id, odd rows have id = row_index
        std::vector<int32_t>     ids(10);
        std::vector<bool>        mask(10);
        std::vector<std::string> ssns(10);
        for (int i = 0; i < 10; ++i) {
            ids[i]  = i;
            mask[i] = (i % 2 != 0); // odd rows non-null
            ssns[i] = "SSN-" + std::to_string(i);
        }

        QpqtWriter w("/tmp/tn02.qpqt", s, kid, pk);
        w.write_row_group(10, {pack_int32_column(ids)}, {ssns}, {mask});
        w.finalize();

        QpqtReader r("/tmp/tn02.qpqt");
        r.set_secret_key(sk);
        uint64_t s2 = 0;
        // Filter id > 0: should only match non-null rows with id > 0
        // Non-null rows: 1,3,5,7,9 — id > 0: 1,3,5,7,9 = 5 survivors
        auto results = r.query({{0, [](int32_t v){ return v > 0; }}}, s2);
        ASSERT(results.size() == 5, "TC-NULL-02: 5 non-null survivors with id > 0");
        ASSERT(s2 > 0, "TC-NULL-02: Section 2 read for survivors");
    }

    // TC-NULL-03: All-null column
    {
        QpqtSchema s;
        s.column_count = 1;
        s.columns = {{"val", QpqtColumnType::INT32, false, 4}};
        s.columns[0].nullable = true;

        std::vector<int32_t> vals = {1, 2, 3};
        std::vector<bool>    mask = {false, false, false}; // all null

        QpqtWriter w("/tmp/tn03.qpqt", s, kid);
        w.write_row_group(3, {pack_int32_column(vals)}, {}, {mask});
        w.finalize();

        QpqtReader r("/tmp/tn03.qpqt");
        uint64_t s2 = 0;
        auto results = r.query({{0, [](int32_t v){ return v > 0; }}}, s2);
        ASSERT(results.empty(), "TC-NULL-03: all-null column → 0 survivors");
        ASSERT(s2 == 0, "TC-NULL-03: no Section 2 read for all-null");
    }

    // TC-NULL-04: Non-nullable column reads unchanged (v1.0 compatible)
    {
        QpqtSchema s;
        s.column_count = 1;
        s.columns = {{"id", QpqtColumnType::INT32, false, 4}};
        // nullable = false (default) — no bitmap written

        std::vector<int32_t> vals = {100, 200, 300};
        QpqtWriter w("/tmp/tn04.qpqt", s, kid);
        w.write_row_group(3, {pack_int32_column(vals)}, {});
        w.finalize();

        QpqtReader r("/tmp/tn04.qpqt");
        auto row = r.read_row(1);
        ASSERT(!row.structural_values[0].is_null, "TC-NULL-04: non-nullable col not null");
        ASSERT(std::get<int32_t>(row.structural_values[0].value) == 200,
               "TC-NULL-04: non-nullable value correct");
    }

    // TC-NULL-05: Mixed nullable + non-nullable in same schema
    {
        QpqtSchema s;
        s.column_count = 3;
        s.columns = {
            {"id",    QpqtColumnType::INT32,  false, 4},
            {"score", QpqtColumnType::FLOAT64, false, 8},
            {"ssn",   QpqtColumnType::STRING,  true,  16},
        };
        s.columns[0].nullable = false;
        s.columns[1].nullable = true; // score is nullable

        std::vector<int32_t> ids    = {1, 2, 3, 4};
        std::vector<double>  scores = {9.5, 0.0, 8.8, 0.0};
        std::vector<bool>    smask  = {true, false, true, false};
        std::vector<std::string> ssns = {"A", "B", "C", "D"};

        QpqtWriter w("/tmp/tn05.qpqt", s, kid, pk);
        // validity_masks: one per structural column in order (id, score)
        w.write_row_group(4,
            {pack_int32_column(ids), pack_float64_column(scores)},
            {ssns},
            {{}, smask}); // id has no mask, score has mask
        w.finalize();

        QpqtReader r("/tmp/tn05.qpqt");
        r.set_secret_key(sk);

        auto row0 = r.read_row(0);
        auto row1 = r.read_row(1);

        ASSERT(!row0.structural_values[0].is_null, "TC-NULL-05: id[0] non-null");
        ASSERT(!row0.structural_values[1].is_null, "TC-NULL-05: score[0] non-null");
        ASSERT(std::abs(std::get<double>(row0.structural_values[1].value) - 9.5) < 1e-9,
               "TC-NULL-05: score[0] == 9.5");

        ASSERT(!row1.structural_values[0].is_null, "TC-NULL-05: id[1] non-null");
        ASSERT(row1.structural_values[1].is_null,  "TC-NULL-05: score[1] is null");
        ASSERT(row1.pqc_values[0] == "B",          "TC-NULL-05: ssn[1] == B");
    }
}

// ─────────────────────────────────────────────────────────
// TC-STATS: Row group statistics + skipping
// ─────────────────────────────────────────────────────────

void test_rg_stats() {
    current_group = "RG Statistics";

    uint8_t pk[ML_KEM_768_PK_LEN], sk[ML_KEM_768_SK_LEN];
    kem_keygen(pk, sk);
    uint8_t kid[16] = {};

    // Write 3 row groups with non-overlapping id ranges:
    // RG0: ids 0..99     (max=99)
    // RG1: ids 100..199  (max=199)
    // RG2: ids 200..299  (max=299)
    QpqtSchema s;
    s.column_count = 2;
    s.columns = {
        {"id",  QpqtColumnType::INT32,  false, 4},
        {"ssn", QpqtColumnType::STRING, true,  16},
    };

    QpqtWriter w("/tmp/ts01.qpqt", s, kid, pk);
    for (int rg = 0; rg < 3; ++rg) {
        std::vector<int32_t>     ids(100);
        std::vector<std::string> ssns(100);
        for (int i = 0; i < 100; ++i) {
            ids[i]  = rg * 100 + i;
            ssns[i] = "SSN-" + std::to_string(rg * 100 + i);
        }
        w.write_row_group(100, {pack_int32_column(ids)}, {ssns});
    }
    w.finalize();

    // TC-STATS-01: Query that only matches RG2 — RG0 and RG1 skipped by stats
    {
        QpqtReader r("/tmp/ts01.qpqt");
        r.set_secret_key(sk);
        uint64_t s2 = 0;
        auto results = r.query({{0, [](int32_t v){ return v >= 200; }}}, s2);
        ASSERT(results.size() == 100, "TC-STATS-01: 100 survivors from RG2");
        ASSERT(results[0].int32_values[0] == 200, "TC-STATS-01: first id == 200");
        ASSERT(s2 > 0, "TC-STATS-01: Section 2 read for RG2");
    }

    // TC-STATS-02: Query that matches no row group — all skipped
    {
        QpqtReader r("/tmp/ts01.qpqt");
        r.set_secret_key(sk);
        uint64_t s2 = 0;
        auto results = r.query({{0, [](int32_t v){ return v > 500; }}}, s2);
        ASSERT(results.empty(), "TC-STATS-02: 0 survivors — all RGs skipped");
        ASSERT(s2 == 0, "TC-STATS-02: no Section 2 read");
    }

    // TC-STATS-03: Query matching only RG1 — RG0 and RG2 skipped
    {
        QpqtReader r("/tmp/ts01.qpqt");
        r.set_secret_key(sk);
        uint64_t s2 = 0;
        auto results = r.query(
            {{0, [](int32_t v){ return v >= 100 && v < 200; }}}, s2);
        ASSERT(results.size() == 100, "TC-STATS-03: 100 survivors from RG1");
        ASSERT(results[0].pqc_values[0] == "SSN-100", "TC-STATS-03: first SSN correct");
    }

    // TC-STATS-04: Query matching all row groups — no skipping
    {
        QpqtReader r("/tmp/ts01.qpqt");
        r.set_secret_key(sk);
        uint64_t s2 = 0;
        auto results = r.query({{0, [](int32_t v){ return v >= 0; }}}, s2);
        ASSERT(results.size() == 300, "TC-STATS-04: 300 survivors — all RGs scanned");
    }
}

// ─────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────

int main() {
    std::cout << "=== QPQT Test Suite ===\n";
    std::cout << "ML-KEM-768 + HKDF-SHA3-256 + AES-256-GCM\n\n";

#define RUN(fn) do { \
        try { fn(); } \
        catch (std::exception& e) { \
            std::cerr << "  FATAL in " #fn ": " << e.what() << "\n"; \
            ++tests_failed; \
        } \
    } while(0)

    std::cout << "── Correctness Tests ──\n";
    RUN(test_correctness);

    std::cout << "\n── Cryptographic Tests ──\n";
    RUN(test_crypto);

    std::cout << "\n── Lazy Decryption Tests ──\n";
    RUN(test_lazy);

    std::cout << "\n── End-to-End Tests ──\n";
    RUN(test_e2e);

    std::cout << "\n── Edge Case Tests ──\n";
    RUN(test_edge_cases);

    std::cout << "\n── Key Persistence Tests ──\n";
    RUN(test_key_persistence);

    std::cout << "\n── All Column Types Tests ──\n";
    RUN(test_all_types);

    std::cout << "\n── NULL Handling Tests ──\n";
    RUN(test_nulls);

    std::cout << "\n── Row Group Statistics Tests ──\n";
    RUN(test_rg_stats);

    std::cout << "\n════════════════════════════════\n";
    std::cout << "Tests passed : " << tests_passed << "\n";
    std::cout << "Tests failed : " << tests_failed << "\n";
    if (tests_failed == 0)
        std::cout << "ALL TESTS PASSED ✓\n";
    return tests_failed > 0 ? 1 : 0;
}