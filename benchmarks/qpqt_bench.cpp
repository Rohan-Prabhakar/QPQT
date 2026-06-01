/**
 * qpqt_bench.cpp
 * Performance benchmark — mirrors published results.
 *
 * Produces:
 *   - Write throughput at 1M rows
 *   - Structural column scan speed
 *   - Selectivity sweep (1% to 100%)
 *
 * Compile:
 *   g++ -O3 -std=c++17 -fopenmp \
 *       -I../include -I/usr/local/include \
 *       qpqt_bench.cpp -o qpqt_bench \
 *       -L/usr/local/lib -loqs -lssl -lcrypto \
 *       -Wl,-rpath,/usr/local/lib
 */

#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <cstring>
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

static std::vector<uint8_t> pack_int32_column(const std::vector<int32_t>& v) {
    std::vector<uint8_t> b(v.size()*4);
    memcpy(b.data(), v.data(), b.size());
    return b;
}

double now_ms() {
    return std::chrono::duration<double,std::milli>(
        std::chrono::high_resolution_clock::now().time_since_epoch()
    ).count();
}

int main() {
    std::cout << "=== QPQT Performance Benchmark ===\n";
    std::cout << "1M rows | ML-KEM-768 + AES-256-GCM\n\n";

    uint8_t pk[ML_KEM_768_PK_LEN], sk[ML_KEM_768_SK_LEN];
    kem_keygen(pk, sk);
    uint8_t key_id[16] = {};

    QpqtSchema schema;
    schema.column_count = 2;
    schema.columns = {
        {"id",  QpqtColumnType::INT32,  false, 4},
        {"pii", QpqtColumnType::STRING,  true, 64}
    };

    // ── Write benchmark ──
    std::cout << "Writing 1M rows...\n";
    double t0 = now_ms();
    {
        QpqtWriter w("/tmp/bench_1m.qpqt", schema, key_id, pk);
        for (int rg=0; rg<10; ++rg) {
            std::vector<int32_t> ids(100000);
            std::vector<std::string> piis(100000);
            for (int i=0;i<100000;++i){
                int abs=rg*100000+i;
                ids[i]=abs; piis[i]="PII-"+std::to_string(abs);
            }
            w.write_row_group(100000,{pack_int32_column(ids)},{piis});
        }
        w.finalize();
    }
    double t_write = now_ms() - t0;
    std::ifstream fs("/tmp/bench_1m.qpqt", std::ios::ate|std::ios::binary);
    uint64_t fsize_mb = fs.tellg() / (1024*1024);
    std::cout << std::fixed << std::setprecision(1);
    std::cout << "  Write time  : " << t_write << "ms\n";
    std::cout << "  Throughput  : " << std::setprecision(0)
              << (1000000.0/t_write)*1000 << " rows/sec\n";
    std::cout << "  File size   : " << fsize_mb << " MB\n\n";

    // ── Structural scan ──
    {
        QpqtReader r("/tmp/bench_1m.qpqt");
        r.set_secret_key(sk);
        double t = now_ms();
        uint64_t s2=0;
        auto res = r.query({{0,[](int32_t v){return v>2000000;}}}, s2);
        double ms = now_ms()-t;
        std::cout << "Structural scan (no crypto): " << ms << "ms  "
                  << std::setprecision(0) << (1000000.0/ms)*1000
                  << " rows/sec  s2_bytes=" << s2 << "\n\n";
    }

    // ── Selectivity sweep ──
    std::cout << std::left
              << std::setw(14) << "Selectivity"
              << std::setw(14) << "Survivors"
              << std::setw(14) << "Query(ms)"
              << std::setw(16) << "Rows/sec"
              << std::setw(16) << "Speedup vs naive"
              << "\n";
    std::cout << std::string(74, '-') << "\n";

    double naive_ms = 9600.0;
    for (int sel : {1,5,10,25,50,100}) {
        QpqtReader r("/tmp/bench_1m.qpqt");
        r.set_secret_key(sk);
        int div = 100/sel;
        double t = now_ms();
        uint64_t s2=0;
        auto res = r.query({{0,[div](int32_t v){return v%div==0;}}}, s2);
        double ms = now_ms()-t;
        std::cout << std::left
                  << std::setw(14) << (std::to_string(sel)+"%")
                  << std::setw(14) << res.size()
                  << std::setw(14) << std::setprecision(1) << ms
                  << std::setw(16) << std::setprecision(0)
                  << (res.size()>0?(res.size()/ms)*1000:0)
                  << std::setw(16) << std::setprecision(1) << naive_ms/ms
                  << "\n";
    }

    std::cout << "\nNaive PQC baseline (row-level ML-KEM, 4-core): "
              << naive_ms << "ms\n";
    return 0;
}