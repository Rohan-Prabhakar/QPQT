/**
 * qpqt_bench.cpp - Stress test + selectivity benchmark.
 * Tests all column types + lazy decryption USP.
 */
#include <iostream>
#include <iomanip>
#include <fstream>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <cmath>
#include "../include/qpqt_types.h"
#include "../include/qpqt_utils.h"
#include "../include/qpqt_crypto.h"
#define QPQT_PACK_INT32_DEFINED
#define QPQT_WRITER_NO_MAIN
#include "../src/qpqt_writer.cpp"
#define QPQT_READER_NO_MAIN
#undef ASSERT
#include "../src/qpqt_reader.cpp"
using namespace qpqt;
using namespace qpqt::crypto;
using Clock = std::chrono::high_resolution_clock;
static std::vector<uint8_t> pack_int32_column(const std::vector<int32_t>& v) {
    std::vector<uint8_t> b(v.size()*4); memcpy(b.data(),v.data(),b.size()); return b;
}
static double elapsed_s(std::chrono::time_point<Clock> t0, std::chrono::time_point<Clock> t1) {
    return std::chrono::duration<double>(t1-t0).count();
}
int main() {
    const uint32_t TOTAL = 1000000;
    const char* FILE = "/tmp/qpqt_bench.qpqt";
    static const char* REGIONS[] = {"APAC","EMEA","NA","LATAM"};

    QpqtSchema schema;
    schema.column_count = 6;
    schema.columns = {
        {"customer_id",  QpqtColumnType::INT32,   false, 4},
        {"amount_cents", QpqtColumnType::INT64,   false, 8},
        {"score",        QpqtColumnType::FLOAT64, false, 8},
        {"region",       QpqtColumnType::STRING,  false, 0},
        {"ssn",          QpqtColumnType::STRING,  true,  16},
        {"dob",          QpqtColumnType::DATE32,  false, 4},
    };

    uint8_t pk[ML_KEM_768_PK_LEN], sk[ML_KEM_768_SK_LEN], kid[16] = {};
    kem_keygen(pk, sk);

    std::cout << "\n============================================================\n";
    std::cout << "  QPQT Stress Test + Selectivity Benchmark\n";
    std::cout << "  Schema: INT32 + INT64 + FLOAT64 + STRING + PQC + DATE32\n";
    std::cout << "  Rows: " << TOTAL << "\n";
    std::cout << "============================================================\n\n";

    // Write
    std::cerr << "Writing " << TOTAL << " rows...\n";
    auto t0 = Clock::now();
    {
        QpqtWriter w(FILE, schema, kid, pk);
        const uint32_t RG = QPQT_ROWS_PER_ROW_GROUP;
        for (uint32_t base = 0; base < TOTAL; base += RG) {
            uint32_t n = std::min(RG, TOTAL - base);
            std::vector<int32_t>     ids(n);
            std::vector<int64_t>     amts(n);
            std::vector<double>      scores(n);
            std::vector<std::string> regions(n), ssns(n);
            std::vector<int32_t>     dobs(n);
            for (uint32_t i = 0; i < n; ++i) {
                uint32_t a = base+i;
                ids[i]=(int32_t)a; amts[i]=(int64_t)a*100;
                scores[i]=100.0*std::sin(a*0.001);
                regions[i]=REGIONS[a%4]; ssns[i]="SSN"+std::to_string(a);
                dobs[i]=10957+(int32_t)(a%36500);
            }
            w.write_row_group(n, {pack_int32_column(ids), pack_int64_column(amts),
                pack_float64_column(scores), pack_string_column(regions),
                pack_date32_column(dobs)}, {ssns});
        }
        w.finalize();
    }
    double ws = elapsed_s(t0, Clock::now());
    double mb; { std::ifstream f(FILE,std::ios::ate|std::ios::binary); mb=f.tellg()/1e6; }
    std::cerr << "Done: " << std::fixed << std::setprecision(1) << ws << "s  " << mb << " MB\n\n";

    // Type spot-check
    {
        QpqtReader r(FILE); r.set_secret_key(sk);
        auto row = r.read_row(42);
        bool ok = (row.int32_values[0] == 42)
               && (std::get<int64_t>(row.structural_values[1].value) == 4200LL)
               && (std::get<std::string>(row.structural_values[3].value) == "NA")
               && (row.pqc_values[0] == "SSN42");
        std::cout << "  Type check row 42: " << (ok ? "PASS" : "FAIL") << "\n\n";
        if (!ok) return 1;
    }

    // Selectivity sweep
    struct R { const char* label; uint64_t hits; double s2pct, time_s; };
    std::vector<R> res;
    auto run = [&](const char* lbl, std::vector<QpqtPredicate> preds, uint64_t exp) {
        QpqtReader r(FILE); r.set_secret_key(sk);
        uint64_t s2=0; auto t=Clock::now();
        uint64_t hits=r.query_count(preds,s2);
        double el=elapsed_s(t,Clock::now());
        double tot=TOTAL*(16.0+QPQT_AES_GCM_TAG_LEN);
        double pct=tot>0?s2*100.0/tot:0.0;
        res.push_back({lbl,hits,pct,el});
        std::cout << "  " << std::left << std::setw(40) << lbl
                  << std::setw(10) << hits
                  << std::setw(8) << (std::to_string((int)std::round(pct))+"%")
                  << std::setw(10) << (std::to_string((int)(el*1000))+"ms")
                  << (hits==exp?"PASS":"FAIL") << "\n";
    };

    std::cout << "  " << std::left << std::setw(40) << "Query"
              << std::setw(10) << "Survivors" << std::setw(8) << "S2 read"
              << std::setw(10) << "Time" << "Result\n";
    std::cout << "  " << std::string(70,'-') << "\n";
    run("0%  impossible (id > 2000000)",  {{0,[](int32_t v){return v>2000000;}}}, 0);
    run("1%  id % 100 == 0",             {{0,[](int32_t v){return v%100==0;}}}, TOTAL/100);
    run("10% id % 10 == 0",              {{0,[](int32_t v){return v%10==0;}}},  TOTAL/10);
    run("50% id % 2 == 0",               {{0,[](int32_t v){return v%2==0;}}},   TOTAL/2);
    run("100% no filter",                {},                                     TOTAL);

    std::cout << "\n============================================================\n";
    std::cout << "  USP Proof:\n";
    if (res.size()>=2) {
        std::cout << "  0%  selectivity -> S2 read = " << res[0].s2pct << "% (zero PQC decryptions)\n";
        std::cout << "  1%  selectivity -> S2 read = " << std::setprecision(1) << res[1].s2pct << "%\n";
        double speedup = res.back().time_s / std::max(res[0].time_s, 0.001);
        std::cout << "  Speedup (100% vs 0%): " << std::setprecision(0) << speedup << "x\n";
    }
    std::cout << "============================================================\n\n";
    return 0;
}
