/**
 * qpqt_cli.cpp
 * Command-line interface for QPQT.
 *
 * Commands:
 *   qpqt keygen  --out-pub <pub.bin> --out-sec <sec.bin>
 *   qpqt encrypt --input <file.csv|file.parquet>
 *                --pqc-columns col1,col2
 *                --pub-key <pub.bin>
 *                --key-id <uuid-string>
 *                --output <file.qpqt>
 *   qpqt decrypt --input <file.qpqt>
 *                --sec-key <sec.bin>
 *                --output <file.csv>
 *                [--columns col1,col2]
 *                [--where "col=value"]
 *   qpqt inspect --input <file.qpqt>
 *
 * CSV format assumed: first row is header, comma-separated.
 * Parquet support: requires Apache Arrow C++ library (optional).
 *
 * Compile (CSV only, no Arrow):
 *   g++ -O3 -std=c++17 -fopenmp \
 *       -I../include -I/usr/local/include \
 *       qpqt_cli.cpp -o qpqt \
 *       -L/usr/local/lib -loqs -lssl -lcrypto \
 *       -Wl,-rpath,/usr/local/lib
 *
 * Compile (with Arrow/Parquet support):
 *   g++ -O3 -std=c++17 -fopenmp -DQPQT_ARROW_SUPPORT \
 *       -I../include -I/usr/local/include \
 *       $(pkg-config --cflags arrow parquet) \
 *       qpqt_cli.cpp -o qpqt \
 *       -L/usr/local/lib -loqs -lssl -lcrypto \
 *       $(pkg-config --libs arrow parquet) \
 *       -Wl,-rpath,/usr/local/lib
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <cstring>
#include <algorithm>
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

#ifdef QPQT_ARROW_SUPPORT
#include <arrow/api.h>
#include <arrow/io/api.h>
#include <parquet/arrow/reader.h>
#include <parquet/arrow/writer.h>
#endif

using namespace qpqt;
using namespace qpqt::crypto;

// ─────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────

static std::vector<uint8_t> pack_int32_column(const std::vector<int32_t>& v) {
    std::vector<uint8_t> b(v.size()*4);
    memcpy(b.data(), v.data(), b.size());
    return b;
}

static std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::stringstream ss(s);
    std::string part;
    while (std::getline(ss, part, delim))
        parts.push_back(part);
    return parts;
}

static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b-a+1);
}

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

// Parse a simple UUID string (with or without hyphens) into 16 bytes
static void parse_key_id(const std::string& s, uint8_t out[16]) {
    std::string hex;
    for (char c : s)
        if (c != '-') hex += c;
    if (hex.size() != 32)
        throw std::runtime_error("key-id must be a 32-char hex UUID");
    for (int i = 0; i < 16; ++i) {
        out[i] = (uint8_t)std::stoul(hex.substr(i*2, 2), nullptr, 16);
    }
}

// ─────────────────────────────────────────────────────────
// CSV reader
// ─────────────────────────────────────────────────────────

struct CsvTable {
    std::vector<std::string>              headers;
    std::vector<std::vector<std::string>> rows;

    size_t col_index(const std::string& name) const {
        for (size_t i = 0; i < headers.size(); ++i)
            if (headers[i] == name) return i;
        throw std::runtime_error("Column not found: " + name);
    }
};

static CsvTable read_csv(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open CSV: " + path);

    CsvTable table;
    std::string line;

    // Header row
    if (!std::getline(f, line))
        throw std::runtime_error("Empty CSV file");
    table.headers = split(trim(line), ',');
    for (auto& h : table.headers) h = trim(h);

    // Data rows
    while (std::getline(f, line)) {
        if (trim(line).empty()) continue;
        auto cols = split(line, ',');
        while (cols.size() < table.headers.size())
            cols.push_back("");
        for (auto& c : cols) c = trim(c);
        table.rows.push_back(cols);
    }
    return table;
}

static void write_csv(const std::string& path,
                      const std::vector<std::string>& headers,
                      const std::vector<std::vector<std::string>>& rows) {
    std::ofstream f(path);
    if (!f) throw std::runtime_error("Cannot write CSV: " + path);

    for (size_t i = 0; i < headers.size(); ++i) {
        if (i) f << ',';
        f << headers[i];
    }
    f << '\n';

    for (auto& row : rows) {
        for (size_t i = 0; i < row.size(); ++i) {
            if (i) f << ',';
            f << row[i];
        }
        f << '\n';
    }
}

// ─────────────────────────────────────────────────────────
// Command: keygen
// ─────────────────────────────────────────────────────────

int cmd_keygen(const std::map<std::string,std::string>& args) {
    std::string pub_path = args.count("--out-pub") ? args.at("--out-pub") : "qpqt_public.bin";
    std::string sec_path = args.count("--out-sec") ? args.at("--out-sec") : "qpqt_secret.bin";

    std::cout << "Generating ML-KEM-768 keypair...\n";

    std::vector<uint8_t> pk(ML_KEM_768_PK_LEN);
    std::vector<uint8_t> sk(ML_KEM_768_SK_LEN);
    kem_keygen(pk.data(), sk.data());

    write_key_file(pub_path, pk.data(), pk.size());
    write_key_file(sec_path, sk.data(), sk.size());

    // Also generate a key_id UUID
    uint8_t key_id[16];
    generate_uuid(key_id);

    std::cout << "Public key : " << pub_path
              << " (" << ML_KEM_768_PK_LEN << " bytes)\n";
    std::cout << "Secret key : " << sec_path
              << " (" << ML_KEM_768_SK_LEN << " bytes)\n";
    std::cout << "Key ID     : ";
    for (int i = 0; i < 16; ++i) {
        if (i==4||i==6||i==8||i==10) std::cout << '-';
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)key_id[i];
    }
    std::cout << "\n";
    std::cout << "\nStore the secret key securely. "
              << "Never commit it to version control.\n";
    std::cout << "Pass the Key ID to --key-id when encrypting.\n";

    // Save key_id alongside keys
    write_key_file(pub_path + ".keyid", key_id, 16);

    return 0;
}

// ─────────────────────────────────────────────────────────
// Command: encrypt
// Reads CSV (or Parquet with Arrow), writes .qpqt
// ─────────────────────────────────────────────────────────

int cmd_encrypt(const std::map<std::string,std::string>& args) {
    // Validate required args
    for (auto& req : {"--input","--pqc-columns","--pub-key","--output"}) {
        if (!args.count(req))
            throw std::runtime_error("Missing required argument: " + std::string(req));
    }

    std::string input_path  = args.at("--input");
    std::string output_path = args.at("--output");
    std::string pub_key_path= args.at("--pub-key");
    auto pqc_col_names = split(args.at("--pqc-columns"), ',');
    for (auto& c : pqc_col_names) c = trim(c);

    // Key ID
    uint8_t key_id[16] = {};
    if (args.count("--key-id")) {
        parse_key_id(args.at("--key-id"), key_id);
    } else {
        // Try to load from .keyid file next to pub key
        std::string keyid_path = pub_key_path + ".keyid";
        try {
            auto kid = read_key_file(keyid_path);
            if (kid.size() == 16) memcpy(key_id, kid.data(), 16);
        } catch (...) {
            generate_uuid(key_id);
            std::cout << "[warn] No --key-id provided, generated random key ID\n";
        }
    }

    // Load public key
    auto pk_bytes = read_key_file(pub_key_path);
    if (pk_bytes.size() != ML_KEM_768_PK_LEN)
        throw std::runtime_error("Public key file has wrong size");

    std::set<std::string> pqc_set(pqc_col_names.begin(), pqc_col_names.end());

    // ── Detect input format ──
    std::string ext = input_path.size() > 4
                    ? input_path.substr(input_path.size()-4) : "";
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    CsvTable table;

#ifdef QPQT_ARROW_SUPPORT
    if (ext == ".parquet" || ext == "quet") {
        std::cout << "Reading Parquet: " << input_path << "\n";
        // Arrow/Parquet reader
        auto pool = arrow::default_memory_pool();
        std::shared_ptr<arrow::io::ReadableFile> infile;
        PARQUET_ASSIGN_OR_THROW(
            infile, arrow::io::ReadableFile::Open(input_path, pool)
        );
        std::unique_ptr<parquet::arrow::FileReader> reader;
        PARQUET_THROW_NOT_OK(
            parquet::arrow::OpenFile(infile, pool, &reader)
        );
        std::shared_ptr<arrow::Table> arrow_table;
        PARQUET_THROW_NOT_OK(reader->ReadTable(&arrow_table));

        // Convert Arrow table to CsvTable in memory
        for (auto& field : arrow_table->schema()->fields())
            table.headers.push_back(field->name());

        int64_t nrows = arrow_table->num_rows();
        table.rows.resize(nrows, std::vector<std::string>(table.headers.size()));

        for (size_t ci = 0; ci < table.headers.size(); ++ci) {
            auto col = arrow_table->column(ci);
            for (int64_t ri = 0; ri < nrows; ++ri) {
                auto chunk = col->chunk(0);
                if (chunk->type()->id() == arrow::Type::INT32) {
                    auto arr = std::static_pointer_cast<arrow::Int32Array>(chunk);
                    table.rows[ri][ci] = std::to_string(arr->Value(ri));
                } else {
                    auto arr = std::static_pointer_cast<arrow::StringArray>(chunk);
                    table.rows[ri][ci] = arr->GetString(ri);
                }
            }
        }
    } else {
#endif
        std::cout << "Reading CSV: " << input_path << "\n";
        table = read_csv(input_path);
#ifdef QPQT_ARROW_SUPPORT
    }
#endif

    std::cout << "  Rows    : " << table.rows.size() << "\n";
    std::cout << "  Columns : " << table.headers.size() << "\n";

    // ── Build QPQT schema ──
    QpqtSchema schema;
    schema.column_count = (uint16_t)table.headers.size();

    for (auto& hdr : table.headers) {
        QpqtColumnSchema col;
        col.name = hdr;
        col.is_pqc_encrypted = pqc_set.count(hdr) > 0;

        if (col.is_pqc_encrypted) {
            col.type = QpqtColumnType::STRING;
            // Compute max value length across all rows
            uint32_t maxlen = 64; // minimum
            size_t ci = table.col_index(hdr);
            for (auto& row : table.rows)
                maxlen = std::max(maxlen, (uint32_t)row[ci].size());
            // Round up to next 16 bytes (AES block alignment)
            maxlen = ((maxlen + 15) / 16) * 16;
            col.max_value_bytes = maxlen;
            std::cout << "  PQC col : " << hdr
                      << " (max_len=" << maxlen << ")\n";
        } else {
            // Detect type from first non-empty value
            col.type = QpqtColumnType::STRING;
            col.max_value_bytes = 0;
            size_t ci = table.col_index(hdr);
            for (auto& row : table.rows) {
                if (row[ci].empty()) continue;
                try {
                    std::stoi(row[ci]);
                    col.type = QpqtColumnType::INT32;
                } catch (...) {}
                break;
            }
        }
        schema.columns.push_back(col);
    }

    // ── Write QPQT file ──
    std::cout << "\nEncrypting to: " << output_path << "\n";
    QpqtWriter writer(output_path, schema, key_id, pk_bytes.data());

    // Write in row group batches
    size_t total_rows = table.rows.size();
    size_t rg_size    = QPQT_ROWS_PER_ROW_GROUP;
    size_t num_rgs    = (total_rows + rg_size - 1) / rg_size;

    for (size_t rg = 0; rg < num_rgs; ++rg) {
        size_t rg_start = rg * rg_size;
        size_t rg_end   = std::min(rg_start + rg_size, total_rows);
        size_t rg_rows  = rg_end - rg_start;

        std::vector<std::vector<uint8_t>> structural_cols;
        std::vector<std::vector<std::string>> pqc_cols;

        for (size_t ci = 0; ci < schema.columns.size(); ++ci) {
            auto& col = schema.columns[ci];
            if (col.is_pqc_encrypted) {
                std::vector<std::string> vals(rg_rows);
                for (size_t r = 0; r < rg_rows; ++r)
                    vals[r] = table.rows[rg_start + r][ci];
                pqc_cols.push_back(vals);
            } else {
                if (col.type == QpqtColumnType::INT32) {
                    std::vector<int32_t> vals(rg_rows, 0);
                    for (size_t r = 0; r < rg_rows; ++r) {
                        auto& v = table.rows[rg_start + r][ci];
                        if (!v.empty()) {
                            try { vals[r] = std::stoi(v); } catch (...) {}
                        }
                    }
                    structural_cols.push_back(pack_int32_column(vals));
                } else {
                    // STRING structural: store as length-prefixed blobs
                    // Simple: pack as fixed 256-byte fields
                    std::vector<uint8_t> buf(rg_rows * 256, 0);
                    for (size_t r = 0; r < rg_rows; ++r) {
                        auto& v = table.rows[rg_start + r][ci];
                        size_t copy_len = std::min(v.size(), (size_t)255);
                        memcpy(buf.data() + r*256, v.data(), copy_len);
                    }
                    structural_cols.push_back(buf);
                }
            }
        }

        writer.write_row_group((uint32_t)rg_rows, structural_cols, pqc_cols);
        std::cout << "  Row group " << rg << " written ("
                  << rg_rows << " rows)\n";
    }

    writer.finalize();

    // Show file size
    std::ifstream fs(output_path, std::ios::ate | std::ios::binary);
    uint64_t fsize = fs.tellg();
    std::cout << "\nDone.\n";
    std::cout << "  Output size : " << fsize / 1024 << " KB\n";
    std::cout << "  PQC columns : ";
    for (auto& c : pqc_col_names) std::cout << c << " ";
    std::cout << "\n";
    std::cout << "  Algorithm   : ML-KEM-768 + HKDF-SHA3-256 + AES-256-GCM\n";

    return 0;
}

// ─────────────────────────────────────────────────────────
// Command: decrypt
// Reads .qpqt, writes CSV (decrypted PII for authorized users)
// ─────────────────────────────────────────────────────────

int cmd_decrypt(const std::map<std::string,std::string>& args) {
    for (auto& req : {"--input","--sec-key","--output"}) {
        if (!args.count(req))
            throw std::runtime_error("Missing required argument: " + std::string(req));
    }

    std::string input_path  = args.at("--input");
    std::string output_path = args.at("--output");
    std::string sec_key_path= args.at("--sec-key");

    // Optional: filter columns to output
    std::set<std::string> col_filter;
    if (args.count("--columns")) {
        for (auto& c : split(args.at("--columns"), ','))
            col_filter.insert(trim(c));
    }

    // Optional: simple WHERE filter (col=value)
    std::string where_col, where_val;
    if (args.count("--where")) {
        auto parts = split(args.at("--where"), '=');
        if (parts.size() == 2) {
            where_col = trim(parts[0]);
            where_val = trim(parts[1]);
        }
    }

    // Load secret key
    auto sk_bytes = read_key_file(sec_key_path);
    if (sk_bytes.size() != ML_KEM_768_SK_LEN)
        throw std::runtime_error("Secret key file has wrong size");

    std::cout << "Opening: " << input_path << "\n";
    QpqtReader reader(input_path);
    reader.set_secret_key(sk_bytes.data());

    auto& schema = reader.schema();
    std::cout << "  Total rows  : " << reader.total_rows() << "\n";
    std::cout << "  Columns     : " << schema.column_count << "\n";

    // Build output headers
    std::vector<std::string> out_headers;
    for (auto& col : schema.columns) {
        if (col_filter.empty() || col_filter.count(col.name))
            out_headers.push_back(col.name);
    }

    // Build predicate if --where specified
    std::vector<QpqtPredicate> predicates;
    if (!where_col.empty()) {
        for (uint16_t ci = 0; ci < schema.columns.size(); ++ci) {
            if (schema.columns[ci].name == where_col &&
                schema.columns[ci].type == QpqtColumnType::INT32) {
                int32_t val = std::stoi(where_val);
                predicates.push_back({ci, [val](int32_t v){ return v == val; }});
                break;
            }
        }
    }

    std::cout << "Decrypting...\n";
    uint64_t s2_bytes = 0;
    auto results = reader.query(predicates, s2_bytes);

    // Build output rows
    std::vector<std::vector<std::string>> out_rows;
    int32_val_idx = 0;
    pqc_val_idx   = 0;

    for (auto& result : results) {
        std::vector<std::string> row;
        size_t int32_pos = 0, pqc_pos = 0;

        for (size_t ci = 0; ci < schema.columns.size(); ++ci) {
            auto& col = schema.columns[ci];
            if (!col_filter.empty() && !col_filter.count(col.name)) {
                if (!col.is_pqc_encrypted) ++int32_pos;
                else ++pqc_pos;
                continue;
            }

            if (!col.is_pqc_encrypted) {
                if (int32_pos < result.int32_values.size())
                    row.push_back(std::to_string(result.int32_values[int32_pos]));
                else
                    row.push_back("");
                ++int32_pos;
            } else {
                if (pqc_pos < result.pqc_values.size())
                    row.push_back(result.pqc_values[pqc_pos]);
                else
                    row.push_back("");
                ++pqc_pos;
            }
        }
        out_rows.push_back(row);
    }

    write_csv(output_path, out_headers, out_rows);

    std::cout << "Done.\n";
    std::cout << "  Rows written : " << out_rows.size() << "\n";
    std::cout << "  Output       : " << output_path << "\n";

    return 0;
}

// ─────────────────────────────────────────────────────────
// Command: inspect
// Prints file metadata without decrypting
// ─────────────────────────────────────────────────────────

int cmd_inspect(const std::map<std::string,std::string>& args) {
    if (!args.count("--input"))
        throw std::runtime_error("Missing --input");

    std::string path = args.at("--input");
    QpqtReader reader(path);
    auto& schema = reader.schema();
    auto& hdr    = reader.file_header();

    std::cout << "=== QPQT File Inspector ===\n\n";
    std::cout << "File         : " << path << "\n";
    std::cout << "Version      : " << hdr.version_major
              << "." << hdr.version_minor << "\n";
    std::cout << "Total rows   : " << hdr.total_rows << "\n";
    std::cout << "Row groups   : " << hdr.row_group_count << "\n";

    std::cout << "File UUID    : ";
    for (int i = 0; i < 16; ++i) {
        if (i==4||i==6||i==8||i==10) std::cout << '-';
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)hdr.file_uuid[i];
    }
    std::cout << "\n";

    std::cout << "\nSchema (" << schema.column_count << " columns):\n";
    std::cout << std::left
              << std::setw(24) << "Name"
              << std::setw(12) << "Type"
              << std::setw(10) << "Encrypted"
              << std::setw(12) << "MaxLen"
              << "\n";
    std::cout << std::string(58, '-') << "\n";

    for (auto& col : schema.columns) {
        std::string type_str;
        switch (col.type) {
            case QpqtColumnType::INT32:   type_str = "INT32";   break;
            case QpqtColumnType::INT64:   type_str = "INT64";   break;
            case QpqtColumnType::FLOAT32: type_str = "FLOAT32"; break;
            case QpqtColumnType::FLOAT64: type_str = "FLOAT64"; break;
            case QpqtColumnType::STRING:  type_str = "STRING";  break;
            case QpqtColumnType::DATE32:  type_str = "DATE32";  break;
        }
        std::cout << std::left
                  << std::setw(24) << col.name
                  << std::setw(12) << type_str
                  << std::setw(10) << (col.is_pqc_encrypted ? "PQC" : "plain")
                  << std::setw(12) << col.max_value_bytes
                  << "\n";
    }

    // File size
    std::ifstream fs(path, std::ios::ate | std::ios::binary);
    uint64_t fsize = fs.tellg();
    std::cout << "\nFile size    : " << fsize / 1024 << " KB\n";
    std::cout << "Crypto       : ML-KEM-768 + HKDF-SHA3-256 + AES-256-GCM\n";
    std::cout << "FIPS         : 203 (ML-KEM) + 197 (AES)\n";

    return 0;
}

// ─────────────────────────────────────────────────────────
// Main — argument parser
// ─────────────────────────────────────────────────────────

static void print_usage() {
    std::cout << R"(
QPQT — Quantum-Safe Columnar Storage

Usage:
  qpqt keygen  [--out-pub <pub.bin>] [--out-sec <sec.bin>]
  qpqt encrypt --input <file.csv|file.parquet>
               --pqc-columns <col1,col2,...>
               --pub-key <pub.bin>
               [--key-id <uuid>]
               --output <file.qpqt>
  qpqt decrypt --input <file.qpqt>
               --sec-key <sec.bin>
               --output <file.csv>
               [--columns <col1,col2,...>]
               [--where "col=value"]
  qpqt inspect --input <file.qpqt>

Examples:
  # Generate keypair
  qpqt keygen --out-pub pub.bin --out-sec sec.bin

  # Encrypt a CSV — PII columns ssn and dob are quantum-safe encrypted
  qpqt encrypt --input customers.csv \
               --pqc-columns ssn,dob,account_number \
               --pub-key pub.bin \
               --output customers.qpqt

  # Inspect without decrypting (safe to run anywhere)
  qpqt inspect --input customers.qpqt

  # Decrypt only authorized columns for authorized users
  qpqt decrypt --input customers.qpqt \
               --sec-key sec.bin \
               --columns customer_id,ssn \
               --output decrypted.csv

  # Decrypt with predicate (lazy — only matching rows decrypted)
  qpqt decrypt --input customers.qpqt \
               --sec-key sec.bin \
               --where "customer_id=12345" \
               --output single_customer.csv
)";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string cmd = argv[1];

    // Parse key=value args
    std::map<std::string,std::string> args;
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a.substr(0,2) == "--" && i+1 < argc) {
            args[a] = argv[++i];
        }
    }

    try {
        if (cmd == "keygen")  return cmd_keygen(args);
        if (cmd == "encrypt") return cmd_encrypt(args);
        if (cmd == "decrypt") return cmd_decrypt(args);
        if (cmd == "inspect") return cmd_inspect(args);

        std::cerr << "Unknown command: " << cmd << "\n";
        print_usage();
        return 1;
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
