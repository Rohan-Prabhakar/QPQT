/**
 * qpqt_arrow.cpp
 * Apache Arrow integration for QPQT.
 *
 * Exports QPQT structural columns as Arrow RecordBatches.
 * This makes structural data readable by DuckDB, Polars,
 * Spark, pandas (via pyarrow), and any Arrow-compatible tool
 * WITHOUT touching the PQC section at all.
 *
 * Compile:
 *   g++ -O3 -std=c++17 -fopenmp \
 *       -I../include -I/usr/local/include \
 *       $(pkg-config --cflags arrow) \
 *       qpqt_arrow.cpp -o qpqt_arrow \
 *       -L/usr/local/lib -loqs -lssl -lcrypto \
 *       $(pkg-config --libs arrow) \
 *       -Wl,-rpath,/usr/local/lib
 *
 * Usage:
 *   # Export structural columns to Arrow IPC stream
 *   qpqt_arrow export --input customers.qpqt \
 *                     --output customers_structural.arrow
 *
 *   # Then in Python / DuckDB:
 *   import pyarrow as pa
 *   import pyarrow.ipc as ipc
 *   import duckdb
 *
 *   with ipc.open_stream("customers_structural.arrow") as reader:
 *       table = reader.read_all()
 *
 *   # Query with DuckDB at native speed
 *   duckdb.execute("SELECT * FROM table WHERE state_code = 5")
 *
 * Design:
 *   - Only structural (unencrypted) columns are exported
 *   - PQC columns are represented as a placeholder binary column
 *     containing the row index — used for joining back decrypted
 *     values from a separate QPQT decrypt call
 *   - The Arrow schema includes QPQT metadata in custom_metadata
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <cstring>
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

#ifdef QPQT_ARROW_AVAILABLE
#include <arrow/api.h>
#include <arrow/io/api.h>
#include <arrow/ipc/api.h>
#include <arrow/builder.h>
#endif

using namespace qpqt;
using namespace qpqt::crypto;

static std::vector<uint8_t> pack_int32_column(const std::vector<int32_t>& v) {
    std::vector<uint8_t> b(v.size()*4);
    memcpy(b.data(), v.data(), b.size());
    return b;
}

// ─────────────────────────────────────────────────────────
// Arrow-free fallback: export as CSV (always available)
// ─────────────────────────────────────────────────────────

static int export_structural_csv(
    const std::string& input_path,
    const std::string& output_path
) {
    QpqtReader reader(input_path);
    auto& schema = reader.schema();

    std::ofstream out(output_path);
    if (!out) throw std::runtime_error("Cannot write: " + output_path);

    // Write header — structural columns only
    bool first = true;
    std::vector<size_t> struct_col_indices;

    // Always include __qpqt_row_index for joining
    out << "__qpqt_row_index";
    first = false;

    for (size_t ci = 0; ci < schema.columns.size(); ++ci) {
        auto& col = schema.columns[ci];
        if (!col.is_pqc_encrypted) {
            out << ',' << col.name;
            struct_col_indices.push_back(ci);
        }
    }
    // PQC columns appear as <colname>__pqc_pending
    for (auto& col : schema.columns) {
        if (col.is_pqc_encrypted) {
            out << ',' << col.name << "__pqc_pending";
        }
    }
    out << '\n';

    // Query all rows — structural only (no secret key, no decryption)
    uint64_t s2_bytes = 0;
    auto results = reader.query({}, s2_bytes);

    uint64_t row_idx = 0;
    for (auto& row : results) {
        out << row_idx;

        size_t int32_pos = 0;
        for (size_t ci = 0; ci < schema.columns.size(); ++ci) {
            auto& col = schema.columns[ci];
            if (!col.is_pqc_encrypted) {
                int32_t v = int32_pos < row.int32_values.size()
                          ? row.int32_values[int32_pos++] : 0;
                out << ',' << v;
            }
        }
        // PQC columns as row_index placeholder
        for (auto& col : schema.columns) {
            if (col.is_pqc_encrypted) {
                out << ',' << row_idx; // join key
            }
        }
        out << '\n';
        ++row_idx;
    }

    std::cout << "Exported " << row_idx << " rows to " << output_path << "\n";
    std::cout << "PQC columns are placeholders — join on __qpqt_row_index\n";
    std::cout << "after decrypting with: qpqt decrypt --input " << input_path << "\n";
    return 0;
}

#ifdef QPQT_ARROW_AVAILABLE
// ─────────────────────────────────────────────────────────
// Arrow IPC export — native Arrow format
// Readable by DuckDB, Polars, pandas, Spark
// ─────────────────────────────────────────────────────────

static int export_structural_arrow(
    const std::string& input_path,
    const std::string& output_path
) {
    QpqtReader reader(input_path);
    auto& schema = reader.schema();

    // Build Arrow schema
    std::vector<std::shared_ptr<arrow::Field>> fields;
    fields.push_back(arrow::field("__qpqt_row_index", arrow::int64()));

    for (auto& col : schema.columns) {
        if (!col.is_pqc_encrypted) {
            if (col.type == QpqtColumnType::INT32) {
                fields.push_back(arrow::field(col.name, arrow::int32()));
            } else {
                fields.push_back(arrow::field(col.name, arrow::utf8()));
            }
        } else {
            // PQC columns: int64 row index placeholder + metadata
            auto meta = arrow::KeyValueMetadata::Make(
                {"qpqt_encrypted", "qpqt_algorithm"},
                {"true",           "ML-KEM-768+AES-256-GCM"}
            );
            fields.push_back(arrow::field(
                col.name + "__pqc_pending",
                arrow::int64(),
                true, meta
            ));
        }
    }

    // Add file-level metadata
    auto schema_meta = arrow::KeyValueMetadata::Make(
        {"qpqt_version", "qpqt_source", "qpqt_total_rows"},
        {"1.0",          input_path,
         std::to_string(reader.total_rows())}
    );
    auto arrow_schema = arrow::schema(fields, schema_meta);

    // Open output file
    auto out_file = arrow::io::FileOutputStream::Open(output_path).ValueOrDie();
    auto writer = arrow::ipc::MakeFileWriter(out_file, arrow_schema).ValueOrDie();

    // Read and convert in row group batches
    uint64_t s2_bytes = 0;
    auto results = reader.query({}, s2_bytes);

    // Build arrays
    arrow::Int64Builder   row_idx_builder;
    std::vector<std::shared_ptr<arrow::ArrayBuilder>> builders;

    for (auto& col : schema.columns) {
        if (!col.is_pqc_encrypted) {
            if (col.type == QpqtColumnType::INT32)
                builders.push_back(std::make_shared<arrow::Int32Builder>());
            else
                builders.push_back(std::make_shared<arrow::StringBuilder>());
        } else {
            builders.push_back(std::make_shared<arrow::Int64Builder>());
        }
    }

    int64_t ridx = 0;
    for (auto& row : results) {
        row_idx_builder.Append(ridx);

        size_t int32_pos = 0, pqc_pos = 0;
        for (size_t ci = 0; ci < schema.columns.size(); ++ci) {
            auto& col = schema.columns[ci];
            if (!col.is_pqc_encrypted) {
                if (col.type == QpqtColumnType::INT32) {
                    int32_t v = int32_pos < row.int32_values.size()
                              ? row.int32_values[int32_pos++] : 0;
                    static_cast<arrow::Int32Builder*>(builders[ci].get())->Append(v);
                } else {
                    static_cast<arrow::StringBuilder*>(builders[ci].get())->Append("");
                }
            } else {
                static_cast<arrow::Int64Builder*>(builders[ci].get())->Append(ridx);
                ++pqc_pos;
            }
        }
        ++ridx;
    }

    // Finalize arrays
    std::vector<std::shared_ptr<arrow::Array>> arrays;
    std::shared_ptr<arrow::Array> ridx_arr;
    row_idx_builder.Finish(&ridx_arr);
    arrays.push_back(ridx_arr);

    for (auto& b : builders) {
        std::shared_ptr<arrow::Array> arr;
        b->Finish(&arr);
        arrays.push_back(arr);
    }

    auto batch = arrow::RecordBatch::Make(arrow_schema, ridx, arrays);
    writer->WriteRecordBatch(*batch);
    writer->Close();

    std::cout << "Arrow IPC written: " << output_path << "\n";
    std::cout << "Rows: " << ridx << "\n";
    std::cout << "\nUse in DuckDB:\n";
    std::cout << "  SELECT * FROM read_ipc('" << output_path << "')\n";
    std::cout << "  WHERE state_code = 5\n";
    std::cout << "\nUse in Python:\n";
    std::cout << "  import pyarrow.ipc as ipc\n";
    std::cout << "  table = ipc.open_file('" << output_path << "').read_all()\n";
    std::cout << "  df = table.to_pandas()\n";

    return 0;
}
#endif

// ─────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    std::string mode = "csv"; // default fallback
    std::string input, output;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--input"  && i+1<argc) input  = argv[++i];
        if (a == "--output" && i+1<argc) output = argv[++i];
        if (a == "--format" && i+1<argc) mode   = argv[++i];
    }

    if (input.empty() || output.empty()) {
        std::cout << "Usage: qpqt_arrow --input file.qpqt "
                  << "--output out.arrow [--format csv|arrow]\n";
        return 1;
    }

    try {
#ifdef QPQT_ARROW_AVAILABLE
        if (mode == "arrow")
            return export_structural_arrow(input, output);
#endif
        return export_structural_csv(input, output);
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
