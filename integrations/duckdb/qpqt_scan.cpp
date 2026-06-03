/**
 * qpqt_scan.cpp
 * DuckDB table function: read_qpqt('file.qpqt')
 *
 * Predicate pushdown on INT32 structural columns avoids decrypting
 * PQC columns for non-matching rows — this is the core USP.
 *
 * Usage:
 *   SET qpqt_secret_key = '/path/to/secret.bin';
 *   SELECT * FROM read_qpqt('customers.qpqt');
 *   SELECT id FROM read_qpqt('customers.qpqt') WHERE id > 100;
 */

#include "qpqt_scan.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/common/types/data_chunk.hpp"
#include "duckdb/planner/filter/constant_filter.hpp"
#include "duckdb/planner/filter/conjunction_filter.hpp"

// Pull in QPQT core
#include "../../include/qpqt_types.h"
#include "../../include/qpqt_utils.h"
#include "../../include/qpqt_crypto.h"

#define QPQT_PACK_INT32_DEFINED
#define QPQT_WRITER_NO_MAIN
#include "../../src/qpqt_writer.cpp"

#define QPQT_READER_NO_MAIN
#undef ASSERT
#include "../../src/qpqt_reader.cpp"

#include <fstream>

namespace qpqt_duckdb {

using namespace duckdb;

// ─────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────

static std::vector<uint8_t> load_key_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("Cannot open QPQT key file: " + path);
    size_t sz = f.tellg(); f.seekg(0);
    std::vector<uint8_t> buf(sz);
    f.read(reinterpret_cast<char*>(buf.data()), sz);
    return buf;
}

static LogicalType qpqt_to_duckdb(QpqtColumnType t, bool is_pqc) {
    if (is_pqc) return LogicalType::VARCHAR;
    switch (t) {
        case QpqtColumnType::INT32:   return LogicalType::INTEGER;
        case QpqtColumnType::INT64:   return LogicalType::BIGINT;
        case QpqtColumnType::FLOAT32: return LogicalType::FLOAT;
        case QpqtColumnType::FLOAT64: return LogicalType::DOUBLE;
        case QpqtColumnType::STRING:  return LogicalType::VARCHAR;
        case QpqtColumnType::DATE32:  return LogicalType::DATE;
        default:                      return LogicalType::VARCHAR;
    }
}

// ─────────────────────────────────────────────────────────
// Bind data
// ─────────────────────────────────────────────────────────

struct QpqtBindData : public TableFunctionData {
    std::string          file_path;
    QpqtSchema           schema;
    uint64_t             total_rows;
    bool                 has_key = false;
    std::vector<uint8_t> secret_key;
};

// ─────────────────────────────────────────────────────────
// Global state
// ─────────────────────────────────────────────────────────

struct QpqtGlobalState : public GlobalTableFunctionState {
    std::unique_ptr<QpqtReader>  reader;
    std::vector<QpqtPredicate>   predicates;
    uint64_t                     current_row = 0;
    uint64_t                     total_rows  = 0;
    bool                         done        = false;
};

// ─────────────────────────────────────────────────────────
// Translate DuckDB filters → QpqtPredicates
// ─────────────────────────────────────────────────────────

static void translate_filter(const TableFilter& filter,
                              uint16_t schema_col,
                              const QpqtSchema& schema,
                              std::vector<QpqtPredicate>& out) {
    if (schema.columns[schema_col].type != QpqtColumnType::INT32) return;
    if (schema.columns[schema_col].is_pqc_encrypted) return;

    if (filter.filter_type == TableFilterType::CONSTANT_COMPARISON) {
        auto& cf = filter.Cast<ConstantFilter>();
        int32_t val = cf.constant.GetValue<int32_t>();
        switch (cf.comparison_type) {
            case ExpressionType::COMPARE_EQUAL:
                out.push_back({schema_col, [val](int32_t v){ return v == val; }}); break;
            case ExpressionType::COMPARE_GREATERTHAN:
                out.push_back({schema_col, [val](int32_t v){ return v > val; }}); break;
            case ExpressionType::COMPARE_GREATERTHANOREQUALTO:
                out.push_back({schema_col, [val](int32_t v){ return v >= val; }}); break;
            case ExpressionType::COMPARE_LESSTHAN:
                out.push_back({schema_col, [val](int32_t v){ return v < val; }}); break;
            case ExpressionType::COMPARE_LESSTHANOREQUALTO:
                out.push_back({schema_col, [val](int32_t v){ return v <= val; }}); break;
            default: break;
        }
    } else if (filter.filter_type == TableFilterType::CONJUNCTION_AND) {
        auto& cf = filter.Cast<ConjunctionAndFilter>();
        for (auto& child : cf.child_filters)
            translate_filter(*child, schema_col, schema, out);
    }
}

// ─────────────────────────────────────────────────────────
// Bind
// ─────────────────────────────────────────────────────────

static unique_ptr<FunctionData> QpqtBind(
    ClientContext&             context,
    TableFunctionBindInput&    input,
    vector<LogicalType>&       return_types,
    vector<string>&            names)
{
    auto bind        = make_uniq<QpqtBindData>();
    bind->file_path  = input.inputs[0].GetValue<string>();

    QpqtReader probe(bind->file_path);
    bind->schema     = probe.schema();
    bind->total_rows = probe.total_rows();

    // Check for secret key setting
    Value key_val;
    if (context.TryGetCurrentSetting("qpqt_secret_key", key_val)) {
        auto key_path = key_val.GetValue<string>();
        if (!key_path.empty()) {
            bind->secret_key = load_key_file(key_path);
            bind->has_key    = (bind->secret_key.size() ==
                                crypto::ML_KEM_768_SK_LEN);
        }
    }

    for (auto& col : bind->schema.columns) {
        names.push_back(col.name);
        return_types.push_back(qpqt_to_duckdb(col.type, col.is_pqc_encrypted));
    }
    return std::move(bind);
}

// ─────────────────────────────────────────────────────────
// InitGlobal
// ─────────────────────────────────────────────────────────

static unique_ptr<GlobalTableFunctionState> QpqtInitGlobal(
    ClientContext&           context,
    TableFunctionInitInput&  input)
{
    auto& bind = input.bind_data->Cast<QpqtBindData>();
    auto state = make_uniq<QpqtGlobalState>();

    state->reader     = make_uniq<QpqtReader>(bind.file_path);
    state->total_rows = bind.total_rows;

    if (bind.has_key)
        state->reader->set_secret_key(bind.secret_key.data());

    // Translate DuckDB pushed-down filters → QPQT predicates
    if (input.filters) {
        for (auto& [col_idx, filter] : input.filters->filters) {
            if (col_idx >= bind.schema.columns.size()) continue;
            translate_filter(*filter, (uint16_t)col_idx,
                             bind.schema, state->predicates);
        }
    }

    return std::move(state);
}

// ─────────────────────────────────────────────────────────
// Scan — fills one DataChunk per call (STANDARD_VECTOR_SIZE rows)
// ─────────────────────────────────────────────────────────

static void QpqtScan(
    ClientContext&        context,
    TableFunctionInput&   data,
    DataChunk&            output)
{
    auto& bind  = data.bind_data->Cast<QpqtBindData>();
    auto& state = data.global_state->Cast<QpqtGlobalState>();

    if (state.done) { output.SetCardinality(0); return; }

    uint64_t s2 = 0;
    auto rows = state.reader->query(
        state.predicates, s2,
        state.current_row, STANDARD_VECTOR_SIZE
    );

    state.current_row += STANDARD_VECTOR_SIZE;
    if (state.current_row >= state.total_rows) state.done = true;

    if (rows.empty()) { output.SetCardinality(0); return; }

    idx_t n = (idx_t)rows.size();
    output.SetCardinality(n);

    // Fill columns
    int struct_idx = 0;
    int pqc_idx    = 0;

    for (idx_t c = 0; c < bind.schema.columns.size(); ++c) {
        auto& col = bind.schema.columns[c];
        auto& vec = output.data[c];

        if (!col.is_pqc_encrypted) {
            // Structural INT32
            if (col.type == QpqtColumnType::INT32) {
                auto* ptr = FlatVector::GetData<int32_t>(vec);
                for (idx_t i = 0; i < n; ++i)
                    ptr[i] = rows[i].int32_values[struct_idx];
            }
            struct_idx++;
        } else {
            // PQC column — VARCHAR
            for (idx_t i = 0; i < n; ++i) {
                if (!bind.has_key) {
                    FlatVector::SetNull(vec, i, true);
                } else {
                    auto& s = rows[i].pqc_values[pqc_idx];
                    FlatVector::GetData<string_t>(vec)[i] =
                        StringVector::AddString(vec, s);
                }
            }
            pqc_idx++;
        }
    }
}

// ─────────────────────────────────────────────────────────
// Build and return the table function (registered by extension entry point)
// ─────────────────────────────────────────────────────────

TableFunction GetQpqtScanFunction() {
    TableFunction fn(
        "read_qpqt",
        {LogicalType::VARCHAR},
        QpqtScan,
        QpqtBind,
        QpqtInitGlobal
    );
    fn.filter_pushdown     = true;
    fn.projection_pushdown = true;
    return fn;
}

} // namespace qpqt_duckdb
