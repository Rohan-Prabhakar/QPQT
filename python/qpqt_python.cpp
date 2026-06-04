/**
 * qpqt_python.cpp
 * Python bindings for QPQT via pybind11.
 *
 * Install:
 *   pip install pybind11 numpy
 *
 * Build:
 *   g++ -O3 -std=c++17 -fopenmp -shared -fPIC \
 *       $(python3 -m pybind11 --includes) \
 *       -I../include -I/usr/local/include \
 *       qpqt_python.cpp -o qpqt$(python3-config --extension-suffix) \
 *       -L/usr/local/lib -loqs -lssl -lcrypto \
 *       -Wl,-rpath,/usr/local/lib
 *
 * Usage:
 *   import qpqt
 *
 *   # Key generation
 *   pub, sec = qpqt.keygen()
 *
 *   # Write from pandas DataFrame
 *   import pandas as pd
 *   df = pd.read_csv("customers.csv")
 *   writer = qpqt.Writer("customers.qpqt",
 *                         pqc_columns=["ssn", "dob"],
 *                         public_key=pub)
 *   writer.write(df)
 *   writer.close()
 *
 *   # Read back — structural columns only (fast, no crypto)
 *   reader = qpqt.Reader("customers.qpqt")
 *   df_struct = reader.read_structural()
 *
 *   # Decrypt PII for authorized users
 *   reader.set_secret_key(sec)
 *   df_full = reader.query(where={"state": "CA"})
 *
 *   # Schema inspection
 *   print(reader.schema())
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>
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

namespace py = pybind11;
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

// Convert Python bytes to uint8_t vector
static std::vector<uint8_t> bytes_to_vec(const py::bytes& b) {
    std::string s = b;
    return std::vector<uint8_t>(s.begin(), s.end());
}

static py::bytes vec_to_bytes(const std::vector<uint8_t>& v) {
    return py::bytes(reinterpret_cast<const char*>(v.data()), v.size());
}

// ─────────────────────────────────────────────────────────
// PyQpqtWriter — wraps QpqtWriter for Python
// ─────────────────────────────────────────────────────────

class PyQpqtWriter {
public:
    PyQpqtWriter(
        const std::string&          path,
        const std::vector<std::string>& col_names,
        const std::vector<std::string>& col_types,    // "int32" | "string"
        const std::vector<std::string>& pqc_columns,
        const py::bytes&            public_key,
        const py::bytes&            key_id
    ) {
        auto pk_vec  = bytes_to_vec(public_key);
        auto kid_vec = bytes_to_vec(key_id);

        if (pk_vec.size() != ML_KEM_768_PK_LEN)
            throw std::runtime_error("public_key must be " +
                std::to_string(ML_KEM_768_PK_LEN) + " bytes");
        if (kid_vec.size() != 16)
            throw std::runtime_error("key_id must be 16 bytes");

        std::set<std::string> pqc_set(pqc_columns.begin(), pqc_columns.end());

        schema_.column_count = (uint16_t)col_names.size();
        for (size_t i = 0; i < col_names.size(); ++i) {
            QpqtColumnSchema col;
            col.name = col_names[i];
            col.is_pqc_encrypted = pqc_set.count(col_names[i]) > 0;

            const auto& t = col_types[i];
            if      (t == "int32")   col.type = QpqtColumnType::INT32;
            else if (t == "int64")   col.type = QpqtColumnType::INT64;
            else if (t == "float32") col.type = QpqtColumnType::FLOAT32;
            else if (t == "float64") col.type = QpqtColumnType::FLOAT64;
            else if (t == "date32")  col.type = QpqtColumnType::DATE32;
            else                     col.type = QpqtColumnType::STRING;

            col.max_value_bytes = col.is_pqc_encrypted ? 256 : 0;
            schema_.columns.push_back(col);
        }

        uint8_t kid[16];
        memcpy(kid, kid_vec.data(), 16);

        writer_ = std::make_unique<QpqtWriter>(
            path, schema_, kid, pk_vec.data()
        );
    }

    // Write a batch: dict of column_name -> list of values
    void write_batch(
        const std::map<std::string, py::object>& columns,
        size_t num_rows
    ) {
        std::vector<std::vector<uint8_t>> structural;
        std::vector<std::vector<std::string>> pqc;

        for (auto& col : schema_.columns) {
            if (!columns.count(col.name))
                throw std::runtime_error("Missing column: " + col.name);

            auto& pyval = columns.at(col.name);

            if (col.is_pqc_encrypted) {
                py::list lst = pyval.cast<py::list>();
                std::vector<std::string> vals;
                for (auto item : lst) vals.push_back(item.cast<std::string>());
                pqc.push_back(vals);
            } else {
                py::list lst = pyval.cast<py::list>();
                switch (col.type) {
                    case QpqtColumnType::INT32:
                    case QpqtColumnType::DATE32: {
                        std::vector<int32_t> vals;
                        for (auto item : lst) vals.push_back(item.cast<int32_t>());
                        structural.push_back(col.type == QpqtColumnType::INT32
                            ? pack_int32_column(vals) : pack_date32_column(vals));
                        break;
                    }
                    case QpqtColumnType::INT64: {
                        std::vector<int64_t> vals;
                        for (auto item : lst) vals.push_back(item.cast<int64_t>());
                        structural.push_back(pack_int64_column(vals));
                        break;
                    }
                    case QpqtColumnType::FLOAT32: {
                        std::vector<float> vals;
                        for (auto item : lst) vals.push_back(item.cast<float>());
                        structural.push_back(pack_float32_column(vals));
                        break;
                    }
                    case QpqtColumnType::FLOAT64: {
                        std::vector<double> vals;
                        for (auto item : lst) vals.push_back(item.cast<double>());
                        structural.push_back(pack_float64_column(vals));
                        break;
                    }
                    case QpqtColumnType::STRING:
                    default: {
                        std::vector<std::string> vals;
                        for (auto item : lst) vals.push_back(item.cast<std::string>());
                        structural.push_back(pack_string_column(vals));
                        break;
                    }
                }
            }
        }

        writer_->write_row_group((uint32_t)num_rows, structural, pqc);
    }

    void close() {
        if (writer_) {
            writer_->finalize();
            writer_.reset();
        }
    }

    ~PyQpqtWriter() { close(); }

private:
    QpqtSchema                    schema_;
    std::unique_ptr<QpqtWriter>   writer_;
};

// ─────────────────────────────────────────────────────────
// PyQpqtReader — wraps QpqtReader for Python
// ─────────────────────────────────────────────────────────

class PyQpqtReader {
public:
    explicit PyQpqtReader(const std::string& path)
        : reader_(std::make_unique<QpqtReader>(path)) {}

    void set_secret_key(const py::bytes& sk) {
        auto sk_vec = bytes_to_vec(sk);
        if (sk_vec.size() != ML_KEM_768_SK_LEN)
            throw std::runtime_error("secret_key must be " +
                std::to_string(ML_KEM_768_SK_LEN) + " bytes");
        reader_->set_secret_key(sk_vec.data());
    }

    uint64_t total_rows() const { return reader_->total_rows(); }

    // Returns schema as list of dicts
    py::list schema() const {
        py::list result;
        for (auto& col : reader_->schema().columns) {
            py::dict d;
            d["name"]      = col.name;
            d["encrypted"] = col.is_pqc_encrypted;
            d["max_bytes"] = col.max_value_bytes;
            std::string t;
            switch (col.type) {
                case QpqtColumnType::INT32:   t="int32";   break;
                case QpqtColumnType::INT64:   t="int64";   break;
                case QpqtColumnType::FLOAT32: t="float32"; break;
                case QpqtColumnType::FLOAT64: t="float64"; break;
                case QpqtColumnType::STRING:  t="string";  break;
                case QpqtColumnType::DATE32:  t="date32";  break;
            }
            d["type"] = t;
            result.append(d);
        }
        return result;
    }

    // Query with optional predicate dict {col_name: value}
    // Returns dict of column_name -> list of values
    py::dict query(
        const py::dict& where = py::dict()
    ) {
        auto& sch = reader_->schema();

        // Build predicates from where dict
        std::vector<QpqtPredicate> predicates;
        for (auto& item : where) {
            std::string col_name = item.first.cast<std::string>();
            for (uint16_t ci = 0; ci < sch.columns.size(); ++ci) {
                if (sch.columns[ci].name == col_name &&
                    sch.columns[ci].type == QpqtColumnType::INT32 &&
                    !sch.columns[ci].is_pqc_encrypted) {
                    int32_t val = item.second.cast<int32_t>();
                    predicates.push_back({ci, [val](int32_t v){ return v==val; }});
                    break;
                }
            }
        }

        uint64_t s2_bytes = 0;
        auto results = reader_->query(predicates, s2_bytes);

        // Assemble output dict
        py::dict out;
        std::vector<std::string> col_names;
        std::vector<bool>        col_is_pqc;
        std::vector<QpqtColumnType> col_types;

        for (auto& col : sch.columns) {
            col_names.push_back(col.name);
            col_is_pqc.push_back(col.is_pqc_encrypted);
            col_types.push_back(col.type);
        }

        // Pre-allocate lists
        std::map<std::string, py::list> lists;
        for (auto& n : col_names) lists[n] = py::list();

        for (auto& row : results) {
            size_t struct_pos = 0, pqc_pos = 0;
            for (size_t ci = 0; ci < col_names.size(); ++ci) {
                if (!col_is_pqc[ci]) {
                    if (struct_pos < row.structural_values.size()) {
                        auto& cv = row.structural_values[struct_pos];
                        if (cv.is_null) {
                            lists[col_names[ci]].append(py::none());
                        } else {
                            switch (col_types[ci]) {
                                case QpqtColumnType::INT32:
                                case QpqtColumnType::DATE32:
                                    lists[col_names[ci]].append(
                                        std::get<int32_t>(cv.value)); break;
                                case QpqtColumnType::INT64:
                                    lists[col_names[ci]].append(
                                        std::get<int64_t>(cv.value)); break;
                                case QpqtColumnType::FLOAT32:
                                    lists[col_names[ci]].append(
                                        std::get<float>(cv.value)); break;
                                case QpqtColumnType::FLOAT64:
                                    lists[col_names[ci]].append(
                                        std::get<double>(cv.value)); break;
                                case QpqtColumnType::STRING:
                                    lists[col_names[ci]].append(
                                        std::get<std::string>(cv.value)); break;
                                default:
                                    lists[col_names[ci]].append(py::none());
                            }
                        }
                    } else {
                        lists[col_names[ci]].append(py::none());
                    }
                    ++struct_pos;
                } else {
                    std::string v = pqc_pos < row.pqc_values.size()
                                  ? row.pqc_values[pqc_pos] : "";
                    lists[col_names[ci]].append(v);
                    ++pqc_pos;
                }
            }
        }

        for (auto& kv : lists) out[kv.first.c_str()] = kv.second;
        return out;
    }

    // Read structural columns only (no decryption, very fast)
    py::dict read_structural() {
        return query(); // no secret key — PQC columns return empty strings
    }

private:
    std::unique_ptr<QpqtReader> reader_;
};

// ─────────────────────────────────────────────────────────
// Module definition
// ─────────────────────────────────────────────────────────

PYBIND11_MODULE(qpqt, m) {
    m.doc() = "QPQT — Quantum-Safe Columnar Storage Format\n"
              "ML-KEM-768 + HKDF-SHA3-256 + AES-256-GCM";

    // ── keygen ──
    m.def("keygen", []() -> py::tuple {
        std::vector<uint8_t> pk(ML_KEM_768_PK_LEN);
        std::vector<uint8_t> sk(ML_KEM_768_SK_LEN);
        kem_keygen(pk.data(), sk.data());
        return py::make_tuple(vec_to_bytes(pk), vec_to_bytes(sk));
    }, "Generate an ML-KEM-768 keypair.\n"
       "Returns (public_key_bytes, secret_key_bytes)");

    // ── generate_key_id ──
    m.def("generate_key_id", []() -> py::bytes {
        uint8_t kid[16];
        generate_uuid(kid);
        return py::bytes(reinterpret_cast<char*>(kid), 16);
    }, "Generate a random 16-byte key ID");

    // ── Writer ──
    py::class_<PyQpqtWriter>(m, "Writer")
        .def(py::init<
                const std::string&,
                const std::vector<std::string>&,
                const std::vector<std::string>&,
                const std::vector<std::string>&,
                const py::bytes&,
                const py::bytes&
             >(),
             py::arg("path"),
             py::arg("column_names"),
             py::arg("column_types"),
             py::arg("pqc_columns"),
             py::arg("public_key"),
             py::arg("key_id"),
             R"doc(
Create a QPQT writer.

Args:
    path: Output file path (.qpqt)
    column_names: List of column names
    column_types: List of types per column.
                  Structural: "int32", "int64", "float32", "float64", "date32", "string"
                  PQC (encrypted): always "string"
    pqc_columns: Column names to encrypt with ML-KEM-768 + AES-256-GCM
    public_key: ML-KEM-768 public key bytes (from keygen())
    key_id: 16-byte key ID (from generate_key_id())

Example:
    pub, sec = qpqt.keygen()
    kid = qpqt.generate_key_id()
    writer = qpqt.Writer(
        "customers.qpqt",
        column_names=["id", "state", "ssn"],
        column_types=["int32", "string", "string"],
        pqc_columns=["ssn"],
        public_key=pub,
        key_id=kid
    )
    writer.write_batch({"id": [1,2,3], "state": ["CA","NY","TX"], "ssn": ["111","222","333"]}, 3)
    writer.close()
)doc"
        )
        .def("write_batch", &PyQpqtWriter::write_batch,
             py::arg("columns"), py::arg("num_rows"),
             "Write a batch of rows. columns is a dict of name -> list.")
        .def("close", &PyQpqtWriter::close,
             "Finalize and close the file.");

    // ── Reader ──
    py::class_<PyQpqtReader>(m, "Reader")
        .def(py::init<const std::string&>(), py::arg("path"),
             "Open a .qpqt file for reading.")
        .def("set_secret_key", &PyQpqtReader::set_secret_key,
             py::arg("secret_key"),
             "Provide the ML-KEM-768 secret key for PQC column decryption.")
        .def("total_rows", &PyQpqtReader::total_rows,
             "Total number of rows in the file.")
        .def("schema", &PyQpqtReader::schema,
             "Return schema as a list of column dicts.")
        .def("query", &PyQpqtReader::query,
             py::arg("where") = py::dict(),
             R"doc(
Query the file. Returns a dict of column_name -> list of values.

Args:
    where: Optional dict of {column_name: value} predicates.
           Only INT32 structural columns supported for filtering.
           PQC columns are decrypted only for matching rows.

Example:
    # All rows
    data = reader.query()

    # Filtered rows (lazy decryption)
    data = reader.query(where={"state_code": 5})

    df = pd.DataFrame(data)
)doc"
        )
        .def("read_structural", &PyQpqtReader::read_structural,
             "Read only structural (unencrypted) columns at full speed.");

    // ── Constants ──
    m.attr("ML_KEM_768_PK_LEN") = (int)ML_KEM_768_PK_LEN;
    m.attr("ML_KEM_768_SK_LEN") = (int)ML_KEM_768_SK_LEN;
    m.attr("ROWS_PER_PAGE")     = (int)QPQT_ROWS_PER_PAGE;
    m.attr("ROWS_PER_RG")       = (int)QPQT_ROWS_PER_ROW_GROUP;
}
