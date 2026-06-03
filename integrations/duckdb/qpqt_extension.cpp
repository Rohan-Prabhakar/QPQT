/**
 * qpqt_extension.cpp
 * DuckDB extension entry point for QPQT (DuckDB 1.5.x API).
 *
 * Usage:
 *   LOAD '/path/to/qpqt.duckdb_extension';
 *   SET qpqt_secret_key = '/path/to/secret.bin';
 *   SELECT * FROM read_qpqt('customers.qpqt');
 */

#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/config.hpp"
#include "qpqt_scan.hpp"

DUCKDB_CPP_EXTENSION_ENTRY(qpqt, loader) {
    // Register SET qpqt_secret_key = '/path/to/secret.bin';
    auto& db     = loader.GetDatabaseInstance();
    auto& config = duckdb::DBConfig::GetConfig(db);
    config.AddExtensionOption(
        "qpqt_secret_key",
        "Path to ML-KEM-768 secret key file for QPQT decryption. "
        "PQC columns return NULL when not set.",
        duckdb::LogicalType::VARCHAR,
        duckdb::Value("")
    );

    // Register read_qpqt() table function
    loader.RegisterFunction(qpqt_duckdb::GetQpqtScanFunction());
}
