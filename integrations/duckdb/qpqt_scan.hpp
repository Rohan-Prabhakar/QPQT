#pragma once
#include "duckdb.hpp"
#include "duckdb/function/table_function.hpp"

namespace qpqt_duckdb {

duckdb::TableFunction GetQpqtScanFunction();

} // namespace qpqt_duckdb
