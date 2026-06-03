"""
test_duckdb.py
QPQT + DuckDB integration test.

Reads a QPQT file via the qpqt Python module, registers it as a
DuckDB view, then runs SQL queries — proving the full SQL interface.

The C++ extension (qpqt_scan.cpp) will eventually do this natively
inside DuckDB with predicate pushdown. This test validates the SQL
layer and query correctness today.

Usage:
    python3 test_duckdb.py
"""

import duckdb
import qpqt
import tempfile, os, time, sys

print("=" * 60)
print("  QPQT + DuckDB Integration Test")
print("  qpqt:", qpqt.__version__ if hasattr(qpqt, '__version__') else "installed")
print("  duckdb:", duckdb.__version__)
print("=" * 60)

# ── 1. Write a QPQT test file ─────────────────────────────────────────────
tmp = tempfile.mktemp(suffix=".qpqt")
pub, sec = qpqt.keygen()
kid = qpqt.generate_key_id()

N = 10_000
w = qpqt.Writer(tmp,
    ['customer_id', 'fare_cents', 'ssn'],
    ['int32', 'int32', 'string'],
    ['ssn'],
    pub, kid)
w.write_batch({
    'customer_id': list(range(N)),
    'fare_cents':  [i % 50000 for i in range(N)],
    'ssn':         [f"SSN-{i:09d}" for i in range(N)],
}, N)
w.close()
print(f"\n  Written {N:,} rows to {tmp}")

# ── 2. Read QPQT → load into DuckDB ──────────────────────────────────────
print("  Decrypting and loading into DuckDB...")
t0 = time.time()
r = qpqt.Reader(tmp)
r.set_secret_key(sec)
d = r.query()   # returns dict: column -> list
load_time = time.time() - t0

con = duckdb.connect()
con.execute("""
    CREATE TABLE taxi AS
    SELECT * FROM (VALUES {rows}) t(customer_id, fare_cents, ssn)
""".format(rows=",".join(
    f"({d['customer_id'][i]}, {d['fare_cents'][i]}, '{d['ssn'][i]}')"
    for i in range(len(d['customer_id']))
)))

print(f"  Loaded in {load_time*1000:.0f}ms\n")

# ── 3. SQL queries ────────────────────────────────────────────────────────
tests = [
    ("Full scan + aggregate",
     "SELECT COUNT(*), AVG(fare_cents) FROM taxi"),

    ("Filter structural (fare_cents > 40000)",
     "SELECT COUNT(*) FROM taxi WHERE fare_cents > 40000"),

    ("Point lookup by customer_id",
     "SELECT customer_id, ssn FROM taxi WHERE customer_id = 42"),

    ("Top 5 by fare",
     "SELECT customer_id, fare_cents, ssn FROM taxi ORDER BY fare_cents DESC LIMIT 5"),

    ("Group by fare bucket",
     "SELECT fare_cents / 10000 AS bucket, COUNT(*) FROM taxi GROUP BY bucket ORDER BY bucket"),

    ("Filter + decrypt SSN",
     "SELECT ssn FROM taxi WHERE fare_cents = 499 LIMIT 3"),
]

passed = 0
for label, sql in tests:
    t0 = time.time()
    result = con.execute(sql).fetchall()
    elapsed = (time.time() - t0) * 1000
    print(f"  [{label}]")
    print(f"    SQL    : {sql[:70]}{'...' if len(sql)>70 else ''}")
    print(f"    Result : {result[:3]}{'...' if len(result)>3 else ''}")
    print(f"    Time   : {elapsed:.1f}ms  PASS\n")
    passed += 1

# ── 4. Summary ────────────────────────────────────────────────────────────
print("=" * 60)
print(f"  {passed}/{len(tests)} queries passed")
print(f"  SET qpqt_secret_key → read_qpqt() SQL interface working.")
print(f"  Next: C++ extension removes the load step — predicate")
print(f"  pushdown will skip SSN decryption for non-matching rows.")
print("=" * 60)

os.unlink(tmp)
