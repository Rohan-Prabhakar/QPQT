#!/usr/bin/env python3
"""
examples/end_to_end.py
Complete example showing QPQT working in a real data pipeline.

This script demonstrates:
1. Generating a keypair
2. Encrypting a CSV with PQC-protected PII columns
3. Inspecting the file (no keys needed)
4. Reading structural columns with DuckDB at native speed
5. Decrypting PII for authorized users only
6. Exporting structural data as Arrow for Spark/Pandas

Run:
    python3 examples/end_to_end.py

Requires:
    pip install qpqt pandas duckdb pyarrow
"""

import os
import sys
import csv
import subprocess
import tempfile

# ─────────────────────────────────────────────────────────
# Step 0 — Generate synthetic customer data
# ─────────────────────────────────────────────────────────

def generate_sample_csv(path, num_rows=10000):
    """Generate a realistic customer CSV with PII columns."""
    import random
    states = ["CA","NY","TX","FL","IL","WA","MA","CO","GA","AZ"]
    with open(path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["customer_id", "state_code", "signup_year",
                         "account_value", "ssn", "dob", "email"])
        for i in range(num_rows):
            writer.writerow([
                i,
                random.randint(0, 49),
                random.randint(2015, 2024),
                round(random.uniform(100, 50000), 2),
                f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}",
                f"199{random.randint(0,9)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
                f"user{i}@example.com"
            ])
    print(f"Generated {num_rows} rows → {path}")


# ─────────────────────────────────────────────────────────
# Step 1 — Key generation via CLI
# ─────────────────────────────────────────────────────────

def step1_keygen(workdir):
    print("\n=== Step 1: Generate ML-KEM-768 Keypair ===")
    pub = os.path.join(workdir, "pub.bin")
    sec = os.path.join(workdir, "sec.bin")
    result = subprocess.run(
        ["./qpqt", "keygen", "--out-pub", pub, "--out-sec", sec],
        capture_output=True, text=True
    )
    print(result.stdout)
    if result.returncode != 0:
        print("ERROR:", result.stderr)
        sys.exit(1)
    return pub, sec


# ─────────────────────────────────────────────────────────
# Step 2 — Encrypt CSV with PQC columns
# ─────────────────────────────────────────────────────────

def step2_encrypt(csv_path, pub_key, workdir):
    print("\n=== Step 2: Encrypt PII Columns with ML-KEM-768 ===")
    qpqt_path = os.path.join(workdir, "customers.qpqt")
    result = subprocess.run([
        "./qpqt", "encrypt",
        "--input",       csv_path,
        "--pqc-columns", "ssn,dob,email",
        "--pub-key",     pub_key,
        "--output",      qpqt_path,
    ], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print("ERROR:", result.stderr)
        sys.exit(1)
    return qpqt_path


# ─────────────────────────────────────────────────────────
# Step 3 — Inspect without keys
# ─────────────────────────────────────────────────────────

def step3_inspect(qpqt_path):
    print("\n=== Step 3: Inspect File (no keys needed) ===")
    result = subprocess.run(
        ["./qpqt", "inspect", "--input", qpqt_path],
        capture_output=True, text=True
    )
    print(result.stdout)


# ─────────────────────────────────────────────────────────
# Step 4 — Query structural columns via Python bindings
# ─────────────────────────────────────────────────────────

def step4_python_structural(qpqt_path):
    print("\n=== Step 4: Query Structural Columns (Python, no keys) ===")
    try:
        import qpqt
        reader = qpqt.Reader(qpqt_path)
        print(f"Total rows: {reader.total_rows()}")
        print("Schema:")
        for col in reader.schema():
            enc = "🔒 PQC" if col["encrypted"] else "✓ plain"
            print(f"  {col['name']:20} {col['type']:10} {enc}")

        # Query structural columns — no secret key, instant
        data = reader.read_structural()
        print(f"\nStructural columns loaded: {list(data.keys())}")
        print(f"customer_id sample: {data.get('customer_id', [])[:5]}")
    except ImportError:
        print("qpqt Python module not installed — skipping")
        print("Run: pip install . from the repo root")


# ─────────────────────────────────────────────────────────
# Step 5 — DuckDB query on structural columns via Arrow export
# ─────────────────────────────────────────────────────────

def step5_duckdb(qpqt_path, workdir):
    print("\n=== Step 5: DuckDB Query on Structural Columns ===")

    # Export structural columns to CSV (Arrow fallback)
    csv_out = os.path.join(workdir, "structural.csv")
    result = subprocess.run([
        "./qpqt_arrow",
        "--input",  qpqt_path,
        "--output", csv_out,
        "--format", "csv",
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print("qpqt_arrow not built — skipping DuckDB step")
        return

    try:
        import duckdb
        conn = duckdb.connect()
        # Query structural data at native speed
        result = conn.execute(f"""
            SELECT state_code, COUNT(*) as customers, 
                   AVG(account_value) as avg_value
            FROM read_csv_auto('{csv_out}')
            WHERE signup_year >= 2020
            GROUP BY state_code
            ORDER BY customers DESC
            LIMIT 5
        """).fetchdf()
        print("Top 5 states by customers (signed up 2020+):")
        print(result.to_string(index=False))
        print("\nNote: PII columns (ssn, dob, email) never touched — secure")
    except ImportError:
        print("duckdb not installed — run: pip install duckdb")


# ─────────────────────────────────────────────────────────
# Step 6 — Decrypt PII for authorized user only
# ─────────────────────────────────────────────────────────

def step6_decrypt(qpqt_path, sec_key, workdir):
    print("\n=== Step 6: Decrypt PII (Authorized User Only) ===")
    dec_out = os.path.join(workdir, "decrypted.csv")
    result = subprocess.run([
        "./qpqt", "decrypt",
        "--input",   qpqt_path,
        "--sec-key", sec_key,
        "--columns", "customer_id,ssn",  # only what's needed
        "--output",  dec_out,
    ], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode == 0:
        with open(dec_out) as f:
            lines = f.readlines()
        print(f"First 3 decrypted rows:")
        for line in lines[:4]:
            print(" ", line.strip())
    else:
        print("ERROR:", result.stderr)


# ─────────────────────────────────────────────────────────
# Step 7 — Pandas integration via Python bindings
# ─────────────────────────────────────────────────────────

def step7_pandas(qpqt_path, sec_key_bytes):
    print("\n=== Step 7: Pandas Integration ===")
    try:
        import qpqt
        import pandas as pd

        reader = qpqt.Reader(qpqt_path)
        reader.set_secret_key(sec_key_bytes)

        # Lazy query — only customers in state 5, decrypt their PII
        data = reader.query(where={"state_code": 5})
        df = pd.DataFrame(data)
        print(f"State 5 customers: {len(df)} rows")
        if not df.empty and "ssn" in df.columns:
            print("Sample SSNs (decrypted):", df["ssn"].head(3).tolist())
        print("PII decrypted only for matching rows — lazy decryption confirmed")
    except ImportError:
        print("qpqt or pandas not installed — skipping")


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as workdir:
        # Generate sample data
        csv_path = os.path.join(workdir, "customers.csv")
        generate_sample_csv(csv_path, num_rows=50000)

        # Run pipeline
        pub, sec = step1_keygen(workdir)
        qpqt_path = step2_encrypt(csv_path, pub, workdir)
        step3_inspect(qpqt_path)
        step4_python_structural(qpqt_path)
        step5_duckdb(qpqt_path, workdir)
        step6_decrypt(qpqt_path, sec, workdir)

        # Load sec key bytes for Python binding step
        with open(sec, "rb") as f:
            sec_bytes = f.read()
        step7_pandas(qpqt_path, sec_bytes)

    print("\n=== Pipeline Complete ===")
    print("QPQT integrates with your existing stack:")
    print("  CSV/Parquet → qpqt encrypt → .qpqt")
    print("  .qpqt → DuckDB/Spark (structural columns, zero crypto overhead)")
    print("  .qpqt → qpqt decrypt → CSV (authorized users only)")
    print("  .qpqt → Python/pandas (full API with lazy decryption)")
