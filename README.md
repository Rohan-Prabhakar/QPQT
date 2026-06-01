# QPQT - Quantum-Safe Columnar Storage Format

A purpose-built binary columnar file format (`.qpqt`) with native
post-quantum cryptography and row-granular lazy decryption - a capability
no existing columnar format offers.

**Cryptographic stack:** ML-KEM-768 (FIPS 203) + HKDF-SHA3-256 + AES-256-GCM (FIPS 197)

---

## Quick Start

```bash
# 1. Install dependencies (liboqs + OpenSSL)
bash scripts/install_deps.sh

# 2. Build
mkdir build && cd build && cmake .. && make -j$(nproc) && cd ..

# 3. Generate a quantum-safe keypair
./build/qpqt keygen --out-pub pub.bin --out-sec sec.bin

# 4. Encrypt a CSV - ssn and dob become quantum-safe encrypted columns
./build/qpqt encrypt \
    --input customers.csv \
    --pqc-columns ssn,dob \
    --pub-key pub.bin \
    --output customers.qpqt

# 5. Inspect the file (no keys required - safe to run anywhere)
./build/qpqt inspect --input customers.qpqt

# 6. Decrypt for authorized users (lazy - only matching rows decrypted)
./build/qpqt decrypt \
    --input customers.qpqt \
    --sec-key sec.bin \
    --where "customer_id=12345" \
    --output result.csv
```

Python:

```python
import qpqt, pandas as pd

pub, sec = qpqt.keygen()
kid = qpqt.generate_key_id()

# Write
w = qpqt.Writer("customers.qpqt",
                column_names=["id", "state", "ssn"],
                column_types=["int32", "string", "string"],
                pqc_columns=["ssn"],
                public_key=pub, key_id=kid)
w.write_batch({"id":[1,2,3], "state":["CA","NY","TX"], "ssn":["111","222","333"]}, 3)
w.close()

# Read - lazy decryption, only matching rows decrypted
r = qpqt.Reader("customers.qpqt")
r.set_secret_key(sec)
df = pd.DataFrame(r.query(where={"id": 2}))
```

---

## The Problem

Enterprises face a dual mandate: regulatory pressure to adopt post-quantum
cryptography (CNSA 2.0, NIST FIPS 203, deadline 2035) and the need to maintain
query performance on large-scale columnar data warehouses.

The naive approach - applying ML-KEM-768 at the row level - costs **9,600ms**
for 1M rows even with 4-core parallelization. That establishes the upper bound
of the problem: PQC done wrong is unusable at analytical query scale.

## The Solution

QPQT redesigns the storage format around PQC cost:

1. **Hybrid KEM construction** - ML-KEM-768 is used once per 4,096-row page to
   encapsulate an AES-256-GCM page key. This reduces KEM operations from 1M to
   250 per million rows.

2. **Fully separated column sections** - structural (unencrypted) and PQC
   columns are physically isolated on disk at 4KB OS page boundaries. Predicates
   run on structural columns without loading the PQC section into CPU cache.

3. **Row-granular lazy decryption** - predicates execute on cheap structural
   columns first. Only the individual rows that survive the predicate trigger
   KEM decapsulation and AES-GCM decryption.

4. **O(1) manifest lookup** - a flat crypto manifest in the footer maps any row
   to its page key via pointer arithmetic.

## Performance - Honest Three-Baseline Comparison

Benchmarked on Kaggle Xeon CPU (4 cores), 1M rows, real ML-KEM-768 + AES-256-GCM.

Two baselines are measured, not estimated:

- **Naive per-row PQC** - row-level ML-KEM encapsulation. Establishes the upper
  bound of the problem. This is what a quick `liboqs` integration produces.
- **Competent per-page PQC** - the *correct* hybrid KEM construction (per-page
  ML-KEM + AES-GCM, exactly like QPQT) but stored in a plain layout with no
  column separation and no lazy decryption. It decrypts every row in the queried
  column because decryption is chunk-granular. This isolates QPQT's actual
  contribution.

| Selectivity | Naive per-row | Competent per-page | QPQT | QPQT vs competent |
|---|---|---|---|---|
| 1%   | 9,600ms | 2,150ms | **78ms**    | **27.6x** |
| 5%   | 9,600ms | 2,111ms | **163ms**   | **12.9x** |
| 10%  | 9,600ms | 2,113ms | **264ms**   | **8.0x**  |
| 25%  | 9,600ms | 2,103ms | **557ms**   | **3.8x**  |
| 50%  | 9,600ms | 2,148ms | **1,055ms** | **2.0x**  |
| 100% | 9,600ms | 2,147ms | **2,098ms** | **1.02x (no advantage)** |

**Reading this table honestly:**

QPQT's contribution is *row-granular lazy decryption*. At low selectivity -
the common case for analytical queries - it decrypts orders of magnitude fewer
rows than a competent columnar-unaware implementation, giving 8-27x.

As selectivity approaches 100%, the advantage shrinks to parity: when every row
survives the predicate, QPQT and the competent baseline do identical work. **At
100% selectivity QPQT offers no advantage over competent per-page PQC** - and
that is expected, because there is nothing to skip.

The win is real precisely where real queries live: selective filters on large
tables. It is not a universal speedup, and the methodology isolates exactly
what QPQT adds versus what any competent PQC implementation would already do.

Other measured numbers:

| Metric | Value |
|---|---|
| Write throughput (1M rows) | 534K rows/sec (1,871ms) |
| Structural scan (no crypto) | 5ms, 188M rows/sec |
| File size (1M rows) | 80MB |
| Storage vs naive per-row ML-KEM | 80MB vs ~1,084MB (92% reduction) |

## Cryptographic Design

```
ML-KEM-768 keypair  ->  secret key stored in KMS (file holds only key_id)
                                |
                        Per page (4,096 rows):
                        ML-KEM-768 encapsulate(public_key)
                            |-- kem_ciphertext  ->  CRYPTO MANIFEST
                            +-- shared_secret (32 bytes)
                                        |
                                HKDF-SHA3-256(shared_secret, page_context)
                                        +-- aes_page_key (32 bytes, unique per page)
                                                    |
                                            AES-256-GCM per row
                                            |-- IV (12B, deterministic)
                                            |-- ciphertext (= plaintext length)
                                            +-- auth_tag (16B, tamper detection)
```

### IV construction and GCM nonce safety

QPQT uses deterministic AES-GCM IVs. **This is safe because nonce uniqueness is
guaranteed within every key scope.** Each 4,096-row page derives its own unique
AES-256 key via ML-KEM encapsulation + HKDF-SHA3-256. The IV only needs to be
unique under a given key, and within a single page key the `(row_index,
column_index)` tuple is unique by construction. The `file_uuid` component
prevents cross-file collision in the event a page key is ever reused across
files. There is no nonce reuse under any single key - the failure mode that
breaks GCM does not occur.

All components are NIST-approved and quantum-safe:
- ML-KEM-768: FIPS 203 (replaces RSA/ECDH for key establishment)
- AES-256-GCM: FIPS 197 (quantum-safe symmetrically; Grover's only halves the
  effective key strength, leaving 128-bit security)
- HKDF-SHA3-256: SP 800-56C

## Why a Separate Format (and not Parquet)?

A reasonable question: Parquet already has Modular Encryption - why not derive
its AES key from ML-KEM and get quantum-safe Parquet today?

For *encryption alone*, you could. Parquet Modular Encryption does per-column
AES-GCM and you could wrap the key with ML-KEM. **The encryption is not the
contribution.**

The contribution is **row-granular lazy decryption**. Parquet does support
predicate pushdown and can skip entire encrypted column chunks or row groups via
footer statistics - that is real and valuable. What it cannot do is decrypt only
the *surviving rows within a chunk* that the predicate did not eliminate
wholesale. Parquet decrypts at **chunk granularity**, not **surviving-row
granularity**. Closing that specific gap is what requires a format where
structural columns are physically separated (so the predicate runs before any
decryption) and where a manifest addresses individual rows' page keys.

QPQT is a purpose-built format for organizations that need PQC-protected
columnar data with row-granular lazy decryption. Existing tools integrate via
the CLI, Python bindings, and Arrow export rather than reading `.qpqt` natively.

## File Format

```
+-----------------------------------------------------+
| FILE HEADER (48 bytes)                              |
| magic + version + file_uuid + total_rows + offsets  |
+-----------------------------------------------------+
| SCHEMA BLOCK (variable)                             |
+-----------------------------------------------------+
| KEY REFERENCE BLOCK (32 bytes) - key_id, not the key|
+-----------------------------------------------------+
| ROW GROUP 0  (100,000 rows)                         |
|  |-- SECTION 1: Structural columns (unencrypted)    |
|  |   [tightly packed, padded to 4KB boundary]       |
|  +-- SECTION 2: PQC columns (AES-256-GCM per row)   |
|      [starts on 4KB OS page boundary]               |
+-----------------------------------------------------+
| ROW GROUP 1 ... N                                   |
+-----------------------------------------------------+
| FILE FOOTER                                         |
|  |-- Row group offset table                         |
|  |-- CRYPTO MANIFEST (flat array, O(1) lookup)      |
|  +-- FOOTER HEADER (40 bytes) + CRC32               |
+-----------------------------------------------------+
```


## Key Management

```bash
./qpqt keygen --out-pub pub.bin --out-sec sec.bin
```

- `pub.bin` - ML-KEM-768 public key (1184 bytes). Safe to share with writers.
- `sec.bin` - ML-KEM-768 secret key (2400 bytes). **Never share. Never commit.**
- `pub.bin.keyid` - 16-byte key ID. Pass to `--key-id` when encrypting.


| Environment | Recommended key storage |
|---|---|
| Local dev | Outside repo, e.g. `~/.qpqt/keys/` |
| AWS | AWS KMS + Secrets Manager |
| Azure | Azure Key Vault |
| GCP | Cloud KMS |
| Databricks | `dbutils.secrets` |
| On-premise | HashiCorp Vault or HSM |

QPQT stores a `key_id` reference in the file header, not the key itself, so key
rotation never requires rewriting existing data files.


## Build

### Prerequisites
- Ubuntu 22.04 or Debian 12
- CMake 3.16+, OpenSSL 3.x, C++17 compiler with OpenMP

### Steps
```bash
bash scripts/install_deps.sh        # installs liboqs from source
mkdir build && cd build
cmake .. && make -j$(nproc)
./qpqt_tests
```

## Ecosystem Integration

| Tool | How |
|---|---|
| CLI | `qpqt encrypt/decrypt/inspect` on CSV (Parquet with Arrow build) |
| Python / pandas | `pip install .` then `import qpqt` |
| DuckDB / Polars / Spark | `qpqt_arrow export` produces structural columns as Arrow IPC |


## License

MIT

## Author

Rohan Prabhakar
