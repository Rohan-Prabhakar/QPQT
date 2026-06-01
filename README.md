# QPQT — Quantum-Safe Columnar Storage Format

A binary columnar file format (`.qpqt`) with native post-quantum cryptography,
designed for high-performance analytical query workloads.

**Cryptographic stack:** ML-KEM-768 (FIPS 203) + HKDF-SHA3-256 + AES-256-GCM (FIPS 197)

---

## The Problem

Enterprises face a dual mandate: regulatory pressure to adopt post-quantum
cryptography (CNSA 2.0, NIST FIPS 203, deadline 2030) and the need to maintain
query performance on large-scale columnar data warehouses.

Naively applying ML-KEM-768 at the row level on 1M rows costs **9,600ms** even
with 4-core parallelization. That makes PQC unusable at analytical query scale.

## The Solution

QPQT redesigns the storage format around PQC cost:

1. **Hybrid KEM construction** — ML-KEM-768 is used once per 4,096-row page to
   encapsulate an AES-256-GCM page key. This reduces KEM operations from 1M to
   250 per million rows (99.97% reduction).

2. **Fully separated column sections** — structural (unencrypted) and PQC
   columns are physically isolated on disk at 4KB OS page boundaries. Queries
   scan structural columns without loading PQC section into CPU cache.

3. **Lazy decryption** — predicates execute on cheap structural columns first.
   Only surviving rows trigger KEM decapsulation and AES-GCM decryption.

4. **O(1) manifest lookup** — a flat crypto manifest in the footer maps any row
   to its page key via pointer arithmetic. No scanning, no parsing, nanosecond
   latency.

## Performance Results

Benchmarked on Kaggle Xeon CPU (4 cores), 1M rows, real ML-KEM-768 + AES-256-GCM:

| Selectivity | Survivors | Query time | vs naive PQC | Storage |
|---|---|---|---|---|
| 1% | 10,000 | **78ms** | **124x faster** | |
| 5% | 50,000 | **158ms** | **61x faster** | |
| 10% | 100,000 | **249ms** | **39x faster** | |
| 25% | 250,000 | **548ms** | **18x faster** | |
| 50% | 500,000 | **1,010ms** | **10x faster** | |
| 100% | 1,000,000 | **1,941ms** | **5x faster** | |
| Write (1M rows) | — | **1,625ms** | — | **80MB** |
| Structural scan only | — | **4.5ms** | **2,145x faster** | |

> Naive PQC baseline: row-level ML-KEM-768 encapsulation, 4-core OpenMP parallelized = 9,600ms

Storage overhead: **80MB** for 1M rows vs ~1,084MB for naive row-level ML-KEM.
**92% storage reduction** while maintaining identical security guarantees.

## Cryptographic Design

```
ML-KEM-768 keypair  →  stored in KMS (referenced by key_id in file)
                                │
                        Per page (4,096 rows):
                        ML-KEM-768 encapsulate(public_key)
                            ├── kem_ciphertext  →  stored in CRYPTO MANIFEST
                            └── shared_secret (32 bytes)
                                        │
                                HKDF-SHA3-256(shared_secret, page_context)
                                        └── aes_page_key (32 bytes)
                                                    │
                                            AES-256-GCM per row
                                            ├── IV: deterministic (file_uuid + page + row + col)
                                            ├── ciphertext: same length as plaintext
                                            └── auth_tag: 16 bytes (tamper detection)
```

All components are NIST-approved and quantum-safe:
- ML-KEM-768: FIPS 203 (replaces RSA/ECDH for key exchange)
- AES-256-GCM: FIPS 197 (quantum-safe for symmetric encryption via Grover's)
- HKDF-SHA3-256: SP 800-56C

## File Format

```
┌─────────────────────────────────────────────────────┐
│ FILE HEADER (48 bytes)                              │
│ magic + version + file_uuid + total_rows + offsets  │
├─────────────────────────────────────────────────────┤
│ SCHEMA BLOCK (variable)                             │
│ column names + types + is_pqc_encrypted flags       │
├─────────────────────────────────────────────────────┤
│ KEY REFERENCE BLOCK (32 bytes)                      │
│ key_id (UUID) + kem_algorithm                       │
├─────────────────────────────────────────────────────┤
│ ROW GROUP 0  (100,000 rows)                         │
│  ├── SECTION 1: Structural column chunks            │
│  │   [unencrypted, tightly packed, cache-aligned]   │
│  │   [padded to 4KB OS page boundary]               │
│  └── SECTION 2: PQC column chunks                  │
│      [AES-256-GCM encrypted per row]                │
│      [starts on 4KB OS page boundary]               │
├─────────────────────────────────────────────────────┤
│ ROW GROUP 1 ... N                                   │
├─────────────────────────────────────────────────────┤
│ FILE FOOTER                                         │
│  ├── Row group offset table                         │
│  ├── CRYPTO MANIFEST (flat array, O(1) lookup)      │
│  │   per page: kem_ciphertext(1088) + iv_base(12)   │
│  └── FOOTER HEADER (40 bytes) + CRC32               │
└─────────────────────────────────────────────────────┘
```

## Test Coverage

36 tests across correctness, cryptography, lazy decryption, performance, and edge cases:

| Category | Tests | What they verify |
|---|---|---|
| Correctness | TC-01 to TC-07 | Write/read roundtrip at 1, 4095, 4096, 4097, 100K, 100001, 1M rows |
| Cryptographic | TC-08 to TC-12 | Wrong key fails, tamper detection, manifest count, IV uniqueness, cross-file IV |
| Lazy decryption | TC-13 to TC-15 | 0% / 5% / 100% selectivity section 2 read tracking |
| Performance | TC-16 to TC-18 | Write throughput, structural scan, 5% selectivity query |
| Edge cases | TC-19 to TC-22 | All-PQC schema, empty file, truncated file, NULL values |
| End-to-end | TC-W4-01 to W4-05 | Real ML-KEM keypairs, page boundary, RG boundary, lazy query, 1M random access |

## Build

### Prerequisites
- Ubuntu 22.04 or Debian 12
- CMake 3.16+
- OpenSSL 3.x

### Install liboqs
```bash
bash scripts/install_deps.sh
```

### Build
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Run tests
```bash
./qpqt_tests
```

### Run benchmarks
```bash
./qpqt_bench
```
### Key Management
 
### Generate a keypair
 
```bash
./qpqt keygen --out-pub pub.bin --out-sec sec.bin
```
 
This produces:
- `pub.bin` — ML-KEM-768 public key (1184 bytes). Safe to share with writers.
- `sec.bin` — ML-KEM-768 secret key (2400 bytes). **Never share. Never commit.**
- `pub.bin.keyid` — 16-byte key ID. Pass this to `--key-id` when encrypting.

### Where keys should live
 
| Environment | Recommended storage |
|---|---|
| Local development | Outside repo, e.g. `~/.qpqt/keys/` |
| AWS | AWS KMS + Secrets Manager |
| Azure | Azure Key Vault |
| GCP | Cloud KMS |
| Databricks | `dbutils.secrets` |
| On-premise | HashiCorp Vault or HSM |
 
The public key and key_id are safe in pipeline config. The secret key must never touch disk unencrypted in production fetch it from your KMS at runtime.

## Value Addition

**What QPQT adds:**
- ML-KEM integrated at the **binary columnar serialization layer**
- Page-scoped hybrid KEM construction optimized for columnar access patterns
- Lazy decryption tied to predicate pushdown — execution order is the optimization
- First published row-level PQC throughput benchmarks at columnar scale


## License
MIT

## Author

Rohan Prabhakar
