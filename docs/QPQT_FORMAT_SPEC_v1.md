# QPQT File Format — v1 Specification
**Quantum-Safe Columnar Storage Format**
Status: LOCKED — v1 Implementation Target
Date: 2026

---

## 1. Overview

QPQT (`.qpqt`) is a binary columnar storage format designed for
high-performance, post-quantum secure data storage. It integrates
NIST FIPS-203 ML-KEM-768 key encapsulation with AES-256-GCM bulk
encryption, optimized for analytical query workloads via fully
separated column layout and lazy decryption.

---

## 2. Non-Negotiable v1 Constraints

| Parameter | Value | Rationale |
|---|---|---|
| Page size | 4096 rows | Cache line alignment, 244 KEM ops per 1M rows |
| Row group size | 100,000 rows | S3 sizing, parallelism, blast radius |
| Key encapsulation | ML-KEM-768 (FIPS 203) | NIST standard, 128-bit post-quantum security |
| Bulk encryption | AES-256-GCM (FIPS 197) | Quantum-safe, authenticated encryption |
| Key derivation | HKDF-SHA3-256 | Standard, auditable |
| Column layout | Fully separated sections | Cache isolation, OS I/O optimization |
| Crypto manifest | Flat array in footer | O(1) pointer arithmetic, no parsing overhead |
| Auth per row | AES-GCM tag (16 bytes) | Tamper detection, no separate HMAC needed |
| Section alignment | 4KB OS page boundary | Prevents cache pollution between sections |
| Key storage | External KMS via key_id | Public key never embedded in file |

**Cut from v1 (deferred to v2):**
- ML-DSA-65 metadata signatures
- Dynamic metadata allocations
- Separate HMAC layers
- Arrow/Parquet compatibility layer
- Distributed key rotation
- AVX-512 SIMD optimization

---

## 3. Full File Layout

```
┌──────────────────────────────────────────────────────┐
│ FILE HEADER (48 bytes, fixed)                        │
├──────────────────────────────────────────────────────┤
│ SCHEMA BLOCK (variable)                              │
├──────────────────────────────────────────────────────┤
│ KEY REFERENCE BLOCK (32 bytes, fixed)                │
├──────────────────────────────────────────────────────┤
│ ROW GROUP 0                                          │
│  ├── ROW GROUP HEADER (28 bytes)                     │
│  ├── SECTION 1: Structural column chunks             │
│  │   [tightly packed, unencrypted]                   │
│  │   [zero-padded to next 4KB boundary]              │
│  └── SECTION 2: PQC column chunks                   │
│      [starts on 4KB OS page boundary]                │
│      [AES-256-GCM encrypted per row]                 │
├──────────────────────────────────────────────────────┤
│ ROW GROUP 1 ... N                                    │
├──────────────────────────────────────────────────────┤
│ FILE FOOTER                                          │
│  ├── ROW GROUP OFFSET TABLE                          │
│  ├── CRYPTO MANIFEST (flat array)                    │
│  └── FOOTER HEADER (40 bytes, fixed)                 │
└──────────────────────────────────────────────────────┘
```

---

## 4. File Header (48 bytes, fixed)

```
Offset  Size  Field               Notes
0       4     magic_number        = 0x51505154 ("QPQT")
4       2     version_major       = 1
6       2     version_minor       = 0
8       16    file_uuid           random UUID generated at write time
                                  used in IV construction to prevent
                                  cross-file IV reuse under same keypair
24      8     total_rows          uint64
32      4     row_group_count     uint32
36      4     schema_offset       uint32 byte offset from file start
40      4     footer_offset       uint32 byte offset from file start
44      4     reserved            = 0x00000000
```

**Why file_uuid matters:**
AES-GCM IV reuse under the same key is catastrophic — it breaks
confidentiality completely. If the same ML-KEM keypair is reused
across multiple files (standard practice), the file_uuid ensures
IV uniqueness across files without requiring random IV generation
per row.

---

## 5. Schema Block (variable)

```
Offset  Size   Field
0       2      column_count      uint16
Per column (repeated column_count times):
  0     1      name_length       uint8  (max 255)
  1     N      column_name       utf-8 string, not null-terminated
  N+1   1      column_type       uint8
                 0x01 = INT32
                 0x02 = INT64
                 0x03 = FLOAT32
                 0x04 = FLOAT64
                 0x05 = STRING
                 0x06 = DATE32
  N+2   1      is_pqc_encrypted  uint8  (0 = structural, 1 = PQC)
  N+3   4      max_value_bytes   uint32 (max plaintext bytes for this
                                         column, used for fixed-width
                                         page layout in SECTION 2)
```

---

## 6. Key Reference Block (32 bytes, fixed)

```
Offset  Size  Field
0       4     kr_magic          = 0x4B455952 ("KEYR")
4       16    key_id            UUID referencing public key in KMS
20      4     kem_algorithm     = 0x00000003 (ML-KEM-768)
24      8     reserved          = 0x0000000000000000
```

**Design rationale:**
The public key (1184 bytes) is NOT embedded in the file. It lives
in an external KMS indexed by key_id. This is correct for enterprise
deployments where:
- Key rotation must not require rewriting data files
- Access control to the public key is auditable
- Multiple files can reference the same keypair by ID

The reader fetches the public key from KMS using key_id at
decryption time.

---

## 7. Row Group Structure

Each row group contains exactly 100,000 rows except the last
which may be partial.

### 7.1 Row Group Header (28 bytes)

```
Offset  Size  Field
0       4     row_group_index   uint32
4       4     row_count         uint32  (≤ 100,000)
8       8     section1_offset   uint64  byte offset from file start
16      8     section2_offset   uint64  byte offset from file start
24      2     section1_padding  uint16  zero-pad bytes after section 1
26      2     reserved          = 0x0000
```

### 7.2 Section 1 — Structural Column Chunks

Contains all columns where `is_pqc_encrypted = 0`.
Columns are written contiguously, one full column at a time.

```
Per structural column:
  Offset  Size   Field
  0       2      column_index    uint16
  2       8      byte_length     uint64  (total bytes for this column)
  10      N      raw_data        tightly packed values

  INT32  layout: 4 bytes × row_count, no padding between values
  INT64  layout: 8 bytes × row_count
  FLOAT32 layout: 4 bytes × row_count
  DATE32 layout: 4 bytes × row_count (days since Unix epoch)
  STRING layout: uint32 offset_array[row_count+1]
                 followed by concatenated utf-8 string bytes
```

**After the last structural column:**
Zero-pad with 0x00 bytes until the current file offset is a
multiple of 4096. Store the padding byte count in
`row_group_header.section1_padding`.

This guarantees SECTION 2 begins on a 4KB OS page boundary,
enabling the OS to cache SECTION 1 and SECTION 2 in completely
separate page cache entries. A query scanning only SECTION 1
never loads SECTION 2 into CPU cache.

### 7.3 Section 2 — PQC Column Chunks

Starts exactly at a 4KB OS page boundary (enforced by Section 1
padding). Contains all columns where `is_pqc_encrypted = 1`.

```
Per PQC column:
  Offset  Size   Field
  0       2      column_index    uint16
  2       4      page_count      uint32

  Per page (up to 4096 rows):
    Offset  Size   Field
    0       4      page_index          uint32
    4       4      row_count           uint32  (≤ 4096)
    8       4      max_plaintext_len   uint32  (from schema block)
    12      N      row_data            fixed-width rows

    Per row (fixed width = max_plaintext_len + 16):
      0     max_plaintext_len   aes_gcm_ciphertext
      +0    16                  gcm_auth_tag
```

**Why fixed-width rows:**
`max_plaintext_len` is stored once per page header, not per row.
This eliminates 4 bytes of length overhead per row (saves 4MB per
1M rows) and enables O(1) row offset calculation within a page:

```
row_offset = page_data_start + (row_index × (max_plaintext_len + 16))
```

---

## 8. Cryptographic Stack

### 8.1 Key Hierarchy

```
ML-KEM-768 keypair (stored in KMS, referenced by key_id)
    │
    └── Per page (4096 rows), per PQC column:
        ML-KEM-768 encapsulate(public_key)
            ├── kem_ciphertext  → stored in CRYPTO MANIFEST
            └── shared_secret (32 bytes)
                    │
                    └── HKDF-SHA3-256(
                            ikm  = shared_secret,
                            info = page_context
                        )
                            └── aes_page_key (32 bytes)
                                    │
                                    └── AES-256-GCM per row
                                        ├── key: aes_page_key
                                        ├── iv:  12 bytes (see 8.3)
                                        ├── plaintext: PII value
                                        ├── ciphertext: same length
                                        └── auth_tag: 16 bytes
```

### 8.2 Page Context for HKDF

```c
// page_context binds the AES key to a specific page in a specific file
// Prevents ciphertext transplant attacks across files or pages
uint8_t page_context[14] = {
    file_uuid[0..3],        // 4 bytes — file identity
    row_group_index,        // 4 bytes — row group position
    page_index,             // 4 bytes — page position
    column_index            // 2 bytes — column identity
};
```

### 8.3 IV Construction (12 bytes, deterministic)

```c
uint8_t iv[12] = {
    file_uuid[0..3],            // 4 bytes — cross-file uniqueness
    page_index,                 // 4 bytes — cross-page uniqueness
    row_index_within_page,      // 2 bytes — cross-row uniqueness
    column_index                // 2 bytes — cross-column uniqueness
};
```

Guarantees IV uniqueness across:
- Different files using the same keypair (file_uuid)
- Different pages within a file (page_index)
- Different rows within a page (row_index_within_page)
- Different PQC columns (column_index)

No random IV generation required. Fully deterministic and
reproducible for testing.

---

## 9. File Footer

The footer is written last. Readers seek to end of file,
read FOOTER HEADER first, then use offsets for targeted reads.
This is the standard footer-first read pattern (same as Parquet).

### 9.1 Row Group Offset Table

```
Per row group (repeated row_group_count times):
  Offset  Size  Field
  0       4     row_group_index   uint32
  8       8     file_byte_offset  uint64  (RG header start)
  16      8     section1_offset   uint64  (absolute, from file start)
  24      8     section2_offset   uint64  (absolute, from file start)
```

### 9.2 Crypto Manifest (flat array)

```
0       4     manifest_entry_count    uint32

Per entry (1110 bytes each, fixed width):
  0       4     row_group_index   uint32
  4       4     page_index        uint32
  8       2     column_index      uint16
  10      1088  kem_ciphertext    ML-KEM-768 encapsulation output
  1098    12    aes_iv_base       first IV for this page (row 0)
```

**O(1) manifest lookup:**

To find the AES key for row R in PQC column C:

```c
uint32_t rg_index     = R / 100000;
uint32_t page_index   = (R % 100000) / 4096;
uint32_t col_position = pqc_column_position(C);

uint64_t manifest_index =
    (rg_index   × pages_per_rg × pqc_column_count) +
    (page_index × pqc_column_count) +
    col_position;

ManifestEntry* entry = manifest_base_ptr
                     + (manifest_index × 1110);
```

Where:
- `pages_per_rg = ceil(100000 / 4096) = 25`
- `pqc_column_count` stored in FOOTER HEADER
- `manifest_base_ptr` = pointer to first manifest entry

No parsing. No iteration. Pure pointer arithmetic.
Nanosecond-latency key lookup regardless of file size.

### 9.3 Footer Header (40 bytes, fixed)

```
Offset  Size  Field
0       4     magic_end               = 0x54515051 ("TQPQ")
8       8     offset_table_offset     uint64 (from file start)
16      8     manifest_offset         uint64 (from file start)
24      4     manifest_entry_count    uint32
28      2     pqc_column_count        uint16
30      4     pages_per_rg            uint32 = 25
34      4     footer_checksum         CRC32 of entire footer
38      2     reserved                = 0x0000
```

**Why footer_checksum covers the entire footer:**
Detects corruption of the offset table or crypto manifest without
requiring ML-DSA signatures (deferred to v2). CRC32 is sufficient
for corruption detection (not tamper resistance) in v1.

---

## 10. Read Path — Lazy Decryption

```
Step 1:  Seek to (file_size - 40), read FOOTER HEADER
Step 2:  Verify magic_end = 0x54515051, verify CRC32
Step 3:  Read ROW GROUP OFFSET TABLE from footer
Step 4:  Identify target row groups from query range
Step 5:  For each target row group:
         pread() SECTION 1 bytes only into memory
         (section2_offset - section1_offset bytes)
Step 6:  Apply predicates on structural columns
         → produce survivor_indices[]
Step 7:  If survivor_indices is empty:
         → return immediately, SECTION 2 never touched
Step 8:  For each surviving row index R:
         a. Compute manifest_index via O(1) formula
         b. Read manifest entry (1110 bytes)
         c. Fetch public key from KMS using file key_id
         d. ML-KEM-768 decapsulate(kem_ciphertext, private_key)
            → shared_secret
         e. HKDF-SHA3-256(shared_secret, page_context)
            → aes_page_key
         f. Construct IV from file_uuid + page_index
            + row_index_within_page + column_index
         g. AES-256-GCM decrypt row ciphertext
         h. Verify GCM auth tag → reject row if tampered
Step 9:  Return decrypted PII values for surviving rows
```

**KMS call optimization:**
Cache decapsulated aes_page_key per (row_group, page, column).
All rows in the same page share one key — only one KMS call and
one ML-KEM decapsulation per page, not per row.

---

## 11. Write Path

```
Step 1:  Fetch public key from KMS using key_id
Step 2:  Generate file_uuid (16 random bytes)
Step 3:  Write FILE HEADER (leave footer_offset = 0, backfill later)
Step 4:  Write SCHEMA BLOCK
Step 5:  Write KEY REFERENCE BLOCK
Step 6:  Initialize in-memory manifest_buffer[]
Step 7:  For each row group (100K rows):
         a. Record row_group_start_offset
         b. Write ROW GROUP HEADER (leave section2_offset = 0)
         c. Write SECTION 1:
            For each structural column:
              write column_index + byte_length + raw packed values
            Compute padding = (4096 - (offset % 4096)) % 4096
            Write padding zero bytes
            Store padding in row_group_header.section1_padding
         d. Record section2_start_offset (now 4KB aligned)
         e. Write SECTION 2:
            For each PQC column:
              For each page (4096 rows):
                i.   ML-KEM-768 encapsulate(public_key)
                     → kem_ciphertext + shared_secret
                ii.  HKDF-SHA3-256(shared_secret, page_context)
                     → aes_page_key
                iii. Write PAGE HEADER
                iv.  For each row:
                     Construct IV (deterministic)
                     AES-256-GCM encrypt plaintext
                     Write ciphertext + gcm_auth_tag
                v.   Append manifest entry to manifest_buffer
         f. Backfill section2_offset in row group header
Step 8:  Write FILE FOOTER:
         a. Write row group offset table
         b. Write manifest_buffer (flat array)
         c. Compute and write FOOTER HEADER with CRC32
Step 9:  Backfill footer_offset in FILE HEADER (seek to offset 40)
```

---

## 12. Test Cases

### Correctness
- TC-01: Write 1 row, read back, verify PII matches after decryption
- TC-02: Write 4095 rows, verify partial page handled correctly
- TC-03: Write 4096 rows, verify exactly one page, one manifest entry
- TC-04: Write 4097 rows, verify two pages, second page has 1 row
- TC-05: Write 100K rows, verify one complete row group
- TC-06: Write 100001 rows, verify two row groups, second has 1 row
- TC-07: Write 1M rows, read random row 743291, verify PII correct

### Cryptographic
- TC-08: Decrypt with wrong private key, verify clean error returned
- TC-09: Flip one bit in SECTION 2, verify GCM tag rejects tampered row
- TC-10: Verify manifest_entry_count = page_count × pqc_column_count
- TC-11: Verify no two rows in same file share identical IV
- TC-12: Write same data twice, verify different file_uuid each time
          → different IVs despite same keypair

### Lazy Decryption
- TC-13: Query 0% selectivity, verify SECTION 2 bytes read = 0
- TC-14: Query 5% selectivity, verify bytes read ≈ 5% of SECTION 2
- TC-15: Query 100% selectivity, verify full SECTION 2 read

### Performance
- TC-16: Write 1M rows, complete under 60 seconds on 4-core machine
- TC-17: Structural column scan matches benchmark 1 baseline ±20%
- TC-18: 5% selectivity query matches benchmark 2 results ±20%

### Edge Cases
- TC-19: 0 rows → empty file written and read without crash
- TC-20: All columns are PQC (no structural columns), verify works
- TC-21: Truncated file mid-section2 → clean error, no undefined behavior
- TC-22: NULL value in PQC column → encrypted as zero-length ciphertext

---

## 13. File Size Estimate

For 1M rows, 2 structural columns (INT32 + DATE32), 1 PQC STRING
column (avg 40 bytes plaintext):

```
File Header          :          48 bytes
Schema Block         :         ~80 bytes
Key Reference Block  :          32 bytes

Section 1 (per RG × 10 RGs):
  INT32 col          :   4,000,000 bytes
  DATE32 col         :   4,000,000 bytes
  Padding (worst)    :       4,096 bytes
  Total Section 1    :  ~8,004,096 bytes  (~8MB)

Section 2 (per RG × 10 RGs):
  per row = 40 + 16  :  56,000,000 bytes  (~53MB)

Crypto Manifest:
  244 pages × 1 col
  × 1110 bytes       :     270,840 bytes  (~265KB)

Footer               :       ~1,200 bytes

Total                :     ~64MB
vs naive ML-KEM/row  :  ~1,084MB
Storage reduction    :      94.1%
```

---

## 14. Implementation Scope (v1)

**In scope:**
- C++ writer (qpqt_writer.cpp)
- C++ reader with lazy decryption (qpqt_reader.cpp)
- C++ test harness (qpqt_tests.cpp)
- liboqs ML-KEM-768 integration
- OpenSSL AES-256-GCM + HKDF integration
- OpenMP parallelized page encryption
- All 22 test cases passing
- Single-node, single-file operation only

**Out of scope for v1:**
- Apache Arrow / Parquet compatibility
- Distributed operation
- AVX-512 SIMD optimization
- ML-DSA-65 metadata signatures
- Production KMS integration (v1 uses local key files)
- Cloud storage direct integration (S3/Azure Blob)
- Compression of structural columns
