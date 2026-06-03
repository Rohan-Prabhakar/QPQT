"""
append_metadata.py
Appends DuckDB extension metadata footer to a built .so file,
producing a valid .duckdb_extension file.

DuckDB extension metadata (512 bytes total, appended to end of .so):
  - 256 bytes: signature (zeros = unsigned)
  - 5 x 32-byte fields in REVERSE order:
      [0] magic_value : "4\0..." (32 bytes)
      [1] platform    : e.g. "linux_amd64" (32 bytes, zero-padded)
      [2] duckdb_version: e.g. "v1.5.3" (32 bytes, zero-padded)
      [3] extension_version: e.g. "0.1.1" (32 bytes, zero-padded)
      [4] abi_type    : "CPP" (32 bytes, zero-padded)

Fields are stored in reverse order (field[4] comes first in the binary,
field[0] = magic comes last), then signature prepended.

Usage:
    python3 append_metadata.py input.so output.duckdb_extension
"""

import sys
import struct
import platform

FOOTER_SIZE    = 512
SIGNATURE_SIZE = 256
FIELD_SIZE     = 32
NUM_FIELDS     = 8   # 8 x 32 = 256 bytes; fields 5-7 are padding zeros

MAGIC_VALUE     = b"4" + b"\x00" * 31
DUCKDB_VERSION  = b"v1.5.3"
EXTENSION_VER   = b"0.1.1"
ABI_TYPE        = b"CPP"

def get_platform():
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        arch = machine
    return f"linux_{arch}".encode()

def pad32(s: bytes) -> bytes:
    return s[:FIELD_SIZE].ljust(FIELD_SIZE, b"\x00")

def build_metadata() -> bytes:
    plat = get_platform()
    # 8 fields × 32 bytes = 256 bytes of field data
    # After DuckDB does std::reverse(), the order becomes [0..7]
    # So in the FILE they are stored as [7][6][5][4][3][2][1][0]
    # Meaning field[0]=magic is at the END of the field block (bytes 224-255)
    fields = [
        pad32(MAGIC_VALUE),         # [0] magic — stored LAST  (bytes 224-255)
        pad32(plat),                # [1] platform             (bytes 192-223)
        pad32(DUCKDB_VERSION),      # [2] duckdb_version       (bytes 160-191)
        pad32(EXTENSION_VER),       # [3] extension_version    (bytes 128-159)
        pad32(ABI_TYPE),            # [4] abi_type             (bytes  96-127)
        pad32(b""),                 # [5] padding              (bytes  64-95)
        pad32(b""),                 # [6] padding              (bytes  32-63)
        pad32(b""),                 # [7] padding — stored FIRST (bytes 0-31)
    ]
    # Stored in reverse so that after std::reverse() they index correctly
    fields_block = b"".join(reversed(fields))  # [7][6][5][4][3][2][1][0] in file
    # Crypto signature follows the field block (zeros = unsigned)
    crypto_sig   = b"\x00" * SIGNATURE_SIZE
    metadata     = fields_block + crypto_sig   # fields first, signature last
    assert len(metadata) == FOOTER_SIZE, f"Expected {FOOTER_SIZE}, got {len(metadata)}"
    return metadata

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} input.so output.duckdb_extension")
        sys.exit(1)

    src, dst = sys.argv[1], sys.argv[2]
    with open(src, "rb") as f:
        data = f.read()

    metadata = build_metadata()
    with open(dst, "wb") as f:
        f.write(data)
        f.write(metadata)

    print(f"Written {dst} ({len(data)} + {FOOTER_SIZE} bytes)")
    print(f"Platform : {get_platform().decode()}")
    print(f"DuckDB   : {DUCKDB_VERSION.decode()}")
    print(f"ABI type : {ABI_TYPE.decode()}")
