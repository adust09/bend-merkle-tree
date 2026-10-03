import Base
import ../sha256.bend as SHA
import ../bytes.bend as B

# SHA-256 adapter for the generic Merkle tree. The tree core never imports this
# module: callers opt into SHA-256 by passing `~sha256_pair` as its hash template.

def sha256_pair(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  SHA.sha256(B.Bytes.append(a, b))

def sha256_bytes(bs: List<&2, U32>) -> List<&2, U32>:
  SHA.sha256(bs)

def sha256_hex(bs: List<&2, U32>) -> String:
  SHA.sha256_hex(bs)
