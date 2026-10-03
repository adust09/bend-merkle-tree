import Base
import ../bytes.bend as B

# The unit of every tree in this library: exactly 32 bytes, held as 32 U32
# values in 0..255. Chunks are both the leaves and the internal nodes, so a
# hash for this library is any top-level definition of shape
#
#   def my_hash(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>
#
# passed to the tree functions as a template argument (`~hash`). Bend closures
# are affine: a function value can be called once, which is enough for a single
# node but not for a tree. Templates are substituted at compile time, so a
# template hash is called per node at no indirection cost, and each instantiation
# is type-checked and proven separately.

def Chunk.zero() -> List<&2, U32>:
  B.Bytes.zero32()

def Chunk.is_zero(+c: List<&2, U32>) -> Bool:
  B.Bytes.eq(c, B.Bytes.zero32())

def Chunk.eq(a: List<&2, U32>, b: List<&2, U32>) -> Bool:
  B.Bytes.eq(a, b)

def Chunk.hex(c: List<&2, U32>) -> String:
  B.Bytes.hex(c)

def Chunk.from_hex_valid(valid: Bool, c: List<&2, U32>)
  -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{c}

def Chunk.from_hex_length(+c: List<&2, U32>)
  -> Maybe<&2, List<&2, U32>>:
  +n = List.length(&2, U32, c)
  Chunk.from_hex_valid(Nat.is_eq(n, 32n), c)

def Chunk.from_hex_result(m: Maybe<&2, List<&2, U32>>)
  -> Maybe<&2, List<&2, U32>>:
  match m:
    case None{}:
      None{}
    case Some{c}:
      Chunk.from_hex_length(c)

# Parses exactly one 32-byte chunk. Shorter and longer byte strings are rejected.
def Chunk.from_hex(s: String) -> Maybe<&2, List<&2, U32>>:
  Chunk.from_hex_result(B.Bytes.from_hex(s))

def Chunk.length(+c: List<&2, U32>) -> Nat:
  B.Bytes.len(c)

# Byte sequences longer than one chunk are split into 32-byte chunks, with the
# final chunk padded on the right with zero bytes.
def Chunk.pad_right(c: List<&2, U32>) -> List<&2, U32>:
  +head = B.Bytes.take(c, 32n)
  +n = List.length(&2, U32, head)
  B.Bytes.append(head, B.Bytes.zeros(Nat.sub(32n, n)))

def Chunk.pack_go(n: Nat, +xs: List<&2, U32>, acc: List<&2, List<&2, U32>>)
  -> List<&2, List<&2, U32>>:
  match n:
    case 0n:
      List.reverse(&2, List<&2, U32>, acc)
    case 1n+p:
      +chunk = Chunk.pad_right(B.Bytes.take(xs, 32n))
      +rest = B.Bytes.drop(xs, 32n)
      Chunk.pack_go(p, rest, chunk <> acc)

def Chunk.chunk_count(+bytes_length: Nat) -> Nat:
  +short = Nat.is_lt(0n, Nat.mod(bytes_length, 32n))
  Nat.add(Nat.div(bytes_length, 32n), Bool.pick(Nat, short, 1n, 0n))

def Chunk.pack(+xs: List<&2, U32>) -> List<&2, List<&2, U32>>:
  +n = Chunk.chunk_count(List.length(&2, U32, xs))
  Chunk.pack_go(n, xs, Nil{})
