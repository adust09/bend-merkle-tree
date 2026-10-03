import Base
import ./chunk.bend as C

# Perfect-binary Merkle trees over 32-byte chunks, generic in the hash function.
#
# Every tree builder below takes the hash as a template argument, `~hash`, so
# any top-level `Chunk -> Chunk -> Chunk` definition can be plugged in:
#
#   merkleize(~MyHash.pair, chunks)
#   merkleize_limit(~MyHash.pair, chunks, 1024n)
#
# The tree shape follows the SSZ specification: chunks are zero padded up to the
# next power of two, a capacity (`limit`) fixes the width instead and the data
# subtree is lifted to it with all-zero siblings, and the empty case is the
# all-zero tree of that width. This is the same shape `ssz.trees.merkleize` in
# eth-ssz computes, which is what leanSpec runs on.

# Smallest power of two greater than or equal to `n`. Returns 1 for 0 and 1,
# matching `ssz.chunks.next_pow2`.
def tree.next_pow2(fuel: Nat, phase: Nat, +n: Nat, +p: Nat, le: Bool) -> Nat:
  match fuel:
    case 0n:
      p
    case 1n+f:
      match phase:
        case 0n:
          tree.next_pow2(f, 1n, n, p, Nat.is_le(n, p))
        case _:
          match le:
            case True{}:
              p
            case False{}:
              tree.next_pow2(f, 0n, n, Nat.mul(p, 2n), False{})

def tree.pow2(n: Nat) -> Nat:
  # `next_pow2` alternates comparison and doubling phases, so two fuel units
  # cover each bit of an SSZ u64 length.
  tree.next_pow2(128n, 0n, n, 1n, False{})

# Depth of a perfect tree whose leaf count is a power of two: 1 -> 0, 8 -> 3.
def tree.log2_pow2(fuel: Nat, n: Nat, d: Nat) -> Nat:
  match fuel:
    case 0n:
      d
    case 1n+p:
      match n:
        case 0n:
          d
        case 1n:
          d
        case _:
          tree.log2_pow2(p, Nat.div(n, 2n), Nat.add(d, 1n))

def tree.depth_of(width: Nat) -> Nat:
  tree.log2_pow2(64n, width, 0n)

# Root of the all-zero perfect tree of the given depth.
def tree.zero_tree(
  ~hash: List<&2, U32> -> List<&2, U32> -> List<&2, U32>, depth: Nat
) -> List<&2, U32>:
  match depth:
    case 0n:
      C.Chunk.zero()
    case 1n+p:
      +z = tree.zero_tree(~hash, p)
      hash(z, z)

def tree.head_chunk(xs: List<&2, List<&2, U32>>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      C.Chunk.zero()
    case Con{h, t}:
      h

# One layer of the tree: pairwise hashes, an odd tail hashed with a zero chunk.
def tree.pair_all(
  ~hash: List<&2, U32> -> List<&2, U32> -> List<&2, U32>,
  xs: List<&2, List<&2, U32>>,
  phase: Nat,
  pending: List<&2, U32>
) -> List<&2, List<&2, U32>>:
  match xs:
    case Nil{}:
      match phase:
        case 0n:
          Nil{}
        case _:
          hash(pending, C.Chunk.zero()) <> Nil{}
    case Con{h, t}:
      match phase:
        case 0n:
          tree.pair_all(~hash, t, 1n, h)
        case _:
          hash(pending, h) <> tree.pair_all(~hash, t, 0n, C.Chunk.zero())

def tree.zero_chunks(
  need: Nat, acc: List<&2, List<&2, U32>>
) -> List<&2, List<&2, U32>>:
  match need:
    case 0n:
      acc
    case 1n+p:
      tree.zero_chunks(p, C.Chunk.zero() <> acc)

def tree.pad_zeros(
  need: Nat, xs: List<&2, List<&2, U32>>
) -> List<&2, List<&2, U32>>:
  List.append(&2, List<&2, U32>, xs, tree.zero_chunks(need, Nil{}))

# Fold a chunk list padded to the perfect width `n` down to a single root.
# `fuel` bounds the recursion at the 64-bit SSZ length limit.
def tree.merkle_pow2(
  ~hash: List<&2, U32> -> List<&2, U32> -> List<&2, U32>,
  fuel: Nat,
  n: Nat,
  xs: List<&2, List<&2, U32>>
) -> List<&2, U32>:
  match fuel:
    case 0n:
      tree.head_chunk(xs)
    case 1n+p:
      match n:
        case 0n:
          C.Chunk.zero()
        case 1n:
          tree.head_chunk(xs)
        case _:
          next = tree.pair_all(~hash, xs, 0n, C.Chunk.zero())
          tree.merkle_pow2(~hash, p, Nat.div(n, 2n), next)

# Merkle root of `xs` with zero padding up to a power of two. The root of the
# empty sequence is the 32-byte zero chunk, as in the SSZ spec (`limit` absent).
def tree.merkleize(
  ~hash: List<&2, U32> -> List<&2, U32> -> List<&2, U32>,
  +xs: List<&2, List<&2, U32>>
) -> List<&2, U32>:
  +n = List.length(&2, List<&2, U32>, xs)
  +w = tree.pow2(n)
  tree.merkle_pow2(~hash, 64n, w, tree.pad_zeros(Nat.sub(w, n), xs))

# Lift a data subtree to a wider tree by hashing in the all-zero sibling at each
# remaining height: node = hash(node, zero_tree(depth)).
def tree.lift(
  ~hash: List<&2, U32> -> List<&2, U32> -> List<&2, U32>,
  steps: Nat,
  depth: Nat,
  node: List<&2, U32>
) -> List<&2, U32>:
  match steps:
    case 0n:
      node
    case 1n+p:
      +depth2 = depth
      tree.lift(~hash, p, Nat.add(depth2, 1n), hash(node, tree.zero_tree(~hash, depth2)))

def tree.merkleize_limit_width(
  ~hash: List<&2, U32> -> List<&2, U32> -> List<&2, U32>,
  +xs: List<&2, List<&2, U32>>,
  +n: Nat,
  limit: Nat,
  empty: Bool
) -> List<&2, U32>:
  match empty:
    case True{}:
      tree.zero_tree(~hash, tree.depth_of(tree.pow2(limit)))
    case False{}:
      +data_width = tree.pow2(n)
      +limit_width = tree.pow2(limit)
      +data_depth = tree.depth_of(data_width)
      node = tree.merkle_pow2(~hash, 64n, data_width, tree.pad_zeros(Nat.sub(data_width, n), xs))
      tree.lift(~hash, Nat.sub(tree.depth_of(limit_width), data_depth), data_depth, node)

# Merkle root of `xs` inside a tree of `limit` leaves: the data subtree is built
# at the data width and lifted to the capacity width. The empty sequence roots
# to the all-zero tree of the capacity width. This direct form requires
# `length(xs) <= limit`; use `merkleize_limit_checked` for untrusted input.
def tree.merkleize_limit(
  ~hash: List<&2, U32> -> List<&2, U32> -> List<&2, U32>,
  +xs: List<&2, List<&2, U32>>,
  limit: Nat
) -> List<&2, U32>:
  +n = List.length(&2, List<&2, U32>, xs)
  tree.merkleize_limit_width(~hash, xs, n, limit, Nat.is_eq(n, 0n))

def tree.merkleize_limit_if(
  ~hash: List<&2, U32> -> List<&2, U32> -> List<&2, U32>,
  valid: Bool,
  xs: List<&2, List<&2, U32>>,
  limit: Nat
) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{tree.merkleize_limit(~hash, xs, limit)}

# Checked capacity-bounded merkleization for untrusted inputs. Returns None
# instead of silently constructing a wider tree when the leaf count exceeds the
# declared limit.
def tree.merkleize_limit_checked(
  ~hash: List<&2, U32> -> List<&2, U32> -> List<&2, U32>,
  +xs: List<&2, List<&2, U32>>,
  +limit: Nat
) -> Maybe<&2, List<&2, U32>>:
  +n = List.length(&2, List<&2, U32>, xs)
  tree.merkleize_limit_if(~hash, Nat.is_le(n, limit), xs, limit)

# SSZ mix-in for variable-length collections: hash the root with the length
# encoded as a little-endian 64-bit chunk.
def tree.mix_in_length(
  ~hash: List<&2, U32> -> List<&2, U32> -> List<&2, U32>,
  root: List<&2, U32>,
  +length: Nat
) -> List<&2, U32>:
  hash(root, C.Chunk.u64_le(length))
