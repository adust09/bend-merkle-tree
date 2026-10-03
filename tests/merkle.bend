import Base
import ../src/bytes.bend as B
import ../src/merkle/chunk.bend as C
import ../src/merkle/tree.bend as M
import ../src/merkle/sha256.bend as S

# Golden vectors for the Merkle library.
#
# The SHA-256 expectations come from the independent perfect-tree reference in
# tests/merkle_golden.py using hashlib.sha256. The
# `mix-` lines run the same tree code through a different pair hash, which is
# what makes "generic over the hash function" a tested property rather than a
# claim.

# Chunk i is the 32 bytes (i*j + 1) mod 256 for j in 0..31.
def chunk_v(+i: Nat, k: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match k:
    case 0n:
      acc
    case 1n+ +p:
      +b = U32.from_nat(Nat.mod(Nat.add(Nat.mul(i, p), 1n), 256n))
      chunk_v(i, p, b <> acc)

def cs(i: Nat) -> List<&2, U32>:
  chunk_v(i, 32n, Nil{})

def chunks_go(n: Nat, acc: List<&2, List<&2, U32>>) -> List<&2, List<&2, U32>>:
  match n:
    case 0n:
      acc
    case 1n+ +p:
      chunks_go(p, cs(p) <> acc)

def chunks(n: Nat) -> List<&2, List<&2, U32>>:
  chunks_go(n, Nil{})

# A toy pair hash, byte-wise (a + 2b + 1) mod 256. Deliberately not associative
# and with no zero identity, so zero trees and limit lifting change the value:
# a tree built with it can only match if the shapes match.
def mix_hash(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  match a:
    case Nil{}:
      Nil{}
    case Con{x, t}:
      match b:
        case Nil{}:
          Nil{}
        case Con{y, u}:
          +y2 = U32.add(U32.shln(y, 1n), 1)
          U32.and(U32.add(x, y2), 255) <> mix_hash(t, u)

def bytes_range(k: Nat, +i: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match k:
    case 0n:
      List.reverse(&2, U32, acc)
    case 1n+p:
      bytes_range(p, Nat.add(i, 1n), U32.from_nat(i) <> acc)

def show_chunks(xs: List<&2, List<&2, U32>>, +sep: String) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{h, t}:
      match t:
        case Nil{}:
          C.Chunk.hex(h)
        case _:
          C.Chunk.hex(h) ++ sep ++ show_chunks(t, sep)

def must_chunk(m: Maybe<&2, List<&2, U32>>) -> List<&2, U32>:
  match m:
    case None{}:
      C.Chunk.zero()
    case Some{c}:
      c

def checked_valid() -> Bool:
  result = M.tree.merkleize_limit_checked(~S.sha256_pair, chunks(3n), 8n)
  Maybe.is_some(&2, List<&2, U32>, result)

def checked_overflow() -> Bool:
  result = M.tree.merkleize_limit_checked(~S.sha256_pair, chunks(3n), 2n)
  Maybe.is_none(&2, List<&2, U32>, result)

def main() -> IO(Unit):
  do IO<Unit>:
    IO.print("pair-zero=" ++ C.Chunk.hex(S.sha256_pair(C.Chunk.zero(), C.Chunk.zero())))
    IO.print("zero-0=" ++ C.Chunk.hex(M.tree.zero_tree(~S.sha256_pair, 0n)))
    IO.print("zero-1=" ++ C.Chunk.hex(M.tree.zero_tree(~S.sha256_pair, 1n)))
    IO.print("zero-2=" ++ C.Chunk.hex(M.tree.zero_tree(~S.sha256_pair, 2n)))
    IO.print("zero-3=" ++ C.Chunk.hex(M.tree.zero_tree(~S.sha256_pair, 3n)))
    IO.print("zero-6=" ++ C.Chunk.hex(M.tree.zero_tree(~S.sha256_pair, 6n)))
    IO.print("zero-10=" ++ C.Chunk.hex(M.tree.zero_tree(~S.sha256_pair, 10n)))
    IO.print("zero-12=" ++ C.Chunk.hex(M.tree.zero_tree(~S.sha256_pair, 12n)))
    IO.print("mz-empty=" ++ C.Chunk.hex(M.tree.merkleize(~S.sha256_pair, chunks(0n))))
    IO.print("mz-1=" ++ C.Chunk.hex(M.tree.merkleize(~S.sha256_pair, chunks(1n))))
    IO.print("mz-2=" ++ C.Chunk.hex(M.tree.merkleize(~S.sha256_pair, chunks(2n))))
    IO.print("mz-3=" ++ C.Chunk.hex(M.tree.merkleize(~S.sha256_pair, chunks(3n))))
    IO.print("mz-5=" ++ C.Chunk.hex(M.tree.merkleize(~S.sha256_pair, chunks(5n))))
    IO.print("mz-8=" ++ C.Chunk.hex(M.tree.merkleize(~S.sha256_pair, chunks(8n))))
    IO.print("mzl-3-8=" ++ C.Chunk.hex(M.tree.merkleize_limit(~S.sha256_pair, chunks(3n), 8n)))
    IO.print("mzl-5-1024=" ++ C.Chunk.hex(M.tree.merkleize_limit(~S.sha256_pair, chunks(5n), 1024n)))
    IO.print("mzl-0-1024=" ++ C.Chunk.hex(M.tree.merkleize_limit(~S.sha256_pair, chunks(0n), 1024n)))
    IO.print("mzl-1-1=" ++ C.Chunk.hex(M.tree.merkleize_limit(~S.sha256_pair, chunks(1n), 1n)))
    IO.print("mzl-2-2=" ++ C.Chunk.hex(M.tree.merkleize_limit(~S.sha256_pair, chunks(2n), 2n)))
    IO.print("mzl-8-8=" ++ C.Chunk.hex(M.tree.merkleize_limit(~S.sha256_pair, chunks(8n), 8n)))
    IO.print("checked-valid=" ++ Bool.show(checked_valid()))
    IO.print("checked-overflow=" ++ Bool.show(checked_overflow()))
    IO.print("pow2-0=" ++ Nat.show(M.tree.pow2(0n)))
    IO.print("pow2-1=" ++ Nat.show(M.tree.pow2(1n)))
    IO.print("pow2-5=" ++ Nat.show(M.tree.pow2(5n)))
    IO.print("pow2-1024=" ++ Nat.show(M.tree.pow2(1024n)))
    IO.print("pow2-2^40=" ++ Nat.show(M.tree.pow2(Nat.pow(2n, 40n))))
    IO.print("depth-1=" ++ Nat.show(M.tree.depth_of(1n)))
    IO.print("depth-1024=" ++ Nat.show(M.tree.depth_of(1024n)))
    IO.print("depth-2^40=" ++ Nat.show(M.tree.depth_of(Nat.pow(2n, 40n))))
    IO.print("chunk-count-0=" ++ Nat.show(C.Chunk.chunk_count(0n)))
    IO.print("chunk-count-32=" ++ Nat.show(C.Chunk.chunk_count(32n)))
    IO.print("chunk-count-33=" ++ Nat.show(C.Chunk.chunk_count(33n)))
    IO.print("chunk-count-100=" ++ Nat.show(C.Chunk.chunk_count(100n)))
    IO.print("pack-4=" ++ show_chunks(C.Chunk.pack(bytes_range(4n, 0n, Nil{})), ","))
    IO.print("pack-100=" ++ show_chunks(C.Chunk.pack(bytes_range(100n, 0n, Nil{})), ","))
    IO.print("bytes-abc=" ++ S.sha256_hex(97 <> 98 <> 99 <> Nil{}))
    IO.print("bytes-empty=" ++ S.sha256_hex(Nil{}))
    IO.print("bytes-64=" ++ S.sha256_hex(bytes_range(64n, 0n, Nil{})))
    IO.print("mix-zero-1=" ++ C.Chunk.hex(M.tree.zero_tree(~mix_hash, 1n)))
    IO.print("mix-zero-3=" ++ C.Chunk.hex(M.tree.zero_tree(~mix_hash, 3n)))
    IO.print("mix-mz-3=" ++ C.Chunk.hex(M.tree.merkleize(~mix_hash, chunks(3n))))
    IO.print("mix-mzl-3-8=" ++ C.Chunk.hex(M.tree.merkleize_limit(~mix_hash, chunks(3n), 8n)))
    IO.print("mix-mzl-2-4=" ++ C.Chunk.hex(M.tree.merkleize_limit(~mix_hash, chunks(2n), 4n)))
    IO.print("eq-self=" ++ Bool.show(C.Chunk.eq(cs(1n), cs(1n))))
    IO.print("eq-diff=" ++ Bool.show(C.Chunk.eq(cs(1n), cs(2n))))
    IO.print("is-zero=" ++ Bool.show(C.Chunk.is_zero(C.Chunk.zero())))
    IO.print("is-zero-false=" ++ Bool.show(C.Chunk.is_zero(cs(1n))))
    IO.print("hex-roundtrip=" ++ Bool.show(C.Chunk.eq(must_chunk(C.Chunk.from_hex(C.Chunk.hex(cs(3n)))), cs(3n))))
    IO.print("hex-short=" ++ Bool.show(Maybe.is_none(&2, List<&2, U32>, C.Chunk.from_hex("00"))))
