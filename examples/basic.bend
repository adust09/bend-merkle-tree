import Base
import ../src/merkle/chunk.bend as C
import ../src/merkle/tree.bend as M
import ../src/merkle/sha256.bend as SHA

def main() -> IO(Unit):
  left = C.Chunk.zero()
  right = C.Chunk.zero()
  root = M.tree.merkleize(~SHA.sha256_pair, left <> right <> Nil{})
  IO.print(C.Chunk.hex(root))
