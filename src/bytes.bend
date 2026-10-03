import Base

# Byte strings are lists of U32 values in 0..255.
# Roots and SSZ chunks are 32-byte lists.

def Bytes.len(xs: List<&2, U32>) -> Nat:
  List.length(&2, U32, xs)

def Bytes.append(a: List<&2, U32>, b: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, a, b)

def Bytes.get(xs: List<&2, U32>, i: Nat) -> Maybe<&2, U32>:
  List.get(&2, U32, xs, i)

def Bytes.byte(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      0
    case Some{x}:
      x

def Bytes.at(+xs: List<&2, U32>, i: Nat) -> U32:
  Bytes.byte(Bytes.get(xs, i))

def Bytes.rep(n: Nat, x: U32) -> List<&2, U32>:
  List.replicate(U32, n, x)

def Bytes.take(xs: List<&2, U32>, n: Nat) -> List<&2, U32>:
  List.take(&2, U32, xs, n)

def Bytes.drop(xs: List<&2, U32>, n: Nat) -> List<&2, U32>:
  List.drop(&2, U32, xs, n)

def hex_nib_b(n: U32, low: Bool) -> Char:
  match low:
    case True{}:
      Chr{(48 + n : U32)}
    case False{}:
      Chr{(87 + n : U32)}

def hex_nib(+n: U32) -> Char:
  hex_nib_b(n, U32.is_lt(n, 10))

def hex_pair(+b: U32) -> String:
  String.from_list({[hex_nib(U32.shrn(b, 4n)), hex_nib(U32.and(b, 15))] : List<&2, Char>})

def Bytes.hex(xs: List<&2, U32>) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{h, t}:
      hex_pair(h) ++ Bytes.hex(t)

def nib_val(c: Char) -> Maybe<&2, U32>:
  match c:
    case '0':
      Some{0}
    case '1':
      Some{1}
    case '2':
      Some{2}
    case '3':
      Some{3}
    case '4':
      Some{4}
    case '5':
      Some{5}
    case '6':
      Some{6}
    case '7':
      Some{7}
    case '8':
      Some{8}
    case '9':
      Some{9}
    case 'a':
      Some{10}
    case 'b':
      Some{11}
    case 'c':
      Some{12}
    case 'd':
      Some{13}
    case 'e':
      Some{14}
    case 'f':
      Some{15}
    case 'A':
      Some{10}
    case 'B':
      Some{11}
    case 'C':
      Some{12}
    case 'D':
      Some{13}
    case 'E':
      Some{14}
    case 'F':
      Some{15}
    case _:
      None{}

def maybe_nib(m: Maybe<&2, Char>) -> Maybe<&2, U32>:
  match m:
    case None{}:
      None{}
    case Some{c}:
      nib_val(c)

def hex_pair_m(hi: Maybe<&2, U32>, lo: Maybe<&2, U32>) -> Maybe<&2, U32>:
  match hi lo:
    case Some{h} Some{l}:
      Some{U32.or(U32.shln(h, 4n), l)}
    case _ _:
      None{}

def hex_chars_pair(+cs: List<&2, Char>) -> Maybe<&2, U32>:
  hex_pair_m(maybe_nib(List.get(&2, Char, cs, 0n)), maybe_nib(List.get(&2, Char, cs, 1n)))

def hex_go(
  fuel: Nat,
  phase: Nat,
  +cs: List<&2, Char>,
  acc: List<&2, U32>,
  empty: Bool,
  pair: Maybe<&2, U32>
) -> Maybe<&2, List<&2, U32>>:
  match fuel:
    case 0n:
      None{}
    case 1n+p:
      match phase:
        case 0n:
          match empty:
            case True{}:
              Some{List.reverse(&2, U32, acc)}
            case False{}:
              hex_go(p, 1n, cs, acc, empty, hex_chars_pair(cs))
        case _:
          match pair:
            case None{}:
              None{}
            case Some{b}:
              +rest = List.drop(&2, Char, cs, 2n)
              hex_go(p, 0n, rest, b <> acc, List.is_empty(&2, Char, rest), None{})

def Bytes.from_hex_chars(+cs: List<&2, Char>) -> Maybe<&2, List<&2, U32>>:
  hex_go(Nat.add(List.length(&2, Char, cs), 2n), 0n, cs, Nil{}, List.is_empty(&2, Char, cs), None{})

def from_hex_prefix(s: String, prefixed: Bool) -> Maybe<&2, List<&2, U32>>:
  match prefixed:
    case True{}:
      Bytes.from_hex_chars(String.to_list(String.drop(s, 2n)))
    case False{}:
      Bytes.from_hex_chars(String.to_list(s))

def Bytes.from_hex(+s: String) -> Maybe<&2, List<&2, U32>>:
  from_hex_prefix(s, String.starts_with(s, "0x"))

def Bytes.u64_be_go(fuel: Nat, mode: Nat, +n: Nat, k: Nat, acc: List<&2, U32>, qr: Nat & Nat) -> List<&2, U32>:
  match fuel:
    case 0n:
      acc
    case 1n+p:
      match mode:
        case 0n:
          match k:
            case 0n:
              acc
            case 1n+j:
              Bytes.u64_be_go(p, 1n, n, j, acc, Nat.divmod(n, 256n))
        case _:
          (q, r) = qr
          Bytes.u64_be_go(p, 0n, q, k, U32.from_nat(r) <> acc, (0n, 0n))

def Bytes.u64_be(n: Nat) -> List<&2, U32>:
  Bytes.u64_be_go(20n, 0n, n, 8n, Nil{}, (0n, 0n))

def Bytes.u64_le_go(fuel: Nat, mode: Nat, +n: Nat, k: Nat, acc: List<&2, U32>, qr: Nat & Nat) -> List<&2, U32>:
  match fuel:
    case 0n:
      List.reverse(&2, U32, acc)
    case 1n+p:
      match mode:
        case 0n:
          match k:
            case 0n:
              List.reverse(&2, U32, acc)
            case 1n+j:
              Bytes.u64_le_go(p, 1n, n, j, acc, Nat.divmod(n, 256n))
        case _:
          (q, r) = qr
          Bytes.u64_le_go(p, 0n, q, k, U32.from_nat(r) <> acc, (0n, 0n))

def Bytes.u64_le(n: Nat) -> List<&2, U32>:
  Bytes.u64_le_go(20n, 0n, n, 8n, Nil{}, (0n, 0n))

def Bytes.u32_le(n: U32) -> List<&2, U32>:
  Bytes.take(Bytes.u64_le(U32.to_nat(n)), 4n)

def Bytes.zeros(n: Nat) -> List<&2, U32>:
  Bytes.rep(n, 0)

def Bytes.zero32() -> List<&2, U32>:
  Bytes.zeros(32n)

def Bytes.eq(a: List<&2, U32>, b: List<&2, U32>) -> Bool:
  String.eq(Bytes.hex(a), Bytes.hex(b))
