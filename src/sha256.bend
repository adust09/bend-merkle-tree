import Base
import ./bytes.bend as B

# SHA-256 (FIPS 180-4). Message bytes are U32 values in 0..255.

type Dig is Data:
  Dig{h0: U32, h1: U32, h2: U32, h3: U32, h4: U32, h5: U32, h6: U32, h7: U32}

type Reg is Data:
  Reg{a: U32, b: U32, c: U32, d: U32, e: U32, f: U32, g: U32, h: U32}

def rotr(+x: U32, +n: Nat) -> U32:
  U32.or(U32.shrn(x, n), U32.shln(x, Nat.sub(32n, n)))

def sig0(+x: U32) -> U32:
  U32.xor(U32.xor(rotr(x, 7n), rotr(x, 18n)), U32.shrn(x, 3n))

def sig1(+x: U32) -> U32:
  U32.xor(U32.xor(rotr(x, 17n), rotr(x, 19n)), U32.shrn(x, 10n))

def big_s0(+x: U32) -> U32:
  U32.xor(U32.xor(rotr(x, 2n), rotr(x, 13n)), rotr(x, 22n))

def big_s1(+x: U32) -> U32:
  U32.xor(U32.xor(rotr(x, 6n), rotr(x, 11n)), rotr(x, 25n))

def ch(+e: U32, +f: U32, g: U32) -> U32:
  U32.xor(U32.and(e, f), U32.and(U32.not(e), g))

def maj(+a: U32, +b: U32, +c: U32) -> U32:
  U32.xor(U32.xor(U32.and(a, b), U32.and(a, c)), U32.and(b, c))

def iv() -> Dig:
  Dig{1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225}

def k_table() -> List<&2, U32>:
  {[1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298] : List<&2, U32>}

def k_at(i: Nat) -> U32:
  B.Bytes.byte(List.get(&2, U32, k_table(), i))

def pad_zeros(rem: Nat, le: Bool) -> Nat:
  match le:
    case True{}:
      Nat.sub(56n, rem)
    case False{}:
      Nat.sub(120n, rem)

def pad(+msg: List<&2, U32>) -> List<&2, U32>:
  +len = B.Bytes.len(msg)
  +rem = Nat.mod(Nat.add(len, 1n), 64n)
  z = pad_zeros(rem, Nat.is_le(rem, 56n))
  tail = B.Bytes.append({[128] : List<&2, U32>}, B.Bytes.zeros(z))
  body = B.Bytes.append(B.Bytes.append(msg, tail), B.Bytes.u64_be(Nat.mul(len, 8n)))
  body

def be_word(b0: U32, b1: U32, b2: U32, b3: U32) -> U32:
  U32.or(U32.or(U32.shln(b0, 24n), U32.shln(b1, 16n)), U32.or(U32.shln(b2, 8n), b3))

def word_at(+bs: List<&2, U32>, i: Nat) -> U32:
  +off = Nat.mul(i, 4n)
  be_word(B.Bytes.at(bs, off), B.Bytes.at(bs, Nat.add(off, 1n)), B.Bytes.at(bs, Nat.add(off, 2n)), B.Bytes.at(bs, Nat.add(off, 3n)))

def load_one(w: Array<U32>, +bs: List<&2, U32>, +i: Nat) -> Array<U32>:
  Array.set(U32, w, U32.from_nat(i), word_at(bs, i))

def load16(left: Nat, +bs: List<&2, U32>, w: Array<U32>) -> Array<U32>:
  match left:
    case 0n:
      w
    case 1n+p:
      +p2 = p
      load16(p2, bs, load_one(w, bs, Nat.sub(15n, p2)))

def arr_get(w: Array<U32>, i: U32) -> Array<U32> & U32:
  Array.get(U32, w, i)

def with_w2(idx: U32, x16: U32, +x15: U32, x7: U32, p: Array<U32> & U32) -> Array<U32>:
  (w, x2) = p
  s0 = sig0(x15)
  s1 = sig1(x2)
  Array.set(U32, w, idx, (x16 + s0 + x7 + s1 : U32))

def with_w7(+idx: U32, x16: U32, x15: U32, p: Array<U32> & U32) -> Array<U32>:
  (w, x7) = p
  with_w2(idx, x16, x15, x7, arr_get(w, U32.sub(idx, 2)))

def with_w15(+idx: U32, x16: U32, p: Array<U32> & U32) -> Array<U32>:
  (w, x15) = p
  with_w7(idx, x16, x15, arr_get(w, U32.sub(idx, 7)))

def with_w16_got(+idx: U32, p: Array<U32> & U32) -> Array<U32>:
  (w, x16) = p
  with_w15(idx, x16, arr_get(w, U32.sub(idx, 15)))

def with_w16(+idx: U32, w: Array<U32>) -> Array<U32>:
  with_w16_got(idx, arr_get(w, U32.sub(idx, 16)))

def extend(left: Nat, w: Array<U32>) -> Array<U32>:
  match left:
    case 0n:
      w
    case 1n+p:
      +p2 = p
      extend(p2, with_w16(U32.from_nat(Nat.sub(63n, p2)), w))

def blank_sched() -> Array<U32>:
  [0 : U32^6n]

def schedule(+chunk: List<&2, U32>) -> Array<U32>:
  extend(48n, load16(16n, chunk, blank_sched()))

def apply_round(r: Reg, kw: U32, ww: U32) -> Reg:
  match r:
    case Reg{+a, +b, +c, d, +e, +f, +g, h}:
      s1 = big_s1(e)
      chv = ch(e, f, g)
      +t1 = (h + s1 + chv + kw + ww : U32)
      s0 = big_s0(a)
      mj = maj(a, b, c)
      t2 = (s0 + mj : U32)
      Reg{(t1 + t2 : U32), a, b, c, (d + t1 : U32), e, f, g}

def drop_sched(p: Array<U32> & U32, r: Reg) -> Reg:
  (w, v) = p
  r

def rounds(fuel: Nat, phase: Nat, left: Nat, r: Reg, w: Array<U32>, got: Array<U32> & U32) -> Reg:
  match fuel:
    case 0n:
      drop_sched(arr_get(w, 0), r)
    case 1n+p:
      match phase:
        case 0n:
          match left:
            case 0n:
              drop_sched(arr_get(w, 0), r)
            case 1n+j:
              +j2 = j
              rounds(p, 1n, j2, r, blank_sched(), arr_get(w, U32.from_nat(Nat.sub(63n, j2))))
        case _:
          (w2, ww) = got
          +left2 = left
          rounds(p, 0n, left2, apply_round(r, k_at(Nat.sub(63n, left2)), ww), w2, arr_get(blank_sched(), 0))

def regs_of(d: Dig) -> Reg:
  match d:
    case Dig{h0, h1, h2, h3, h4, h5, h6, h7}:
      Reg{h0, h1, h2, h3, h4, h5, h6, h7}

def add_dig(d: Dig, r: Reg) -> Dig:
  match d r:
    case Dig{h0, h1, h2, h3, h4, h5, h6, h7} Reg{a, b, c, d0, e, f, g, h}:
      Dig{(h0 + a : U32), (h1 + b : U32), (h2 + c : U32), (h3 + d0 : U32), (h4 + e : U32), (h5 + f : U32), (h6 + g : U32), (h7 + h : U32)}

def compress(+d: Dig, chunk: List<&2, U32>) -> Dig:
  add_dig(d, rounds(130n, 0n, 64n, regs_of(d), schedule(chunk), arr_get(blank_sched(), 0)))

def hash_chunks(left: Nat, dig: Dig, +msg: List<&2, U32>) -> Dig:
  match left:
    case 0n:
      dig
    case 1n+p:
      hash_chunks(p, compress(dig, B.Bytes.take(msg, 64n)), B.Bytes.drop(msg, 64n))

def word_bytes(+x: U32) -> List<&2, U32>:
  {[U32.shrn(x, 24n), U32.and(U32.shrn(x, 16n), 255), U32.and(U32.shrn(x, 8n), 255), U32.and(x, 255)] : List<&2, U32>}

def dig_bytes(d: Dig) -> List<&2, U32>:
  match d:
    case Dig{h0, h1, h2, h3, h4, h5, h6, h7}:
      B.Bytes.append(B.Bytes.append(B.Bytes.append(B.Bytes.append(word_bytes(h0), word_bytes(h1)), word_bytes(h2)), word_bytes(h3)), B.Bytes.append(B.Bytes.append(B.Bytes.append(word_bytes(h4), word_bytes(h5)), word_bytes(h6)), word_bytes(h7)))

def sha_padded(+padded: List<&2, U32>) -> List<&2, U32>:
  dig_bytes(hash_chunks(Nat.div(B.Bytes.len(padded), 64n), iv(), padded))

def sha256(msg: List<&2, U32>) -> List<&2, U32>:
  sha_padded(pad(msg))

def sha256_hex(msg: List<&2, U32>) -> String:
  B.Bytes.hex(sha256(msg))
