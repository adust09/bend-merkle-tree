#!/usr/bin/env python3
"""Generate Merkle tree golden vectors with Python stdlib only."""

from __future__ import annotations

from hashlib import sha256

MERKLEIZE_CASES: list[tuple[str, int, int | None]] = [
    ("mz-empty", 0, None),
    ("mz-1", 1, None),
    ("mz-2", 2, None),
    ("mz-3", 3, None),
    ("mz-5", 5, None),
    ("mz-8", 8, None),
    ("mzl-3-8", 3, 8),
    ("mzl-5-1024", 5, 1024),
    ("mzl-0-1024", 0, 1024),
    ("mzl-1-1", 1, 1),
    ("mzl-2-2", 2, 2),
    ("mzl-8-8", 8, 8),
]
ZERO_DEPTHS = (0, 1, 2, 3, 6, 10, 12)
ZERO_CHUNK = bytes(32)


def chunk(index: int) -> bytes:
    """The Bend test chunk: byte j is (index * j + 1) modulo 256."""
    return bytes(((index * j + 1) % 256) for j in range(32))


def pair_hash(left: bytes, right: bytes) -> bytes:
    return sha256(left + right).digest()


def next_pow2(value: int) -> int:
    return 1 if value <= 1 else 1 << (value - 1).bit_length()


def zero_tree(depth: int, hash_pair=pair_hash) -> bytes:
    node = ZERO_CHUNK
    for _ in range(depth):
        node = hash_pair(node, node)
    return node


def merkleize(
    leaves: list[bytes], limit: int | None = None, hash_pair=pair_hash
) -> bytes:
    if limit is not None and len(leaves) > limit:
        raise ValueError("leaf count exceeds limit")
    width = next_pow2(len(leaves) if limit is None else limit)
    if not leaves:
        return zero_tree((width - 1).bit_length(), hash_pair)

    data_width = next_pow2(len(leaves))
    level = list(leaves) + [ZERO_CHUNK] * (data_width - len(leaves))
    while len(level) > 1:
        level = [hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]

    node = level[0]
    data_depth = (data_width - 1).bit_length()
    for depth in range(data_depth, (width - 1).bit_length()):
        node = hash_pair(node, zero_tree(depth, hash_pair))
    return node


def mix_hash(left: bytes, right: bytes) -> bytes:
    """Non-associative test hash: (left + 2 * right + 1) modulo 256."""
    return bytes((a + 2 * b + 1) & 0xFF for a, b in zip(left, right))


def packed(data: bytes) -> str:
    return ",".join(
        data[i : i + 32].ljust(32, b"\0").hex() for i in range(0, len(data), 32)
    )


def sha_lines(chunks: list[bytes]) -> list[str]:
    lines = [f"pair-zero={pair_hash(ZERO_CHUNK, ZERO_CHUNK).hex()}"]
    lines += [f"zero-{depth}={zero_tree(depth).hex()}" for depth in ZERO_DEPTHS]
    for key, count, limit in MERKLEIZE_CASES:
        lines.append(f"{key}={merkleize(chunks[:count], limit).hex()}")
    lines += ["checked-valid=True", "checked-overflow=True"]
    return lines


def utility_lines(chunks: list[bytes]) -> list[str]:
    return [
        "pow2-0=1",
        "pow2-1=1",
        "pow2-5=8",
        "pow2-1024=1024",
        "pow2-2^40=1099511627776",
        "depth-1=0",
        "depth-1024=10",
        "depth-2^40=40",
        "chunk-count-0=0",
        "chunk-count-32=1",
        "chunk-count-33=2",
        "chunk-count-100=4",
        "pack-4=" + packed(bytes(range(4))),
        "pack-100=" + packed(bytes(range(100))),
        "bytes-abc=" + sha256(b"abc").hexdigest(),
        "bytes-empty=" + sha256(b"").hexdigest(),
        "bytes-64=" + sha256(bytes(range(64))).hexdigest(),
        "mix-zero-1=" + zero_tree(1, mix_hash).hex(),
        "mix-zero-3=" + zero_tree(3, mix_hash).hex(),
        "mix-mz-3=" + merkleize(chunks[:3], hash_pair=mix_hash).hex(),
        "mix-mzl-3-8=" + merkleize(chunks[:3], 8, mix_hash).hex(),
        "mix-mzl-2-4=" + merkleize(chunks[:2], 4, mix_hash).hex(),
        "eq-self=True",
        "eq-diff=False",
        "is-zero=True",
        "is-zero-false=False",
        "hex-roundtrip=True",
        "hex-short=True",
    ]


def main() -> None:
    chunks = [chunk(index) for index in range(8)]
    print("\n".join(sha_lines(chunks) + utility_lines(chunks)))


if __name__ == "__main__":
    main()
