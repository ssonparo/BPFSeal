#!/usr/bin/env python3
"""BPFSeal P3A: standalone incremental Merkle commitment reference and tests.

Diagnostic userspace model; NOT evidence of kernel performance or attestation.
Uses 64 leaves and explicit domain separation; NOT byte-compatible with
BPFSeal v1's SHA256(1116-byte canonical buffer).
"""
from __future__ import annotations
import argparse
import hashlib
import random
import struct

CAPACITY = 64
EMPTY = None

def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def be32(n: int) -> bytes:
    return struct.pack('>I', n)

def be64(n: int) -> bytes:
    return struct.pack('>Q', n)

def encode_leaf(index: int, item: tuple[bytes, int] | None) -> bytes:
    if item is None:
        body = b'\x00' + (b'\x00' * 16)
    else:
        tag, load_time = item
        assert len(tag) == 8 and 0 <= load_time < 2**64
        body = b'\x01' + tag + be64(load_time)
    return H(b'BPFSeal-Merkle-v1:leaf\x00' + be32(index) + body)

def combine(left: bytes, right: bytes) -> bytes:
    return H(b'BPFSeal-Merkle-v1:node\x00' + left + right)

def finalize(cookie: int, capacity: int, tree_root: bytes) -> bytes:
    return H(b'BPFSeal-Merkle-v1:root\x00' + be64(cookie) + be32(capacity) + tree_root)

class Incremental:
    def __init__(self, cookie: int, capacity: int):
        assert 1 <= capacity <= CAPACITY and 0 <= cookie < 2**64
        self.cookie, self.capacity = cookie, capacity
        self.slots: list[tuple[bytes, int] | None] = [EMPTY] * CAPACITY
        self.nodes = [b''] * (2 * CAPACITY)  # leaves: 64..127, root: 1
        self.generation = 0
        for i in range(CAPACITY):
            self.nodes[CAPACITY+i] = encode_leaf(i, None)
        for i in range(CAPACITY-1, 0, -1):
            self.nodes[i] = combine(self.nodes[2*i], self.nodes[2*i+1])

    def digest(self) -> bytes:
        return finalize(self.cookie, self.capacity, self.nodes[1])

    def update(self, index: int, item: tuple[bytes, int]) -> None:
        assert 0 <= index < self.capacity
        self.slots[index] = item
        self.generation += 1  # even same-object replacement advances generation
        p = CAPACITY + index
        self.nodes[p] = encode_leaf(index, item)
        while p > 1:
            p //= 2
            self.nodes[p] = combine(self.nodes[2*p], self.nodes[2*p+1])

    def delete(self, index: int) -> bool:
        assert 0 <= index < self.capacity
        if self.slots[index] is None:
            return False  # ENOENT: no generation advance
        self.slots[index] = None
        self.generation += 1
        p = CAPACITY + index
        self.nodes[p] = encode_leaf(index, None)
        while p > 1:
            p //= 2
            self.nodes[p] = combine(self.nodes[2*p], self.nodes[2*p+1])
        return True

def independent_rebuild(cookie: int, capacity: int, slots: list) -> bytes:
    # Deliberately separate implementation: bottom-up lists, not stored tree nodes.
    layer = [encode_leaf(i, slots[i]) for i in range(CAPACITY)]
    while len(layer) > 1:
        layer = [combine(layer[j], layer[j+1]) for j in range(0, len(layer), 2)]
    return finalize(cookie, capacity, layer[0])

def exercise(capacity: int, steps: int, seed: int) -> None:
    rng = random.Random(seed)
    obj = Incremental(0x0123456789ABCDEF, capacity)
    A = (bytes.fromhex('614b434cd8324ecc'), 171224815712)
    B = (bytes.fromhex('79aa95555f6b99c7'), 171224868507)
    assert obj.digest() == independent_rebuild(obj.cookie, capacity, obj.slots)
    initial = obj.digest()
    obj.update(0, A)
    same = obj.digest()
    obj.update(0, A)
    assert obj.digest() == same and obj.generation == 2
    obj.update(0, B)
    assert obj.digest() != same
    obj.update(0, A)
    assert obj.digest() == same
    assert obj.delete(0) and obj.digest() == initial
    previous_gen = obj.generation
    assert not obj.delete(0) and obj.generation == previous_gen
    assert obj.digest() == independent_rebuild(obj.cookie, capacity, obj.slots)
    for i in range(steps):
        slot = rng.randrange(capacity)
        before = obj.generation
        if rng.random() < .3:
            changed = obj.delete(slot)
            assert obj.generation == before + int(changed)
        else:
            obj.update(slot, (A, B)[rng.randrange(2)])
            assert obj.generation == before + 1
        assert obj.digest() == independent_rebuild(obj.cookie, capacity, obj.slots), (capacity, i)
    other = Incremental(obj.cookie ^ 1, capacity)
    assert other.digest() != Incremental(obj.cookie, capacity).digest()
    print(f'PASS capacity={capacity} random_transitions={steps} seed={seed} generation={obj.generation} digest={obj.digest().hex()}')

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--steps', type=int, default=1000)
    p.add_argument('--seed', type=int, default=20261103)
    a = p.parse_args()
    assert 0 <= a.steps <= 100000
    for capacity in (1, 4, 16, 64):
        exercise(capacity, a.steps, a.seed)
    print('P3A_REFERENCE_MODEL: PASS (userspace only; kernel not tested)')
