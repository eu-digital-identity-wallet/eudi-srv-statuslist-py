"""Status list bits, index allocation and the ``full_list.json`` state."""

from __future__ import annotations

import base64
import zlib

import pytest

from app.status_list import BitArray, IssuerStatusList, NoMoreIndices, RandomIndexAllocator

#: Saved by token-status-list 0.1.0a2.dev1: 32 entries, indices 12, 19, 20,
#: 22 and 23 taken, 19 and 20 revoked.
OLD_LIBRARY_DUMP = {
    "allocator": {"type": "random", "allocated": "eNpjELjBAAAB5ADp", "num_allocated": 5},
    "status_list": {"bits": 1, "lst": "eNpjYJBgAAAANAAZ"},
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def test_entry_zero_is_the_least_significant_bit():
    lst = BitArray.with_at_least(1, 16)
    lst.set(0, 1)
    lst.set(9, 1)
    assert bytes(lst.lst) == bytes([0b00000001, 0b00000010])


@pytest.mark.parametrize("bits", [2, 4, 8])
def test_multi_bit_entries(bits):
    lst = BitArray.with_at_least(bits, 8)
    top = (1 << bits) - 1
    lst.set(1, top)
    lst.set(2, 2)
    assert [lst.get(i) for i in range(4)] == [0, top, 2, 0]
    lst.set(1, 1)
    assert lst.get(1) == 1


def test_two_bit_layout_matches_the_draft():
    # Section 4.1 example: statuses 1, 2, 0, 3 in the first byte.
    lst = BitArray.with_at_least(2, 4)
    for index, status in enumerate([1, 2, 0, 3]):
        lst.set(index, status)
    assert bytes(lst.lst) == bytes([0b11001001])


def test_size_rounds_up_to_whole_bytes():
    assert BitArray.with_at_least(1, 10).size == 16
    assert BitArray.with_at_least(8, 3).size == 3


@pytest.mark.parametrize("bits,size", [(3, 8), (1, 0)])
def test_invalid_shapes(bits, size):
    with pytest.raises(ValueError):
        BitArray.with_at_least(bits, size)


@pytest.mark.parametrize("index", [-1, 16, "1"])
def test_index_outside_the_list(index):
    lst = BitArray.with_at_least(1, 16)
    with pytest.raises(IndexError):
        lst.get(index)
    with pytest.raises(IndexError):
        lst.set(index, 1)


@pytest.mark.parametrize("status", [-1, 2, "1"])
def test_status_must_fit(status):
    with pytest.raises(ValueError):
        BitArray.with_at_least(1, 8).set(0, status)


def test_compressed_is_zlib_and_dump_is_base64url():
    lst = BitArray.with_at_least(1, 64)
    lst.set(5, 1)
    assert zlib.decompress(lst.compressed()) == bytes(lst.lst)
    dumped = lst.dump()
    assert dumped == {"bits": 1, "lst": b64url(lst.compressed())}
    assert "=" not in dumped["lst"]
    assert BitArray.load(dumped).lst == lst.lst


@pytest.mark.parametrize(
    "value,error",
    [
        ({"bits": 1}, TypeError),
        ({"bits": "1", "lst": "eJwDAAAAAAE"}, TypeError),
        ({"bits": 3, "lst": b64url(zlib.compress(b"\0"))}, ValueError),
        ({"bits": 1, "lst": "not base64!"}, ValueError),
        ({"bits": 1, "lst": b64url(b"not zlib")}, ValueError),
    ],
)
def test_invalid_dump(value, error):
    with pytest.raises(error):
        BitArray.load(value)


def test_allocator_hands_out_every_index_once():
    allocator = RandomIndexAllocator(BitArray.with_at_least(1, 64))
    taken = [allocator.take() for _ in range(64)]
    assert sorted(taken) == list(range(64))
    with pytest.raises(NoMoreIndices):
        allocator.take()


def test_allocator_counts_taken_indices_itself():
    allocated = BitArray.with_at_least(1, 8)
    for index in range(7):
        allocated.set(index, 1)
    stored = RandomIndexAllocator(allocated).dump() | {"num_allocated": 0}
    allocator = RandomIndexAllocator.load(stored)
    assert allocator.num_allocated == 7
    assert allocator.take() == 7
    with pytest.raises(NoMoreIndices):
        allocator.take()


def test_allocator_picks_uniformly_among_free_indices():
    """A run of taken indices does not favour the free index after it (draft-12 section 12.5.1)."""
    allocated = BitArray.with_at_least(1, 64)
    for index in range(32):
        allocated.set(index, 1)
    counts = dict.fromkeys(range(32, 64), 0)
    for _ in range(4000):
        counts[RandomIndexAllocator(BitArray(1, allocated.lst)).take()] += 1
    assert set(counts) == set(range(32, 64))
    assert 60 < min(counts.values()) and max(counts.values()) < 200  # 125 expected each


def test_allocator_lists_the_free_indices_when_probes_miss(monkeypatch):
    monkeypatch.setattr(RandomIndexAllocator, "PROBES", 0)
    allocated = BitArray.with_at_least(1, 1024)
    for index in range(1024):
        if index != 517:
            allocated.set(index, 1)
    assert RandomIndexAllocator(allocated).take() == 517


def test_allocator_needs_one_bit_entries():
    with pytest.raises(ValueError):
        RandomIndexAllocator(BitArray.with_at_least(2, 8))


@pytest.mark.parametrize(
    "value,error",
    [
        ({"type": "linear", "next": 0, "size": 8}, ValueError),
        ({"type": "random", "allocated": 1}, TypeError),
    ],
)
def test_invalid_allocator_dump(value, error):
    with pytest.raises(error):
        RandomIndexAllocator.load(value)


def test_new_list_never_hands_out_padding_entries():
    lst = IssuerStatusList.new(8, 3)
    assert lst.status_list.size == 3
    assert sorted(lst.allocator.take() for _ in range(3)) == [0, 1, 2]
    with pytest.raises(NoMoreIndices):
        lst.allocator.take()


def test_dump_and_load_round_trip():
    lst = IssuerStatusList.new(1, 16)
    index = lst.allocator.take()
    lst.status_list.set(index, 1)
    loaded = IssuerStatusList.load(lst.dump())
    assert loaded.status_list.get(index) == 1
    assert loaded.allocator.num_allocated == 1
    assert loaded.dump() == lst.dump()


def test_loads_lists_saved_by_the_old_library():
    lst = IssuerStatusList.load(OLD_LIBRARY_DUMP)
    assert lst.status_list.size == 32
    assert [i for i in range(32) if lst.status_list.get(i)] == [19, 20]
    assert lst.allocator.num_allocated == 5
    taken = {lst.allocator.take() for _ in range(27)}
    assert taken == set(range(32)) - {12, 19, 20, 22, 23}
    assert lst.dump()["status_list"] == OLD_LIBRARY_DUMP["status_list"]


@pytest.mark.parametrize(
    "value",
    [
        [],
        {"status_list": OLD_LIBRARY_DUMP["status_list"]},
        {"allocator": OLD_LIBRARY_DUMP["allocator"], "status_list": "x"},
    ],
)
def test_invalid_state(value):
    with pytest.raises(TypeError):
        IssuerStatusList.load(value)


def test_allocator_smaller_than_the_list():
    small = {"type": "random", "allocated": b64url(zlib.compress(b"\0")), "num_allocated": 0}
    with pytest.raises(ValueError):
        IssuerStatusList.load({"allocator": small, "status_list": OLD_LIBRARY_DUMP["status_list"]})
