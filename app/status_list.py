# coding: latin-1
###############################################################################
# Copyright (c) 2026 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Based on token-status-list 0.1.0a2.dev1
# (https://github.com/Indicio-tech/token-status-list-py), Copyright Daniel
# Bluhm, Apache License 2.0. Modified: only the status list, the random index
# allocator and their serialization are kept; the signing helpers and the
# linear allocator are removed; indices and stored state are validated.
#
###############################################################################
"""Token Status List: the status bits and the allocation of their indices.

Encoding as in draft-ietf-oauth-status-list-12, section 4: entry 0 is in
the least significant bits of the first byte, and the list is compressed
with DEFLATE in the ZLIB format at the highest level.

:meth:`IssuerStatusList.dump` is what ``full_list.json`` stores; it is the
format of token-status-list 0.1.0a2, so lists written by it still load.
"""

from __future__ import annotations

import base64
import binascii
import secrets
import zlib
from typing import Any

#: Number of bits per entry allowed by the draft.
ALLOWED_BITS = (1, 2, 4, 8)


class NoMoreIndices(Exception):
    """Every index of the list is taken."""


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class BitArray:
    """A list of ``size`` entries of ``bits`` bits each."""

    def __init__(self, bits: int, lst: bytes):
        if bits not in ALLOWED_BITS:
            raise ValueError(f"bits must be one of {ALLOWED_BITS}")
        self.bits = bits
        self.lst = bytearray(lst)
        self.size = len(self.lst) * 8 // bits
        self._mask = (1 << bits) - 1

    @classmethod
    def with_at_least(cls, bits: int, size: int) -> BitArray:
        """An all-zero list of at least ``size`` entries (rounded up to whole bytes)."""
        if bits not in ALLOWED_BITS:
            raise ValueError(f"bits must be one of {ALLOWED_BITS}")
        if size < 1:
            raise ValueError("size must be at least 1")
        return cls(bits, bytes(-(-size * bits // 8)))

    def _position(self, index: int) -> tuple[int, int]:
        """Byte and bit offset of an entry."""
        if not isinstance(index, int) or not 0 <= index < self.size:
            raise IndexError(f"index must be between 0 and {self.size - 1}")
        bit = index * self.bits
        return bit // 8, bit % 8

    def get(self, index: int) -> int:
        """Value of entry ``index``.

        Raises:
            IndexError: ``index`` is outside the list.
        """
        byte, shift = self._position(index)
        return (self.lst[byte] >> shift) & self._mask

    def set(self, index: int, status: int) -> None:
        """Sets entry ``index`` to ``status``.

        Raises:
            IndexError: ``index`` is outside the list.
            ValueError: ``status`` does not fit in ``bits``.
        """
        if not isinstance(status, int) or not 0 <= status <= self._mask:
            raise ValueError(f"status must be between 0 and {self._mask}")
        byte, shift = self._position(index)
        self.lst[byte] = (self.lst[byte] & ~(self._mask << shift)) | (status << shift)

    def compressed(self) -> bytes:
        """The list compressed with ZLIB at the highest level."""
        return zlib.compress(bytes(self.lst), level=9)

    def dump(self) -> dict[str, Any]:
        """``{"bits": ..., "lst": <compressed, base64url without padding>}``."""
        return {"bits": self.bits, "lst": _b64url_encode(self.compressed())}

    @classmethod
    def from_b64(cls, bits: int, value: str) -> BitArray:
        """Reads a compressed, base64url encoded list.

        Raises:
            ValueError: ``value`` is not base64url or not ZLIB.
        """
        try:
            return cls(bits, zlib.decompress(_b64url_decode(value)))
        except (binascii.Error, zlib.error) as e:
            raise ValueError(f"invalid list: {e}") from e

    @classmethod
    def load(cls, value: dict[str, Any]) -> BitArray:
        """Reads what :meth:`dump` returned.

        Raises:
            ValueError, TypeError: Not a valid dump.
        """
        bits, lst = value.get("bits"), value.get("lst")
        if not isinstance(bits, int) or not isinstance(lst, str):
            raise TypeError("status list needs an integer 'bits' and a string 'lst'")
        return cls.from_b64(bits, lst)


class RandomIndexAllocator:
    """Hands out the free indices of a list in random order.

    Every free index is equally likely to be taken next, so the indices keep
    a Relying Party from telling how many credentials were issued, or in
    which order (draft-12 section 12.5.1).
    """

    #: Random positions tried before the free indices are listed.
    PROBES = 32

    def __init__(self, allocated: BitArray):
        if allocated.bits != 1:
            raise ValueError("the allocation map must have 1 bit per entry")
        self.allocated = allocated
        # Counted rather than trusted from the stored state.
        self.num_allocated = int.from_bytes(allocated.lst, "big").bit_count()

    @property
    def size(self) -> int:
        return self.allocated.size

    def take(self) -> int:
        """Takes a free index, uniformly at random among the free ones.

        Random positions are tried first; a nearly full list falls back to
        choosing among its free indices listed.

        Raises:
            NoMoreIndices: Every index is taken.
        """
        if self.num_allocated >= self.size:
            raise NoMoreIndices("All indices are allocated")
        for _ in range(self.PROBES):
            index = secrets.randbelow(self.size)
            if not self.allocated.get(index):
                break
        else:
            lst = self.allocated.lst
            index = secrets.choice(
                [i for i in range(self.size) if not lst[i >> 3] >> (i & 7) & 1]
            )
        self.allocated.set(index, 1)
        self.num_allocated += 1
        return index

    def dump(self) -> dict[str, Any]:
        return {
            "type": "random",
            "allocated": _b64url_encode(self.allocated.compressed()),
            "num_allocated": self.num_allocated,
        }

    @classmethod
    def load(cls, value: dict[str, Any]) -> RandomIndexAllocator:
        """Reads what :meth:`dump` returned (``num_allocated`` is recounted).

        Raises:
            ValueError, TypeError: Not a valid dump.
        """
        if value.get("type") != "random":
            raise ValueError(f"unsupported allocator type {value.get('type')!r}")
        allocated = value.get("allocated")
        if not isinstance(allocated, str):
            raise TypeError("allocator needs a string 'allocated'")
        return cls(BitArray.from_b64(1, allocated))


class IssuerStatusList:
    """A status list and the allocator of its indices."""

    def __init__(self, status_list: BitArray, allocator: RandomIndexAllocator):
        if allocator.size < status_list.size:
            raise ValueError("the allocator is smaller than the status list")
        self.status_list = status_list
        self.allocator = allocator

    @classmethod
    def new(cls, bits: int, size: int) -> IssuerStatusList:
        """An empty list of at least ``size`` entries of ``bits`` bits."""
        status_list = BitArray.with_at_least(bits, size)
        allocated = BitArray.with_at_least(1, status_list.size)
        # The allocation map is whole bytes too: its entries past the list are never handed out.
        for index in range(status_list.size, allocated.size):
            allocated.set(index, 1)
        return cls(status_list, RandomIndexAllocator(allocated))

    def dump(self) -> dict[str, Any]:
        """The state stored in ``full_list.json``."""
        return {"allocator": self.allocator.dump(), "status_list": self.status_list.dump()}

    @classmethod
    def load(cls, value: dict[str, Any]) -> IssuerStatusList:
        """Reads what :meth:`dump` returned.

        Raises:
            ValueError, TypeError: Not a valid dump.
        """
        if not isinstance(value, dict):
            raise TypeError("status list state must be an object")
        allocator, status_list = value.get("allocator"), value.get("status_list")
        if not isinstance(allocator, dict) or not isinstance(status_list, dict):
            raise TypeError("status list state needs 'allocator' and 'status_list' objects")
        return cls(BitArray.load(status_list), RandomIndexAllocator.load(allocator))
