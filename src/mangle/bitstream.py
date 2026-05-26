"""HEVC (H.265) bitstream primitives.

This module provides the low-level machinery mangle needs to read and rewrite
H.265 bitstreams at the parameter level:

  * splitting an Annex-B byte stream into NAL units (start-code framing)
  * stripping / re-inserting emulation-prevention bytes (RBSP <-> EBSP)
  * an Exp-Golomb-aware bit reader and a matching bit writer

HEVC NAL payloads are coded as RBSP (Raw Byte Sequence Payload). To prevent a
start code (0x000001) from appearing inside payload data, the encoder inserts an
emulation-prevention byte (0x03) after any 0x0000 that would otherwise be
followed by 0x00/0x01/0x02/0x03. We must remove those bytes before parsing and
re-insert them when serialising.

References:
  ITU-T H.265 (HEVC) section 7.3 (syntax) and section 7.4.2 (NAL units).
"""

from __future__ import annotations

from dataclasses import dataclass

START_CODE_LONG = b"\x00\x00\x00\x01"
START_CODE_SHORT = b"\x00\x00\x01"

# HEVC NAL unit type names (nal_unit_type, H.265 Table 7-1). Partial but covers
# everything mangle touches plus the common slice types.
NAL_UNIT_TYPE_NAMES: dict[int, str] = {
    0: "TRAIL_N",
    1: "TRAIL_R",
    2: "TSA_N",
    3: "TSA_R",
    4: "STSA_N",
    5: "STSA_R",
    6: "RADL_N",
    7: "RADL_R",
    8: "RASL_N",
    9: "RASL_R",
    16: "BLA_W_LP",
    17: "BLA_W_RADL",
    18: "BLA_N_LP",
    19: "IDR_W_RADL",
    20: "IDR_N_LP",
    21: "CRA_NUT",
    32: "VPS_NUT",
    33: "SPS_NUT",
    34: "PPS_NUT",
    35: "AUD_NUT",
    39: "PREFIX_SEI_NUT",
    40: "SUFFIX_SEI_NUT",
}

# Slice-segment NAL types: VCL types in [0, 31].
VCL_NAL_TYPES = set(range(0, 32))


@dataclass
class NalUnit:
    """A single NAL unit located within an Annex-B stream.

    Attributes:
        start_code_len: 3 or 4 (length of the leading start code).
        offset: byte offset of the start code within the original stream.
        ebsp: the raw NAL bytes *including* the 2-byte NAL header but *with*
            emulation-prevention bytes still present (the on-wire form).
    """

    start_code_len: int
    offset: int
    ebsp: bytes

    @property
    def nal_unit_type(self) -> int:
        # forbidden_zero_bit(1) | nal_unit_type(6) | nuh_layer_id ...
        return (self.ebsp[0] >> 1) & 0x3F

    @property
    def type_name(self) -> str:
        return NAL_UNIT_TYPE_NAMES.get(self.nal_unit_type, "UNKNOWN")

    @property
    def is_vcl(self) -> bool:
        return self.nal_unit_type in VCL_NAL_TYPES


def split_nal_units(data: bytes) -> list[NalUnit]:
    """Split an Annex-B HEVC stream into its NAL units.

    A NAL unit runs from the byte after its start code up to (but not including)
    the next start code, or end of stream.
    """
    positions: list[tuple[int, int]] = []  # (offset_of_start_code, start_code_len)
    i = 0
    n = len(data)
    while i < n - 2:
        if data[i] == 0 and data[i + 1] == 0:
            if i + 3 < n and data[i + 2] == 0 and data[i + 3] == 1:
                positions.append((i, 4))
                i += 4
                continue
            if data[i + 2] == 1:
                positions.append((i, 3))
                i += 3
                continue
        i += 1

    nals: list[NalUnit] = []
    for idx, (off, sc_len) in enumerate(positions):
        payload_start = off + sc_len
        payload_end = positions[idx + 1][0] if idx + 1 < len(positions) else n
        ebsp = data[payload_start:payload_end]
        nals.append(NalUnit(start_code_len=sc_len, offset=off, ebsp=ebsp))
    return nals


def assemble_nal_units(nals: list[NalUnit]) -> bytes:
    """Reassemble NAL units into an Annex-B byte stream, preserving start codes."""
    out = bytearray()
    for nal in nals:
        out += START_CODE_LONG if nal.start_code_len == 4 else START_CODE_SHORT
        out += nal.ebsp
    return bytes(out)


def ebsp_to_rbsp(ebsp: bytes) -> bytes:
    """Remove emulation-prevention bytes (EBSP -> RBSP).

    Drops the 0x03 in any 0x00 0x00 0x03 sequence (when the byte after 0x03 is
    0x00/0x01/0x02/0x03, which is the only place an encoder inserts it).
    """
    out = bytearray()
    i = 0
    n = len(ebsp)
    while i < n:
        if (
            i + 2 < n
            and ebsp[i] == 0
            and ebsp[i + 1] == 0
            and ebsp[i + 2] == 3
            and (i + 3 >= n or ebsp[i + 3] <= 3)
        ):
            out += b"\x00\x00"
            i += 3
        else:
            out.append(ebsp[i])
            i += 1
    return bytes(out)


def rbsp_to_ebsp(rbsp: bytes) -> bytes:
    """Insert emulation-prevention bytes (RBSP -> EBSP).

    Inserts a 0x03 after any 0x00 0x00 that is followed by 0x00/0x01/0x02/0x03.
    """
    out = bytearray()
    zero_run = 0
    for byte in rbsp:
        if zero_run >= 2 and byte <= 3:
            out.append(0x03)
            zero_run = 0
        out.append(byte)
        zero_run = zero_run + 1 if byte == 0 else 0
    return bytes(out)


class BitReader:
    """Reads bits MSB-first from a byte buffer, with Exp-Golomb support."""

    def __init__(self, data: bytes):
        self._data = data
        self._bitpos = 0

    @property
    def bit_position(self) -> int:
        return self._bitpos

    def read_bit(self) -> int:
        byte_index = self._bitpos >> 3
        if byte_index >= len(self._data):
            raise EOFError("read past end of bitstream")
        bit_offset = 7 - (self._bitpos & 7)
        self._bitpos += 1
        return (self._data[byte_index] >> bit_offset) & 1

    def read_bits(self, count: int) -> int:
        value = 0
        for _ in range(count):
            value = (value << 1) | self.read_bit()
        return value

    def read_ue(self) -> int:
        """Unsigned Exp-Golomb (ue(v))."""
        leading_zeros = 0
        while self.read_bit() == 0:
            leading_zeros += 1
            if leading_zeros > 32:
                raise ValueError("ue(v) leading zeros exceed 32 (corrupt stream)")
        if leading_zeros == 0:
            return 0
        suffix = self.read_bits(leading_zeros)
        return (1 << leading_zeros) - 1 + suffix

    def read_se(self) -> int:
        """Signed Exp-Golomb (se(v))."""
        k = self.read_ue()
        if k == 0:
            return 0
        magnitude = (k + 1) >> 1
        return magnitude if (k & 1) else -magnitude


class BitWriter:
    """Writes bits MSB-first, with Exp-Golomb support."""

    def __init__(self) -> None:
        self._bits: list[int] = []

    @property
    def bit_length(self) -> int:
        return len(self._bits)

    def write_bit(self, bit: int) -> None:
        self._bits.append(bit & 1)

    def write_bits(self, value: int, count: int) -> None:
        for i in range(count - 1, -1, -1):
            self._bits.append((value >> i) & 1)

    def write_ue(self, value: int) -> None:
        if value < 0:
            raise ValueError("ue(v) cannot encode a negative value")
        code = value + 1
        length = code.bit_length()
        # (length - 1) leading zeros, then the `length`-bit code.
        for _ in range(length - 1):
            self._bits.append(0)
        self.write_bits(code, length)

    def write_se(self, value: int) -> None:
        if value == 0:
            self.write_ue(0)
        elif value > 0:
            self.write_ue(2 * value - 1)
        else:
            self.write_ue(-2 * value)

    def to_bytes(self) -> bytes:
        bits = list(self._bits)
        # Pad with a single 1-bit then zeros only if the caller did not already
        # supply trailing bits aligned to a byte boundary. Callers building full
        # RBSPs are responsible for rbsp_trailing_bits(); here we just byte-align
        # with zeros so partial copies remain faithful.
        while len(bits) % 8 != 0:
            bits.append(0)
        out = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for b in bits[i : i + 8]:
                byte = (byte << 1) | b
            out.append(byte)
        return bytes(out)
