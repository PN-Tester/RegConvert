#!/usr/bin/env python3
"""
Created-by: PN-TESTER
Usage:
    python3 RegConvert.py input.reg output.hiv
"""

from __future__ import annotations

import sys
import struct
import hashlib
import re
import codecs
from datetime import datetime, timezone
from pathlib import Path

REGF_SIGNATURE  = b'regf'
HBIN_SIGNATURE  = b'hbin'
NK_SIGNATURE    = b'nk'
VK_SIGNATURE    = b'vk'
SK_SIGNATURE    = b'sk'
LF_SIGNATURE    = b'lf'
LH_SIGNATURE    = b'lh'
RI_SIGNATURE    = b'ri'

# Max subkey entries per LF cell — must fit in one HBIN block
# (4096 - 32 hbin_header - 4 cell_size - 4 lf_header) / 8 bytes_per_entry = 507
MAX_LF_ENTRIES  = 507

BLOCK_SIZE      = 0x1000        # 4096 — both REGF header and HBIN size
HBIN_HEADER_SIZE = 0x20         # 32 bytes

# NK flags
NK_FLAG_VOLATILE    = 0x0001
NK_FLAG_ROOT        = 0x0004
NK_FLAG_LEAF        = 0x0020
NK_FLAG_ASCII       = 0x0020    # name is ASCII (same bit, different docs)

# Value types
REG_NONE                       = 0
REG_SZ                         = 1
REG_EXPAND_SZ                  = 2
REG_BINARY                     = 3
REG_DWORD                      = 4
REG_DWORD_BIG_ENDIAN           = 5
REG_LINK                       = 6
REG_MULTI_SZ                   = 7
REG_RESOURCE_LIST              = 8
REG_FULL_RESOURCE_DESCRIPTOR   = 9
REG_RESOURCE_REQUIREMENTS_LIST = 10
REG_QWORD                      = 11

# Inline-value threshold: if data <= 4 bytes it can go in the offset field
INLINE_DATA_LIMIT = 4

# Big-data threshold: values larger than this use indirect 'db' segments
# (Windows 8+ requirement; many tools expect it for correctness)
BIG_DATA_THRESHOLD = 16344
BIG_DATA_SEGMENT   = 16344  # bytes per db segment

# Timestamp: Windows FILETIME epoch is Jan 1 1601
EPOCH_DIFF = 116444736000000000  # 100-ns intervals between 1601 and 1970



def filetime_now() -> int:
    """Return current time as Windows FILETIME (100-ns intervals since 1601)."""
    ns100 = int(datetime.now(timezone.utc).timestamp() * 1e7)
    return ns100 + EPOCH_DIFF


def align4(n: int) -> int:
    return (n + 3) & ~3


def align8(n: int) -> int:
    return (n + 7) & ~7


def lh_hash(name: str) -> int:
    """Hash used in LH subkey lists (Vista+)."""
    h = 0
    for ch in name.upper():
        h = (h * 37 + ord(ch)) & 0xFFFFFFFF
    return h


# ---------------------------------------------------------------------------
# .reg file parser
# ---------------------------------------------------------------------------

REG_TYPE_MAP = {
    'hex(0)': REG_NONE,
    'hex(1)': REG_SZ,
    'hex(2)': REG_EXPAND_SZ,
    'hex(3)': REG_BINARY,
    'hex(4)': REG_DWORD,
    'hex(5)': REG_DWORD_BIG_ENDIAN,
    'hex(6)': REG_LINK,
    'hex(7)': REG_MULTI_SZ,
    'hex(8)': REG_RESOURCE_LIST,
    'hex(9)': REG_FULL_RESOURCE_DESCRIPTOR,
    'hex(a)': REG_RESOURCE_REQUIREMENTS_LIST,
    'hex(b)': REG_QWORD,
    'hex':    REG_BINARY,
    'dword':  REG_DWORD,
}


class RegValue:
    __slots__ = ('name', 'vtype', 'data')

    def __init__(self, name: str, vtype: int, data: bytes):
        self.name  = name
        self.vtype = vtype
        self.data  = data

    def __repr__(self):
        return f'RegValue({self.name!r}, type={self.vtype}, len={len(self.data)})'


class RegKey:
    __slots__ = ('path', 'values', 'subkeys', '_explicit_paths')

    def __init__(self, path: str):
        self.path    = path
        self.values  = []      # list[RegValue]
        self.subkeys = {}      # name -> RegKey (ordered)

    @property
    def name(self) -> str:
        return self.path.rsplit('\\', 1)[-1]

    def __repr__(self):
        return f'RegKey({self.path!r}, values={len(self.values)}, subkeys={len(self.subkeys)})'


def parse_reg_file(path: str) -> RegKey:
    """
    Parse a .reg (regedit export) file.
    Returns a synthetic root RegKey whose subkeys are the top-level keys.
    """
    text = Path(path).read_bytes()

    # Detect encoding
    if text.startswith(b'\xff\xfe'):
        text = text.decode('utf-16-le')
    elif text.startswith(b'\xfe\xff'):
        text = text.decode('utf-16-be')
    else:
        text = text.decode('utf-8', errors='replace')

    lines = text.splitlines()

    # Check header
    if not lines or 'Windows Registry Editor' not in lines[0]:
        raise ValueError('Not a valid .reg export file (missing header)')

    # Join continuation lines.
    # .reg hex values span multiple lines with a trailing backslash:
    #   "val"=hex:01,02,\
    #     03,04
    # After UTF-16 decode + splitlines(), a continuation line looks like:
    #   '"val"=hex:01,02,\' + '\r'   (backslash then CR, because splitlines
    #   splits on LF and leaves CR attached)
    # So we must strip trailing CR/whitespace before checking for '\'.
    # We only treat trailing '\' as continuation on hex value lines to
    # avoid confusing Windows path strings that end in backslash.
    joined = []
    buf = ''
    in_continuation = False
    for line in lines[1:]:
        # Strip trailing CR and whitespace to normalise line endings
        line = line.rstrip('\r\n \t')
        if in_continuation:
            # Strip leading whitespace (the 2-space indent on continuation lines)
            s = line.lstrip()
            if s.endswith('\\'):
                buf += s[:-1]   # strip trailing backslash, stay in continuation
            else:
                buf += s
                joined.append(buf)
                buf = ''
                in_continuation = False
        else:
            if line.endswith('\\'):
                # Only start continuation on hex value lines
                if '=hex' in line:
                    buf += line[:-1]
                    in_continuation = True
                else:
                    # Trailing backslash in a non-hex context (e.g. registry path) — literal
                    joined.append(line)
            else:
                joined.append(line)
    if buf:
        joined.append(buf)

    root = RegKey('__ROOT__')
    root._explicit_paths = set()
    explicit_paths = root._explicit_paths
    current_key: RegKey | None = None

    for line in joined:
        line = line.strip()
        if not line or line.startswith(';'):
            continue

        # Key header: [KEY\PATH] or [-KEY\PATH] (deletion — skip)
        if line.startswith('['):
            if line.startswith('[-'):
                current_key = None
                continue
            key_path = line[1:line.rindex(']')]
            explicit_paths.add(key_path)
            current_key = _get_or_create_key(root, key_path)
            continue

        if current_key is None:
            continue

        # Value line: "name"=data  or  @=data
        # The name is always quoted or @, so find '=' after the name token.
        if line.startswith('@='):
            name    = ''
            raw_val = line[2:].strip()
        elif line.startswith('"'):
            # find closing quote of name (handle escaped quotes inside)
            i = 1
            while i < len(line):
                if line[i] == '\\':
                    i += 2; continue
                if line[i] == '"':
                    break
                i += 1
            if i >= len(line) or i+1 >= len(line) or line[i+1] != '=':
                continue   # malformed line
            name    = _unescape_reg_string(line[1:i])
            raw_val = line[i+2:].strip()
        else:
            continue   # not a value line

        rv = _parse_value(name, raw_val)
        if rv is not None:
            current_key.values.append(rv)

    # Store the set of explicitly-exported paths on the root for use by build()
    root._explicit_paths = explicit_paths
    return root


def _get_or_create_key(root: RegKey, path: str) -> RegKey:
    parts = path.split('\\')
    node = root
    for i, part in enumerate(parts):
        part_lower = part.lower()
        # case-insensitive lookup
        match = None
        for k in node.subkeys:
            if k.lower() == part_lower:
                match = k
                break
        if match:
            node = node.subkeys[match]
        else:
            new_path = '\\'.join(parts[:i+1])
            new_key = RegKey(new_path)
            node.subkeys[part] = new_key
            node = new_key
    return node


def _unescape_reg_string(s: str) -> str:
    """Unescape .reg string escapes: backslash-backslash to backslash, backslash-quote to quote, backslash-0 to NUL."""
    out = []
    i = 0
    while i < len(s):
        if s[i] == '\\' and i + 1 < len(s):
            c = s[i+1]
            if c == '\\':
                out.append('\\')
            elif c == '"':
                out.append('"')
            elif c == '0':
                out.append('\x00')
            else:
                out.append('\\')
                out.append(c)
            i += 2
        else:
            out.append(s[i])
            i += 1
    return ''.join(out)


def _parse_hex_bytes(s: str) -> bytes:
    """Parse comma-separated hex bytes like '41,00,42,00'."""
    s = s.replace(' ', '').replace('\n', '').replace('\r', '')
    if not s:
        return b''
    return bytes(int(b, 16) for b in s.split(',') if b)


def _parse_value(name: str, raw: str) -> RegValue | None:
    raw = raw.strip()

    # REG_SZ: "string value"
    if raw.startswith('"'):
        inner = raw[1:]
        if inner.endswith('"'):
            inner = inner[:-1]
        s = _unescape_reg_string(inner)
        # Encode as UTF-16-LE with null terminator
        data = (s + '\x00').encode('utf-16-le')
        return RegValue(name, REG_SZ, data)

    # dword:XXXXXXXX
    if raw.startswith('dword:'):
        val = int(raw[6:], 16)
        return RegValue(name, REG_DWORD, struct.pack('<I', val))

    # qword:... (rare in reg export, usually hex(b):)
    if raw.startswith('qword:'):
        val = int(raw[6:], 16)
        return RegValue(name, REG_QWORD, struct.pack('<Q', val))

    # hex type prefixes
    for prefix, vtype in REG_TYPE_MAP.items():
        if prefix == 'dword':
            continue
        if raw.startswith(prefix + ':'):
            hex_part = raw[len(prefix)+1:]
            data = _parse_hex_bytes(hex_part)
            return RegValue(name, vtype, data)

    # bare hex: (no colon — shouldn't happen but be safe)
    if raw.startswith('hex'):
        return RegValue(name, REG_BINARY, b'')

    return None


# ---------------------------------------------------------------------------
# Hive builder
# ---------------------------------------------------------------------------

class HiveBuilder:
    """
    Builds a minimal but valid NT registry hive in memory.

    Layout:
      0x0000 - 0x0FFF : REGF header block (4096 bytes)
      0x1000 +        : HBIN blocks (4096 bytes each, grown as needed)

    All cell offsets stored in NK/VK/etc. are relative to byte 0x1000
    (i.e. they are physical_offset - 0x1000).
    """

    def __init__(self):
        self._hbin_data = bytearray()   # raw bytes of all HBINs combined
        self._hbin_offset = 0           # current write position within hbin_data
        self._cur_block_end = 0         # physical end of the current HBIN block

    # ------------------------------------------------------------------ #
    #  Low-level allocation                                                #
    # ------------------------------------------------------------------ #

    def _add_hbin_block(self, min_data_size: int = 0):
        """
        Append an HBIN block large enough to hold min_data_size bytes of cell data.
        Block size is always a multiple of BLOCK_SIZE (4096).
        Advances _hbin_offset past the new block header.
        """
        block_start = len(self._hbin_data)
        needed = HBIN_HEADER_SIZE + min_data_size
        block_size = ((needed + BLOCK_SIZE - 1) // BLOCK_SIZE) * BLOCK_SIZE
        block = bytearray(block_size)
        struct.pack_into('<4sII', block, 0,
                         HBIN_SIGNATURE,
                         block_start,
                         block_size)
        free_size = block_size - HBIN_HEADER_SIZE
        struct.pack_into('<i', block, HBIN_HEADER_SIZE, free_size)
        self._hbin_data += block
        self._hbin_offset = block_start + HBIN_HEADER_SIZE
        self._cur_block_end = block_start + block_size

    def _alloc_cell(self, size: int) -> int:
        cell_size = align8(size + 4)

        # Bootstrap: ensure at least one block exists
        if not self._hbin_data:
            self._add_hbin_block(cell_size)

        space_left = self._cur_block_end - self._hbin_offset

        if space_left < cell_size:
            # Close current block: write a free cell over remaining space
            if space_left >= 4:
                struct.pack_into('<i', self._hbin_data, self._hbin_offset, space_left)
            # Open a new block sized for this cell
            self._add_hbin_block(cell_size)

        off = self._hbin_offset
        struct.pack_into('<i', self._hbin_data, off, -cell_size)
        self._hbin_offset += cell_size
        return off + 4

    def _finalize_hbin(self):
        """Write a free cell covering any unused space at the end of the last HBIN block."""
        if not self._hbin_data: return
        remaining = self._cur_block_end - self._hbin_offset
        if remaining >= 4:
            struct.pack_into('<i', self._hbin_data, self._hbin_offset, remaining)

    def _write(self, offset: int, data: bytes | bytearray):
        end = offset + len(data)
        if end > len(self._hbin_data):
            raise RuntimeError(f'Write out of bounds: {offset} + {len(data)} > {len(self._hbin_data)}')
        self._hbin_data[offset:end] = data

    # ------------------------------------------------------------------ #
    #  Cell writers                                                        #
    # ------------------------------------------------------------------ #

    def write_sk_cell(self) -> int:
        SYSTEM_SID = bytes([1,1,0,0,0,0,0,5,18,0,0,0])           # S-1-5-18
        ADMINS_SID = bytes([1,2,0,0,0,0,0,5,32,0,0,0,32,2,0,0])  # S-1-5-32-544
        KEY_ALL    = 0x000F003F

        def make_ace(mask, sid):
            return struct.pack('<BBH', 0, 0, 8 + len(sid)) + struct.pack('<I', mask) + sid

        ace1 = make_ace(KEY_ALL, SYSTEM_SID)
        ace2 = make_ace(KEY_ALL, ADMINS_SID)
        acl_body = ace1 + ace2
        # ACL header: revision(1) sbz1(1) acl_size(2) ace_count(2) sbz2(2)
        dacl = struct.pack('<BBHHH', 2, 0, 8 + len(acl_body), 2, 0) + acl_body

        # SD header (20 bytes): revision control off_owner off_group off_sacl off_dacl
        # SE_SELF_RELATIVE=0x8000 | SE_DACL_PRESENT=0x0004
        sd_header = struct.pack('<BBHIIII', 1, 0, 0x8004, 0, 0, 0, 20)
        sd = sd_header + dacl
        sd_len = len(sd)

        sk_size = 20 + sd_len   # SK header is 20 bytes
        off = self._alloc_cell(sk_size)
        buf = bytearray(sk_size)
        buf[0:2] = SK_SIGNATURE
        struct.pack_into('<H', buf, 2,  0)            # reserved
        # FwdLink and BkwdLink: point to self (single SK in ring)
        # We'll patch these after we know the cell offset
        struct.pack_into('<I', buf, 4,  0xFFFFFFFF)   # FwdLink (patched below)
        struct.pack_into('<I', buf, 8,  0xFFFFFFFF)   # BkwdLink (patched below)
        struct.pack_into('<I', buf, 12, 1)            # ReferenceCount
        struct.pack_into('<I', buf, 16, sd_len)       # DescriptorSize
        buf[20:20+sd_len] = sd
        self._write(off, buf)
        # Patch fwd/bk links to point to this cell's own cell offset (self-ring)
        cell_off = off - 4
        struct.pack_into('<I', self._hbin_data, off + 4, cell_off)
        struct.pack_into('<I', self._hbin_data, off + 8, cell_off)
        return off

    def write_vk_cell(self, value: RegValue) -> int:
        """Write a VK (value key) cell. Returns data offset."""
        name_bytes = value.name.encode('utf-8') if value.name else b''
        name_len   = len(name_bytes)

        data       = value.data
        data_len   = len(data)

        # Decide if data is inline (fits in 4 bytes)
        inline = data_len <= INLINE_DATA_LIMIT

        vk_size = 20 + name_len
        off = self._alloc_cell(vk_size)
        buf = bytearray(vk_size)

        if inline:
            # Inline: data goes in the DataOffset field (left-aligned, zero-padded).
            # The top bit of DataSize is set to signal inline storage.
            data_field = bytearray(4)
            data_field[:data_len] = data
            data_offset  = struct.unpack('<I', data_field)[0]
            stored_dlen  = data_len | 0x80000000   # top bit = inline flag on LENGTH
        elif data_len <= BIG_DATA_THRESHOLD:
            # Normal out-of-line: single data cell.
            data_cell_off = self._alloc_cell(max(data_len, 1))
            if data_len:
                self._write(data_cell_off, data)
            data_offset = data_cell_off - 4
            stored_dlen = data_len
        else:
            # Large value: single oversized cell spanning multiple HBIN pages.
            # _alloc_cell creates a larger HBIN block as needed.
            # This is compatible with all tools (impacket reads data_len bytes directly).
            data_cell_off = self._alloc_cell(data_len)
            self._write(data_cell_off, data)
            data_offset = data_cell_off - 4
            stored_dlen = data_len

        flags = 0x0001 if name_bytes else 0x0000   # 1 = ASCII name, 0 = default value

        # VK layout: sig(2) name_len(2) data_size(4) data_offset(4) data_type(4) flags(2) spare(2) = 20 bytes
        buf[0:2] = VK_SIGNATURE
        struct.pack_into('<H', buf, 2,  name_len)
        struct.pack_into('<I', buf, 4,  stored_dlen)
        struct.pack_into('<I', buf, 8,  data_offset)
        struct.pack_into('<I', buf, 12, value.vtype)
        struct.pack_into('<H', buf, 16, flags)
        struct.pack_into('<H', buf, 18, 0)   # spare
        if name_bytes:
            buf[20:20+name_len] = name_bytes
        self._write(off, buf)
        return off

    def write_value_list(self, vk_offsets: list[int]) -> int:
        """Write an array of VK offsets. Returns data offset."""
        count = len(vk_offsets)
        off = self._alloc_cell(count * 4)
        buf = bytearray(count * 4)
        for i, vkoff in enumerate(vk_offsets):
            struct.pack_into('<I', buf, i * 4, vkoff - 4)
        self._write(off, buf)
        return off

    def _write_lf_chunk(self, entries: list[tuple[int, str]]) -> int:
        """Write a single LF cell for up to MAX_LF_ENTRIES entries. Returns data offset."""
        count = len(entries)
        cell_size = 4 + count * 8
        off = self._alloc_cell(cell_size)
        buf = bytearray(cell_size)
        buf[0:2] = LF_SIGNATURE
        struct.pack_into('<H', buf, 2, count)
        for i, (nk_off, name) in enumerate(entries):
            hint = name[:4].encode('ascii', errors='replace').ljust(4, b'\x00')
            struct.pack_into('<I', buf, 4 + i * 8, nk_off - 4)
            buf[8 + i * 8: 12 + i * 8] = hint
        self._write(off, buf)
        return off

    def write_lf_cell(self, entries: list[tuple[int, str]]) -> int:
        if len(entries) <= MAX_LF_ENTRIES:
            return self._write_lf_chunk(entries)

        chunks = [entries[i:i+MAX_LF_ENTRIES]
                  for i in range(0, len(entries), MAX_LF_ENTRIES)]
        chunk_offsets = [self._write_lf_chunk(chunk) for chunk in chunks]

        ri_size = 4 + len(chunk_offsets) * 4
        off = self._alloc_cell(ri_size)
        buf = bytearray(ri_size)
        buf[0:2] = RI_SIGNATURE
        struct.pack_into('<H', buf, 2, len(chunk_offsets))
        for i, lf_off in enumerate(chunk_offsets):
            struct.pack_into('<I', buf, 4 + i * 4, lf_off - 4)
        self._write(off, buf)
        return off

    # ------------------------------------------------------------------ #
    #  Recursive key tree builder                                          #
    # ------------------------------------------------------------------ #

    def _write_nk(self, nk_off: int, key: RegKey, is_root: bool,
                  sk_offset: int, ts: int,
                  subkey_entries: list, vk_offsets: list) -> None:
        """Write a fully-populated NK cell at the pre-allocated offset."""
        NO_OFFSET = 0xFFFFFFFF
        name_bytes = key.name.encode('utf-8')
        nk_size    = 76 + len(name_bytes)

        subkey_list_off = (self.write_lf_cell(subkey_entries) - 4
                           if subkey_entries else NO_OFFSET)
        value_list_off  = (self.write_value_list(vk_offsets) - 4
                           if vk_offsets else NO_OFFSET)

        flags = 0x0020  # compressed (ASCII) name
        if is_root:
            flags |= 0x000c  # root (0x0004) + predefined handle (0x0008), required by Windows
        buf = bytearray(nk_size)
        buf[0:2] = NK_SIGNATURE
        struct.pack_into('<H', buf, 2,  flags)
        struct.pack_into('<Q', buf, 4,  ts)
        struct.pack_into('<I', buf, 12, 0)
        struct.pack_into('<I', buf, 16, NO_OFFSET)
        struct.pack_into('<I', buf, 20, len(subkey_entries))
        struct.pack_into('<I', buf, 24, 0)
        struct.pack_into('<I', buf, 28, subkey_list_off)
        struct.pack_into('<I', buf, 32, NO_OFFSET)
        struct.pack_into('<I', buf, 36, len(vk_offsets))
        struct.pack_into('<I', buf, 40, value_list_off)
        struct.pack_into('<I', buf, 44, sk_offset)
        struct.pack_into('<I', buf, 48, NO_OFFSET)
        struct.pack_into('<I', buf, 52, 0)
        struct.pack_into('<I', buf, 56, 0)
        struct.pack_into('<I', buf, 60, 0)
        struct.pack_into('<I', buf, 64, 0)
        struct.pack_into('<I', buf, 68, 0)
        struct.pack_into('<H', buf, 72, len(name_bytes))
        struct.pack_into('<H', buf, 74, 0)
        buf[76:76+len(name_bytes)] = name_bytes
        self._write(nk_off, buf)

    def build_key(self, root_key: RegKey, is_root: bool, sk_offset: int, ts: int,
                  reserved_nk_off: int | None = None) -> int:

        # nk_off_map: key id -> allocated nk data offset
        nk_off_map: dict[int, int] = {}

        stack = [(root_key, is_root, reserved_nk_off, None, 0)]

        while stack:
            key, key_is_root, res_off, parent_id, phase = stack.pop()
            kid = id(key)

            if phase == 0:
                # Allocate NK cell
                name_bytes = key.name.encode('utf-8')
                nk_size = 76 + len(name_bytes)
                if res_off is not None:
                    nk_off = res_off
                else:
                    nk_off = self._alloc_cell(nk_size)
                nk_off_map[kid] = nk_off

                # Push phase-1 frame (will run after all children)
                stack.append((key, key_is_root, res_off, parent_id, 1))

                # Push children phase-0 (reversed so first child runs first)
                for child_name, child_key in reversed(list(key.subkeys.items())):
                    stack.append((child_key, False, None, kid, 0))

            else:
                # All children built — write this NK
                nk_off = nk_off_map[kid]

                # Collect child nk offsets + names in original order
                subkey_entries = [(nk_off_map[id(ck)], cn)
                                  for cn, ck in key.subkeys.items()]

                # Write VK cells
                vk_offsets = [self.write_vk_cell(v) for v in key.values]

                # Write the NK
                self._write_nk(nk_off, key, key_is_root, sk_offset, ts,
                               subkey_entries, vk_offsets)

                my_cell_off = nk_off - 4
                for child_nk_off, _ in subkey_entries:
                    struct.pack_into('<I', self._hbin_data, child_nk_off + 16, my_cell_off)

        return nk_off_map[id(root_key)]

    # ------------------------------------------------------------------ #
    #  REGF header                                                         #
    # ------------------------------------------------------------------ #

    def _build_regf_header(self, root_cell_offset: int, hive_data_size: int, ts: int) -> bytes:
        """Build the 4096-byte REGF header block."""
        buf = bytearray(BLOCK_SIZE)

        # Primary fields (offset 0..95)
        struct.pack_into('<4sIIQIIII',
                         buf, 0,
                         REGF_SIGNATURE,
                         1,                    # PrimarySequenceNumber
                         1,                    # SecondarySequenceNumber
                         ts,                   # LastWrittenTimestamp
                         1,                    # MajorVersion
                         3,                    # MinorVersion (XP+)
                         0,                    # Type (0=primary)
                         1,                    # Unknown/BootType — Windows sets this to 1
                         )
        struct.pack_into('<I', buf, 36, root_cell_offset)   # RootCellOffset
        struct.pack_into('<I', buf, 40, hive_data_size)     # HiveBinsDataSize
        struct.pack_into('<I', buf, 44, 1)                  # Unknown/BootRecover — Windows sets this to 1

        # Checksum at offset 508 = XOR of first 127 DWORDs
        xor = 0
        for i in range(127):
            xor ^= struct.unpack_from('<I', buf, i * 4)[0]
        struct.pack_into('<I', buf, 508, xor)

        return bytes(buf)


    def build(self, root: RegKey) -> bytes:

        if not root.subkeys:
            raise ValueError('No keys found in .reg file')

        explicit = getattr(root, '_explicit_paths', set())
        if not explicit:
            raise ValueError('No keys found in .reg file')

        all_paths = [p.split('\\') for p in explicit]

        # Find longest common prefix
        common = all_paths[0][:]
        for parts in all_paths[1:]:
            new_common = []
            for a, b in zip(common, parts):
                if a == b:
                    new_common.append(a)
                else:
                    break
            common = new_common


        def _walk_to(start, parts):
            node = start
            for part in parts:
                found = node.subkeys.get(part) or next(
                    (v for k,v in node.subkeys.items() if k.lower()==part.lower()), None)
                if found:
                    node = found
                else:
                    break
            return node

        hkey_prefix = [p for p in common if p.upper().startswith('HKEY_')]
        # Walk to the last HKEY_* node
        node_after_hkey = _walk_to(root, hkey_prefix)
        # Step into its first non-HKEY child that is on the common prefix path
        next_part = next((p for p in common if not p.upper().startswith('HKEY_')), None)
        if next_part and next_part in node_after_hkey.subkeys:
            hive_root = node_after_hkey.subkeys[next_part]
        elif next_part:
            # case-insensitive
            hive_root = next((v for k,v in node_after_hkey.subkeys.items()
                              if k.lower() == next_part.lower()), node_after_hkey)
        else:
            hive_root = node_after_hkey

        ts = filetime_now()

        # Pre-allocate root NK cell first — lands at 0x20 (right after HBIN header),
        # matching what Windows reg save produces.
        root_name = hive_root.name
        root_nk_size = 76 + len(root_name.encode("utf-8"))
        root_nk_off = self._alloc_cell(root_nk_size)

        # Write SK (security) cell after root NK
        sk_off_data = self.write_sk_cell()
        sk_off = sk_off_data - 4  # convert to cell offset

        # Recursively build all NK/VK/LH cells, passing pre-allocated root offset
        self.build_key(hive_root, is_root=True, sk_offset=sk_off, ts=ts,
                       reserved_nk_off=root_nk_off)

        # Finalize: write free cell covering any unused tail of last HBIN block
        self._finalize_hbin()

        hive_data_size = len(self._hbin_data)
        header = self._build_regf_header(root_nk_off - 4, hive_data_size, ts)

        return header + bytes(self._hbin_data)



def main():
    if len(sys.argv) < 3:
        print('Usage: python3 reg_export_to_save.py <input.reg> <output.hiv>')
        print()
        print('Converts a Windows .reg export file (regedit format) to a')
        print('binary NT registry hive file (reg save / reg load format).')
        sys.exit(1)

    # Large hives can have deeply nested keys; increase recursion limit accordingly
    sys.setrecursionlimit(100000)

    in_path  = sys.argv[1]
    out_path = sys.argv[2]

    print(f'[*] Parsing {in_path} ...')
    root = parse_reg_file(in_path)

    def _count_keys(key):
        return 1 + sum(_count_keys(c) for c in key.subkeys.values())

    def _count_vals(key):
        return len(key.values) + sum(_count_vals(c) for c in key.subkeys.values())

    total_keys = sum(_count_keys(k) for k in root.subkeys.values())
    total_vals = sum(_count_vals(k) for k in root.subkeys.values())

    print(f'    Keys:   {total_keys}')
    print(f'    Values: {total_vals}')

    # Debug: show parse tree and root descent
    print(f'[*] Parse tree top 3 levels:')
    def _show(key, depth=0):
        indent = "    " + "  " * depth
        print(f'{indent}{key.name!r}  ({len(key.subkeys)}k {len(key.values)}v)')
        if depth < 2:
            for ch in list(key.subkeys.values())[:4]:
                _show(ch, depth+1)
            if len(key.subkeys) > 4:
                print(f'{indent}  ...({len(key.subkeys)-4} more)')
    for top in root.subkeys.values():
        _show(top)
    print(f'[*] Root descent:')
    _node = root
    while len(_node.subkeys) == 1 and len(_node.values) == 0:
        _node = next(iter(_node.subkeys.values()))
        print(f'    -> {_node.name!r}  ({len(_node.subkeys)}k {len(_node.values)}v)')
    print(f'    Hive root: {_node.name!r}')

    print(f'[*] Building hive ...')
    builder = HiveBuilder()
    hive_bytes = builder.build(root)

    print(f'[*] Writing {out_path} ({len(hive_bytes):,} bytes) ...')
    Path(out_path).write_bytes(hive_bytes)
    print('[+] Done.')


if __name__ == '__main__':
    main()