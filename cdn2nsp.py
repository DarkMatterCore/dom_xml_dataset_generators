#!/usr/bin/env python3

"""
 * cdn2nsp.py
 *
 * Copyright (c) 2023, DarkMatterCore <pabloacurielz@gmail.com>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
"""

from __future__ import annotations

import os, sys, re, subprocess, shutil, hashlib, random, string, glob, threading, psutil, time, argparse, io, struct, traceback, rsa

from io import BytesIO
from dataclasses import dataclass
from typing import Generator, IO, NoReturn, TypeAlias

from structs.cnmt import Cnmt
from structs.tik import Tik
from structs.nacp import Nacp

FileListEntry: TypeAlias = tuple[str, int]
FileList: TypeAlias = list[FileListEntry]

SCRIPT_PATH: str = os.path.realpath(__file__)
SCRIPT_NAME: str = os.path.basename(SCRIPT_PATH)
SCRIPT_DIR:  str = os.path.dirname(SCRIPT_PATH)

CWD:         str = os.getcwd()
INITIAL_DIR: str = (CWD if CWD != SCRIPT_DIR else SCRIPT_DIR)

MAX_CPU_THREAD_COUNT: int = psutil.cpu_count()

DEFAULT_KEYS_PATH: str = os.path.join('~', '.switch', 'prod.keys')

CDN_PATH:        str = os.path.join('.', 'cdn')
HACTOOLNET_PATH: str = os.path.join('.', ('hactoolnet.exe' if os.name == 'nt' else 'hactoolnet'))
KEYS_PATH:       str = DEFAULT_KEYS_PATH
CERT_PATH:       str = os.path.join('.', 'common.cert')
OUTPUT_PATH:     str = os.path.join('.', 'out')
PROCESS_NSP:     bool = False
NUM_THREADS:     int = MAX_CPU_THREAD_COUNT

HACTOOLNET_DISTRIBUTION_TYPE_REGEX  = re.compile(r'^Distribution type:\s+(.+)$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_CONTENT_TYPE_REGEX       = re.compile(r'^Content Type:\s+(.+)$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_ENCRYPTION_TYPE_REGEX    = re.compile(r'^Encryption Type:\s+(.+)$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_RIGHTS_ID_REGEX          = re.compile(r'^Rights ID:\s+([0-9a-f]{32})$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_VERIFICATION_FAIL_REGEX  = re.compile(r'\(FAIL\)', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_SAVING_REGEX             = re.compile(r'^section\d+:/(.+\.cnmt)$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_MISSING_TITLEKEY_REGEX   = re.compile(r'Missing NCA title key', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_ALT_RIGHTS_ID_REGEX      = re.compile(r'Title key for rights ID ([0-9a-f]{32})$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_DECRYPTED_TITLEKEY_REGEX = re.compile(r'^Titlekey \(Decrypted\)(?: \(From CLI\))?:?\s+([0-9a-f]{32})$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_MKEY_REVISION_REGEX      = re.compile(r'^Master Key Revision:\s+(\d+)\s+\([^\)]+\)$', flags=(re.MULTILINE | re.IGNORECASE))

NCA_DISTRIBUTION_TYPE: str = 'download'

CHUNK_SIZE: int = 0x800000 # 8 MiB

COMMON_CERT_SIZE: int = 0x700
COMMON_CERT_HASH: str = '3c4f20dca231655e90c75b3e9689e4dd38135401029ab1f2ea32d1c2573f1dfe' # SHA-256

PFS_FULL_HEADER_ALIGNMENT: int = 0x20

BOGUS_TITLEKEYS_PATH: str = ''

EXT_NSP_DATA_PATH: str = ''

def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)

def utilsGetPath(path_arg: str, fallback_path: str, is_file: bool, create: bool = False) -> str:
    path = os.path.abspath(os.path.expanduser(os.path.expandvars(path_arg if path_arg else fallback_path)))

    if not is_file and create:
        os.makedirs(path, exist_ok=True)

    if not os.path.exists(path) or (is_file and os.path.isdir(path)) or (not is_file and os.path.isfile(path)):
        raise ValueError(f'Error: "{path}" points to an invalid file/directory.')

    return path

def utilsIsAligned(value: int, alignment: int) -> bool:
    return ((value & (alignment - 1)) == 0)

def utilsBitwiseNot(value: int, numbits: int):
    return ((1 << numbits) - 1 - value)

def utilsAlignUp(value: int, alignment: int, numbits: int = 32) -> int:
    return ((value + (alignment - 1)) & utilsBitwiseNot(alignment - 1, numbits))

def utilsGetRandomString(length: int) -> str:
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for _ in range(length))
    return result_str

def utilsCapitalizeString(input: str, sep: str = '') -> str:
    elem = [s.capitalize() for s in input.split('_')]
    return sep.join(elem)

def utilsGetListChunks(lst: list, n: int) -> Generator:
    for i in range(0, n):
        yield lst[i::n]

def utilsReconfigureTerminalOutput() -> None:
    if sys.version_info >= (3, 7):
        if isinstance(sys.stdout, io.TextIOWrapper):
            sys.stdout.reconfigure(encoding='utf-8')

        if isinstance(sys.stderr, io.TextIOWrapper):
            sys.stderr.reconfigure(encoding='utf-8')

def utilsRunHactoolnet(type: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    args = [HACTOOLNET_PATH, '-t', type, '-k', KEYS_PATH, '--titlekeys', BOGUS_TITLEKEYS_PATH, '--disablekeywarns'] + args
    return subprocess.run(args, capture_output=True, encoding='utf-8')

def utilsCopyKeysFile() -> None:
    hactoolnet_keys_path = os.path.abspath(os.path.expanduser(os.path.expandvars(DEFAULT_KEYS_PATH)))
    if KEYS_PATH != hactoolnet_keys_path:
        os.makedirs(hactoolnet_keys_path, exist_ok=True)
        shutil.copyfile(KEYS_PATH, hactoolnet_keys_path)

def utilsCreateBogusTitleKeysFile() -> None:
    global BOGUS_TITLEKEYS_PATH
    BOGUS_TITLEKEYS_PATH = os.path.join(OUTPUT_PATH, 'bogus_title.keys')
    with open(BOGUS_TITLEKEYS_PATH, 'w') as fd:
        pass

def utilsDeleteBogusTitleKeysFile() -> None:
    if BOGUS_TITLEKEYS_PATH:
        os.remove(BOGUS_TITLEKEYS_PATH)

def utilsLocateCdnFile(base_path: str, filename: str, size: int = -1) -> str:
    # Check if we can find the requested file at the provided base path.
    cur_path = os.path.join(base_path, filename)
    if os.path.exists(cur_path) and os.path.isfile(cur_path):
        # Validate size.
        entry_size = os.path.getsize(cur_path)
        if (entry_size > 0) and ((size <= 0) or (entry_size == size)):
            return cur_path

    def utilsLocateCdnFileRecursiveScan(root: str) -> str:
        # Recursively scan input directory.
        file_list = glob.glob(pathname=f'**/{filename}', root_dir=root, recursive=True)
        for cur_path in file_list:
            cur_path = os.path.join(root, cur_path)

            # Skip directories.
            if os.path.isdir(cur_path):
                continue

            # Skip empty files.
            entry_size = os.path.getsize(cur_path)
            if (entry_size <= 0) or ((size > 0) and (entry_size != size)):
                continue

            return cur_path

        return ''

    cur_path = ''

    if PROCESS_NSP and base_path.startswith(EXT_NSP_DATA_PATH):
        # Look for the requested file within the extracted NSP data directory.
        cur_path = utilsLocateCdnFileRecursiveScan(EXT_NSP_DATA_PATH)

    if not cur_path:
        # Look for the requested file within the CDN directory.
        cur_path = utilsLocateCdnFileRecursiveScan(CDN_PATH)

    return cur_path

@dataclass(init=False)
class Sha256:
    value: str = ''

    @classmethod
    def from_path(cls, path: str) -> Sha256:
        fd = open(path, 'rb')
        checksums = cls(fd)
        fd.close()
        return checksums

    @classmethod
    def from_bytes(cls, data: bytes) -> Sha256:
        fd = BytesIO(data)
        checksums = cls(fd)
        fd.close()
        return checksums

    @classmethod
    def from_string(cls, data: str, encoding: str = 'utf-8') -> Sha256:
        return cls.from_bytes(data.encode(encoding))

    def __init__(self, fd: IO) -> None:
        # Calculate checksums for the provided filepath.
        sha256_obj = hashlib.sha256()

        while True:
            # Read file chunk.
            chunk = fd.read(CHUNK_SIZE)
            if not chunk:
                break

            # Update checksum.
            sha256_obj.update(chunk)

        self.value = sha256_obj.hexdigest().lower()

class NcaInfo:
    class Exception(Exception):
        def __init__(self, msg: str, rights_id: str = '') -> None:
            self.rights_id = rights_id
            super().__init__(msg)

    @property
    def path(self) -> str:
        return self._nca_path

    @property
    def size(self) -> int:
        return self._nca_size

    @property
    def filename(self) -> str:
        return self._nca_filename

    @property
    def dist_type(self) -> str:
        return self._dist_type

    @property
    def cnt_type(self) -> str:
        return self._cnt_type

    @cnt_type.setter
    def cnt_type(self, cnt_type: str) -> None:
        self._cnt_type = cnt_type

    @property
    def crypto_type(self) -> str:
        return self._crypto_type

    @property
    def rights_id(self) -> str:
        return self._rights_id

    @property
    def sha256(self) -> str:
        return self._sha256

    @property
    def cnt_id(self) -> str:
        # Content IDs are just the first half of the NCA's SHA-256 checksum.
        return self._sha256[:32]

    def __init__(self, nca_path: str, nca_size: int, enc_titlekey: str = '', thrd_id: int = -1, expected_cnt_type: str = '') -> None:
        # Populate class variables.
        self._populate_vars(nca_path, nca_size, enc_titlekey, thrd_id, expected_cnt_type)

        # Run hactoolnet.
        proc = self._get_hactoolnet_output()

        # Parse hactoolnet output.
        self._parse_hactoolnet_output(proc)

        # Calculate SHA-256 checksum for this NCA.
        self._sha256 = Sha256.from_path(self._nca_path).value

        if not self._nca_filename.startswith(self.cnt_id):
            # Update filename, if needed.
            self._nca_filename = f'{self.cnt_id}{".cnmt" if self._cnt_type == "meta" else ""}.nca'

    def __hash__(self) -> int:
        return hash(self._sha256)

    def __eq__(self, other: NcaInfo) -> bool:
        if isinstance(other, NcaInfo):
            return (self._sha256 == other.sha256)
        return NotImplemented

    def _populate_vars(self, nca_path: str, nca_size: int, enc_titlekey: str, thrd_id: int, expected_cnt_type: str) -> None:
        self._nca_path = nca_path
        self._nca_size = nca_size
        self._nca_filename = os.path.basename(self._nca_path)

        self._enc_titlekey = enc_titlekey
        self._thrd_id = thrd_id

        self._expected_cnt_type = expected_cnt_type.lower()

        self._dist_type = ''
        self._cnt_type = ''
        self._crypto_type = ''
        self._rights_id = ''
        self._valid = False

        self._sha256 = ''

    def _get_hactoolnet_output(self) -> subprocess.CompletedProcess[str]:
        # Run hactoolnet.
        args: list[str] = []
        if self._enc_titlekey:
            args.extend(['--titlekey', self._enc_titlekey])
        args.extend(['-y', self._nca_path])

        proc = utilsRunHactoolnet('nca', args)
        if (not proc.stdout) or (proc.returncode != 0):
            # Check if we're dealing with a missing titlekey error.
            if proc.stderr and re.search(HACTOOLNET_MISSING_TITLEKEY_REGEX, proc.stderr):
                # Return prematurely, but provide the rights ID to the caller.
                rights_id = re.search(HACTOOLNET_ALT_RIGHTS_ID_REGEX, proc.stderr)
                rights_id = (rights_id.group(1).lower() if rights_id else '')
                self._raise_exception('placeholder', rights_id)
            else:
                hactoolnet_stderr = proc.stderr.strip()
                self._raise_exception(f'Failed to retrieve NCA info{f" ({hactoolnet_stderr})" if hactoolnet_stderr else ""}')

        return proc

    def _parse_hactoolnet_output(self, proc: subprocess.CompletedProcess[str]) -> None:
        dist_type = re.search(HACTOOLNET_DISTRIBUTION_TYPE_REGEX, proc.stdout)
        cnt_type = re.search(HACTOOLNET_CONTENT_TYPE_REGEX, proc.stdout)
        crypto_type = re.search(HACTOOLNET_ENCRYPTION_TYPE_REGEX, proc.stdout)
        rights_id = re.search(HACTOOLNET_RIGHTS_ID_REGEX, proc.stdout)

        if (not dist_type) or (not cnt_type) or (not crypto_type):
            self._raise_exception('Failed to parse hactoolnet output')

        self._dist_type = dist_type.group(1).lower()
        self._cnt_type = cnt_type.group(1).lower()
        self._crypto_type = crypto_type.group(1).lower().split()[0]
        self._rights_id = (rights_id.group(1).lower() if rights_id else '')
        self._valid = (len(re.findall(HACTOOLNET_VERIFICATION_FAIL_REGEX, proc.stdout)) == 0)

        if self._dist_type != NCA_DISTRIBUTION_TYPE:
            self._raise_exception(f'Invalid distribution type (got "{self._dist_type}", expected "{NCA_DISTRIBUTION_TYPE}")')

        if self._expected_cnt_type and (self._cnt_type != self._expected_cnt_type):
            self._raise_exception(f'Invalid content type (got "{self._cnt_type}", expected "{self._expected_cnt_type}")')

        if (self._crypto_type == 'titlekey') and (not self._rights_id):
            self._raise_exception('Failed to parse Rights ID from hactoolnet output')

        if not self._valid:
            self._raise_exception('Signature/hash verification failed')

    def _raise_exception(self, msg: str, rights_id: str = '') -> NoReturn:
        if self._thrd_id >= 0:
            msg = f'(Thread {self._thrd_id}) {msg}.'
        else:
            msg = f'NCA "{self._nca_path}": {msg}.'

        raise self.Exception(msg, rights_id)

@dataclass(init=False)
class TitleKeyInfo:
    rights_id: str = ''
    value: str = ''
    raw_value: bytes = b''
    size: int = 16

    def __init__(self, titlekey: str, rights_id: str) -> None:
        # Populate properties.
        self.rights_id = rights_id
        self.value = titlekey
        self.raw_value = bytes.fromhex(self.value)

class TikInfo:
    class Exception(Exception):
        def __init__(self, msg: str) -> None:
            super().__init__(msg)

    @property
    def rights_id(self) -> str:
        return self._rights_id

    @property
    def filename(self) -> str:
        return self._tik_filename

    @property
    def path(self) -> str:
        return self._tik_path

    @property
    def size(self) -> int:
        return self._tik_size

    @property
    def valid_sig(self) -> bool:
        return self._valid_sig

    @property
    def enc_titlekey(self) -> TitleKeyInfo | None:
        return self._enc_titlekey

    @property
    def dec_titlekey(self) -> TitleKeyInfo | None:
        return self._dec_titlekey

    def __init__(self, rights_id: str, base_path: str, nca_path: str, thrd_id: int) -> None:
        # Populate class variables.
        self._populate_vars(rights_id, base_path, nca_path, thrd_id)

        # Validate ticket file structure.
        self._validate_tik()

        # Verify ticket signature.
        self._verify_tik_sig()

        # Get decrypted titlekey and key generation.
        self._get_dec_tk_and_key_gen()

        # Fix tampered ticket, if needed.
        self._fix_tampered_tik()

    def _populate_vars(self, rights_id: str, base_path: str, nca_path: str, thrd_id: int) -> None:
        self._rights_id = rights_id.lower()
        self._base_path = base_path
        self._nca_path = nca_path
        self._thrd_id = thrd_id

        self._tik_filename = f'{self._rights_id}.tik'
        self._tik_path = utilsLocateCdnFile(self._base_path, self._tik_filename)
        self._tik_size = (os.path.getsize(self._tik_path) if self._tik_path else 0)

        self._enc_titlekey: TitleKeyInfo | None = None
        self._dec_titlekey: TitleKeyInfo | None = None

        self._key_generation = 0
        self._valid_sig = False

    def _validate_tik(self) -> None:
        # Make sure the ticket file exists.
        if not self._tik_path:
            raise self.Exception(f'(Thread {self._thrd_id}) Error: unable to locate ticket file "{self._tik_filename}". Skipping NSP generation for this title.')

        try:
            # Parse ticket file.
            tik = Tik.from_file(self._tik_path)
        except Exception as e:
            # Reraise the exception as a TikInfo.Exception.
            raise self.Exception(str(e))

        # Make sure the ticket uses a RSA-2048 PKCS#1 v1.5 + SHA-256 signature.
        if tik.sig_type != Tik.SignatureType.rsa2048_sha256:
            raise self.Exception(f'(Thread {self._thrd_id}) Error: ticket "{self._tik_filename}" doesn\'t use a RSA-2048 PKCS#1 v1.5 + SHA-256 signature. Skipping NSP generation for this title.')

        # Make sure the ticket uses common crypto.
        if tik.titlekey_type != Tik.TitlekeyType.common:
            raise self.Exception(f'(Thread {self._thrd_id}) Error: ticket "{self._tik_filename}" doesn\'t use common crypto. Skipping NSP generation for this title.')

        # Load encrypted titlekey right away.
        self._enc_titlekey = TitleKeyInfo(tik.titlekey_block[:16].hex().lower(), self._rights_id)

        # Close ticket.
        tik.close()

    def _verify_tik_sig(self) -> None:
        # Read RSA public key from the certificate chain.
        with open(CERT_PATH, 'rb') as fd:
            fd.seek(0x5C8)
            modulus = int.from_bytes(fd.read(0x100), 'big')
            pub_exp = int.from_bytes(fd.read(0x4), 'big')

        pub_key = rsa.PublicKey(modulus, pub_exp)

        # Read signature and message from the ticket itself.
        with open(self._tik_path, 'rb') as fd:
            fd.seek(0x4)
            signature = fd.read(0x100)

            fd.seek(0x140)
            message = fd.read()

        try:
            # Verify ticket signature.
            rsa.verify(message, signature, pub_key)
        except rsa.VerificationError:
            # Invalid signature.
            self._valid_sig = False
        else:
            # Valid signature. We'll keep the ticket untouched.
            self._valid_sig = True

        print(f'(Thread {self._thrd_id}) Signature for common ticket "{self._tik_filename}" is {"valid" if self._valid_sig else "invalid"}.', flush=True)

    def _get_dec_tk_and_key_gen(self) -> None:
        if not self._enc_titlekey:
            return

        # Get decrypted titlekey and key generation from hactoolnet output.
        proc = utilsRunHactoolnet('nca', ['--titlekey', self._enc_titlekey.value, self._nca_path])
        hactoolnet_stderr = proc.stderr.strip()
        if (not proc.stdout) or (proc.returncode != 0):
            raise self.Exception(f'(Thread {self._thrd_id}) Failed to retrieve NCA info for ticket {f" ({hactoolnet_stderr})" if hactoolnet_stderr else ""}. Skipping NSP generation for this title.')

        dec_titlekey = re.search(HACTOOLNET_DECRYPTED_TITLEKEY_REGEX, proc.stdout)
        nca_key_generation = re.search(HACTOOLNET_MKEY_REVISION_REGEX, proc.stdout)

        if (not dec_titlekey) or (not nca_key_generation):
            raise self.Exception(f'(Thread {self._thrd_id}) Failed to parse hactoolnet output. Skipping NSP generation for this title.')

        dec_titlekey = dec_titlekey.group(1).lower()
        nca_key_generation = int(nca_key_generation.group(1))
        if nca_key_generation > 0:
            # Convert back to a true NCA key generation value.
            nca_key_generation += 1

        # Validate key generation value.
        key_gen_rid = int.from_bytes(bytes.fromhex(self._rights_id[-2:]), 'little', signed=False)
        old_key_gen = (nca_key_generation < 3)

        if (old_key_gen and key_gen_rid) or ((not old_key_gen) and key_gen_rid != nca_key_generation):
            expected_key_gen = (0 if old_key_gen else nca_key_generation)
            raise self.Exception(f'(Thread {self._thrd_id}) Error: invalid rights ID key generation! Got 0x{key_gen_rid:02X}, expected 0x{expected_key_gen:02X}. Skipping NSP generation for this title.')

        # Save values.
        self._dec_titlekey = TitleKeyInfo(dec_titlekey, self._rights_id)
        self._key_generation = nca_key_generation

    def _fix_tampered_tik(self) -> None:
        if self._valid_sig or (not self._enc_titlekey):
            return

        # Serialize a new common ticket.
        tik = struct.pack('<I', Tik.SignatureType.rsa2048_sha256.value)
        tik += b'\xFF' * 0x100
        tik += b'\x00' * 0x3C

        tik += struct.pack('64s', b'Root-CA00000003-XS00000020')

        tik += self._enc_titlekey.raw_value
        tik += b'\x00' * 0xF0

        tik += struct.pack('<BBHBBH8xQQ', 2, Tik.TitlekeyType.common.value, 0, Tik.LicenseType.permanent.value, self._key_generation, 0, 0, 0)
        tik += bytes.fromhex(self._rights_id)
        tik += struct.pack('<IIIHH', 0, 0, 0x2C0, 0, 0)

        with open(self._tik_path, 'wb') as fd:
            fd.write(tik)

        print(f'(Thread {self._thrd_id}) Wrote 0x{os.path.getsize(self._tik_path):X}-byte long fixed tampered ticket to "{self._tik_path}".', flush=True)

@dataclass(init=False)
class NacpLanguageEntry:
    name: str = ''
    publisher: str = ''
    lang: Nacp.Language | None = None

    def __init__(self, nacp_title: Nacp.Title, lang: int) -> None:
        self.name = nacp_title.name.strip()
        self.publisher = nacp_title.publisher.strip()
        self.lang = Nacp.Language(lang)

        if not self.name:
            raise ValueError('Invalid Title name.')

class PartitionFileSystem:
    class Exception(Exception):
        def __init__(self, msg: str) -> None:
            super().__init__(msg)

    @dataclass(init=False)
    class Header:
        entry_count: int = 0
        name_table_size: int = 0

        def __len__(self) -> int:
            return 0x10

        def serialize(self) -> bytes:
            return struct.pack('<4sIII', 'PFS0'.encode(), self.entry_count & 0xFFFFFFFF, self.name_table_size & 0xFFFFFFFF, 0)

    @dataclass
    class Entry:
        offset: int = 0
        size: int = 0
        name_offset: int = 0

        def __len__(self) -> int:
            return 0x18

        def serialize(self) -> bytes:
            return struct.pack('<QQII', self.offset & 0xFFFFFFFFFFFFFFFF, self.size & 0xFFFFFFFFFFFFFFFF, self.name_offset & 0xFFFFFFFF, 0)

    def __init__(self, thrd_id: int) -> None:
        self._header = PartitionFileSystem.Header()
        self._entries: list[PartitionFileSystem.Entry] = []
        self._name_table: bytes = b''

        self._cur_entry_offset: int = 0
        self._cur_name_offset: int = 0

        self._thrd_id = thrd_id

    def add_entry(self, name: str, size: int) -> None:
        if (not name) or (size <= 0):
            raise NspGenerator.Exception(f'(Thread {self._thrd_id}) Error: invalid arguments for new PFS entry.')

        # Generate new PFS entry.
        entry = PartitionFileSystem.Entry(self._cur_entry_offset, size, self._cur_name_offset)

        # Update PFS entry list.
        self._entries.append(entry)

        # Update name table.
        self._name_table += name.encode('utf-8') + b'\x00'

        # Update header.
        self._header.entry_count += 1
        self._header.name_table_size = len(self._name_table)

        # Update offsets.
        self._cur_entry_offset += size
        self._cur_name_offset = len(self._name_table)

    def serialize(self) -> bytes:
        if (self._header.entry_count <= 0) or (self._header.name_table_size <= 0) or (len(self._entries) != self._header.entry_count) or (not self._name_table):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: unable to serialize empty PFS object.')

        raw_header: bytes = b''

        # Calculate header size.
        header_size = (len(self._header) + (len(self._entries) * len(self._entries[0])) + len(self._name_table))

        # Calculate padded header size and padding size.
        padded_header_size = ((header_size + PFS_FULL_HEADER_ALIGNMENT) if utilsIsAligned(header_size, PFS_FULL_HEADER_ALIGNMENT) else utilsAlignUp(header_size, PFS_FULL_HEADER_ALIGNMENT))
        padding_size = (padded_header_size - header_size)

        # Serialize full header.
        self._header.name_table_size += padding_size
        raw_header += self._header.serialize()
        self._header.name_table_size -= padding_size

        for entry in self._entries:
            raw_header += entry.serialize()

        raw_header += self._name_table

        raw_header += (b'\x00' * padding_size)

        return raw_header

class NspGenerator:
    class Exception(Exception):
        def __init__(self, msg: str) -> None:
            super().__init__(msg)

    @property
    def path(self) -> str:
        return self._nsp_path

    @property
    def size(self) -> int:
        return self._nsp_size

    @property
    def filename(self) -> str:
        return self._nsp_filename

    @property
    def title_id(self) -> str:
        return self._title_id

    @property
    def title_version(self) -> int:
        return self._title_version

    @property
    def title_type(self) -> Cnmt.ContentMetaType | None:
        return self._title_type

    @property
    def rights_id(self) -> str:
        return self._rights_id

    @property
    def tik_info(self) -> TikInfo | None:
        return self._tik_info

    @property
    def lang_entries(self) -> list[NacpLanguageEntry]:
        return self._lang_entries

    @property
    def display_version(self) -> str:
        return self._display_version

    @property
    def contents(self) -> list[NcaInfo]:
        return self._contents

    def __init__(self, meta_nca: NcaInfo, tmp_path: str, thrd_id: int) -> None:
        # Populate class variables.
        self._populate_vars(meta_nca, tmp_path, thrd_id)

        # Extract CNMT file from the provided Meta NCA.
        self._extract_and_parse_cnmt()

        # Build NCA info list.
        self._build_content_list()

        # Build NSP.
        self._build_nsp()

        # Perform cleanup.
        self._cleanup()

    def _populate_vars(self, meta_nca: NcaInfo, tmp_path: str, thrd_id: int) -> None:
        self._meta_nca = meta_nca
        self._tmp_path = tmp_path
        self._thrd_id = thrd_id

        self._cnmt_path = ''
        self._cnmt: Cnmt | None = None

        self._nacp_path = ''
        self._nacp: Nacp | None = None

        # Retrieved from the CNMT in the Meta NCA. Placed here for convenience.
        self._title_id = ''
        self._title_version = 0
        self._title_type: Cnmt.ContentMetaType | None = None

        # Titlekey crypto related fields.
        self._rights_id = ''
        self._tik_info: TikInfo | None = None
        self._cert_filename = ''

        # Retrieved from the NACP in the Control NCA. Placed here for convenience.
        self._lang_entries: list[NacpLanguageEntry] = []
        self._display_version: str = ''

        self._contents: list[NcaInfo] = []

        self._nsp_filename = ''
        self._nsp_path = ''
        self._nsp_size = 0
        self._nsp_fd: IO | None = None

        self._pfs: PartitionFileSystem | None = None

        self._cleanup_called = False

    def _extract_and_parse_cnmt(self) -> None:
        print(f'(Thread {self._thrd_id}) Extracting CNMT from "{self._meta_nca.path}"...', flush=True)

        # Extract files from Meta NCA FS section 0.
        proc = utilsRunHactoolnet('nca', ['--section0dir', self._tmp_path, self._meta_nca.path])
        if (not proc.stdout) or (proc.returncode != 0):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: failed to extract Meta NCA FS section 0. Skipping NSP generation for this title.')

        # Get extracted CNMT filename from hactoolnet's output.
        cnmt_filename = re.search(HACTOOLNET_SAVING_REGEX, proc.stdout)
        if (not cnmt_filename):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: failed to parse CNMT filename from hactoolnet output. Skipping NSP generation for this title.')

        # Make sure the CNMT was extracted.
        cnmt_filename = cnmt_filename.group(1).strip()
        self._cnmt_path = os.path.join(self._tmp_path, cnmt_filename)
        if not os.path.exists(self._cnmt_path):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: failed to locate CNMT file after extraction. Skipping NSP generation for this title.')

        try:
            # Parse CNMT file.
            self._cnmt = Cnmt.from_file(self._cnmt_path)
        except Exception as e:
            # Reraise the exception as a NspGenerator.Exception.
            raise self.Exception(str(e))

        # Update class properties.
        self._title_id = f'{self._cnmt.header.title_id:016x}'

        titlever = self._cnmt.header.version.raw_version
        if isinstance(titlever, int):
            self._title_version = titlever

        self._title_type = Cnmt.ContentMetaType(self._cnmt.header.content_meta_type)

        # Make sure we're dealing with a supported title type.
        if (self._title_type.value < Cnmt.ContentMetaType.application.value) or (self._title_type.value > Cnmt.ContentMetaType.data_patch.value) or (self._title_type.value == Cnmt.ContentMetaType.delta.value):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: invalid content meta type value (0x{self._title_type.value:02x}). Skipping NSP generation for this title.')

    def _build_content_list(self) -> None:
        if not self._cnmt:
            return

        content_count = self._cnmt.header.content_count

        print(f'(Thread {self._thrd_id}) Parsing {content_count} content record(s) from "{os.path.basename(self._cnmt_path)}"...', flush=True)

        # Iterate over all content records.
        for i in range(content_count):
            # Get current content info entry.
            packaged_content_info: Cnmt.PackagedContentInfo = self._cnmt.packaged_content_infos[i]

            cnt_type = Cnmt.ContentType(packaged_content_info.info.type).name
            nca_filename = f'{packaged_content_info.info.id.hex().lower()}.nca'
            nca_size = packaged_content_info.info.raw_size
            if not isinstance(nca_size, int):
                continue

            print(f'(Thread {self._thrd_id}) Parsing {utilsCapitalizeString(cnt_type, " ")} NCA #{packaged_content_info.info.id_offset}: "{nca_filename}".', flush=True)

            # Locate target NCA file.
            nca_path = utilsLocateCdnFile(os.path.dirname(self._meta_nca.path), nca_filename, nca_size)
            if not nca_path:
                # Don't proceed any further with the current title if this NCA isn't available.
                # We don't really care about missing DeltaFragment NCAs, though.
                msg = f'(Thread {self._thrd_id}) Error: file "{nca_filename}" not found within CDN directory.'

                if cnt_type == 'delta_fragment':
                    eprint(f'{msg} Skipping NCA.')
                    continue

                raise self.Exception(f'{msg}. Skipping NSP generation for this title.')

            # Retrieve NCA information.
            nca_info = self._get_nca_info(nca_path, nca_size)

            # Verify content ID.
            if (packaged_content_info.info.id != packaged_content_info.hash[:16]) or (packaged_content_info.info.id.hex().lower() != nca_info.cnt_id):
                raise self.Exception(f'(Thread {self._thrd_id}) Error: content ID / hash mismatch. Skipping NSP generation for this title.')

            # Replace NCA info's content type with the type stored in the CNMT, because it's more descriptive.
            nca_info.cnt_type = cnt_type

            # Update contents list.
            self._contents.append(nca_info)

            # Extract and parse NACP if we're dealing with the first control NCA.
            if (packaged_content_info.info.type == Cnmt.ContentType.control) and (packaged_content_info.info.id_offset == 0) and (not self._nacp):
                self._extract_and_parse_nacp(nca_info)

        # Append Meta NCA to the list.
        self._contents.append(self._meta_nca)

    def _get_nca_info(self, nca_path: str, nca_size: int) -> NcaInfo:
        try:
            # Retrieve NCA information.
            nca_info = NcaInfo(nca_path, nca_size, self._tik_info.enc_titlekey.value if (self._tik_info and self._tik_info.enc_titlekey) else '', self._thrd_id)
        except NcaInfo.Exception as e:
            # Check if we're dealing with a missing titlekey.
            if e.rights_id and (not self._rights_id):
                # Set rights ID for this title.
                self._rights_id = e.rights_id

                # Retrieve ticket file info for this title.
                self._get_tik_info(nca_path)

                try:
                    # Try to retrieve NCA information once more, this time using proper titlekey crypto info.
                    nca_info = NcaInfo(nca_path, nca_size, self._tik_info.enc_titlekey.value if (self._tik_info and self._tik_info.enc_titlekey) else '', self._thrd_id)
                except NcaInfo.Exception as e:
                    # Reraise the exception as a NspGenerator.Exception.
                    raise self.Exception(str(e))
            else:
                # Reraise the exception as a NspGenerator.Exception.
                raise self.Exception(str(e))

        return nca_info

    def _get_tik_info(self, nca_path: str) -> None:
        if not self._title_type:
            return

        try:
            # Retrieve ticket file info.
            self._tik_info = TikInfo(self._rights_id, os.path.dirname(self._meta_nca.path), nca_path, self._thrd_id)
        except TikInfo.Exception as e:
            # Reraise the exception as a NspGenerator.Exception.
            raise self.Exception(str(e))

        # Make sure the ticket signature is valid if we're dealing with a Patch or DataPatch title.
        if (not self._tik_info.valid_sig) and ((self._title_type == Cnmt.ContentMetaType.patch) or (self._title_type == Cnmt.ContentMetaType.data_patch)):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: invalid ticket signature for Patch / DataPatch title. Skipping NSP generation for this title.')

        # Generate certificate chain filename.
        self._cert_filename = f'{self._rights_id}.cert'

    def _extract_and_parse_nacp(self, nca_info: NcaInfo) -> None:
        # Extract files from Control NCA FS section 0.
        proc = utilsRunHactoolnet('nca', ['--section0dir', self._tmp_path, nca_info.path])
        if (not proc.stdout) or (proc.returncode != 0):
            eprint(f'(Thread {self._thrd_id}) Error: failed to extract Control NCA FS section 0. Skipping additional metadata retrieval for current title.')
            return

        # Make sure the NACP was extracted.
        self._nacp_path = os.path.join(self._tmp_path, 'control.nacp')
        if not os.path.exists(self._nacp_path):
            eprint(f'(Thread {self._thrd_id}) Error: failed to locate NACP file after extraction. Skipping additional metadata retrieval for current title.')
            return

        try:
            # Parse NACP file.
            self._nacp = Nacp.from_file(self._nacp_path)
        except Exception:
            eprint(f'(Thread {self._thrd_id}) Error: failed to parse NACP file. Skipping additional metadata retrieval for current title.')
            return

        # Retrieve NACP language entry data.
        for lang in Nacp.Language:
            # Don't proceed any further if we've hit our limit.
            if lang.name == 'count':
                break

            # Don't proceed any further if the current language isn't supported by this title.
            if not self._nacp.supported_language.languages[lang.value]:
                continue

            # Get current NACP Title entry.
            nacp_title: Nacp.Title = self._nacp.title[lang.value]

            try:
                # Build a NacpLanguageEntry object using this Title entry.
                # Don't proceed any further if object initialization fails.
                nacp_lang_entry = NacpLanguageEntry(nacp_title, lang.value)
            except Exception:
                continue

            # Update language entry dictionary.
            self._lang_entries.append(nacp_lang_entry)

        # Get additional NACP properties.
        self._display_version = self._nacp.display_version

    def _build_nsp(self) -> None:
        # Generate NSP filename and path.
        self._nsp_filename = self._generate_nsp_filename()
        self._nsp_path = os.path.join(self._tmp_path, self._nsp_filename)

        print(f'(Thread {self._thrd_id}) Generating "{self._nsp_filename}"...', flush=True)

        # Create NSP file.
        self._nsp_fd = open(self._nsp_path, 'wb')

        # Generate and write NSP header.
        self._write_nsp_header()

        # Write NCAs.
        for cnt in self._contents:
            self._write_file_data(cnt.path)

        if self._tik_info:
            # Write ticket.
            self._write_file_data(self._tik_info.path)

            # Write certificate chain.
            self._write_cert_chain()

    def _generate_nsp_filename(self) -> str:
        if not self._title_type:
            return ''

        filename_type_strings: dict[int, str] = {
            Cnmt.ContentMetaType.application.value: 'BASE',
            Cnmt.ContentMetaType.patch.value: 'UPD',
            Cnmt.ContentMetaType.add_on_content.value: 'DLC',
            Cnmt.ContentMetaType.data_patch.value: 'DLCUPD'
        }

        if self._lang_entries:
            # Default to the first NACP language entry we found.
            name = self._lang_entries[0].name.strip()
        else:
            # Fallback to just using the title ID.
            name = self._title_id

        version = (f' {self._display_version} ' if (self._display_version and self._title_type == Cnmt.ContentMetaType.patch) else ' ')

        return f'{self._normalize_fs_str(name)}{version}[{self._title_id.upper()}][v{self._title_version}][{filename_type_strings.get(self._title_type.value)}].nsp'

    def _normalize_fs_str(self, name: str) -> str:
        # Replace illegal filesystem characters with underscores.
        out = re.sub(r'[\\/:*?"<>|]', '_', name)

        # Strip string.
        return out.strip()

    def _write_nsp_header(self) -> None:
        if not self._nsp_fd:
            return

        # Instantiate PFS object.
        self._pfs = PartitionFileSystem(self._thrd_id)

        try:
            # Loop through all of our parsed contents and add a PFS entry for each one.
            for cnt in self._contents:
                self._pfs.add_entry(cnt.filename, cnt.size)

            if self._tik_info:
                # Add ticket entry.
                self._pfs.add_entry(self._tik_info.filename, self._tik_info.size)

                # Add certificate chain entry.
                self._pfs.add_entry(self._cert_filename, COMMON_CERT_SIZE)

            # Write header.
            raw_header = self._pfs.serialize()
            self._nsp_fd.write(raw_header)

            print(f'(Thread {self._thrd_id}) Wrote 0x{len(raw_header):X}-byte long PFS header.', flush=True)
        except PartitionFileSystem.Exception as e:
            # Reraise the exception as a NspGenerator.Exception.
            raise self.Exception(str(e))

    def _write_file_data(self, path: str) -> None:
        if not self._nsp_fd:
            return

        print(f'(Thread {self._thrd_id}) Writing "{os.path.basename(path)}" (0x{os.path.getsize(path):X} bytes long)...')

        # Open NCA.
        with open(path, 'rb') as fd:
            # Read and write data in chunks.
            while True:
                # Read chunk.
                chunk = fd.read(CHUNK_SIZE)
                if not chunk:
                    break

                # Write chunk.
                self._nsp_fd.write(chunk)

    def _write_cert_chain(self) -> None:
        if not self._nsp_fd:
            return

        print(f'(Thread {self._thrd_id}) Writing "{self._cert_filename}" (0x{COMMON_CERT_SIZE:X} bytes long)...')

        with open(CERT_PATH, 'rb') as fd:
            self._nsp_fd.write(fd.read())

    def _cleanup(self, delete_nsp: bool = False) -> None:
        if self._cleanup_called:
            return

        if self._cnmt:
            # Close Cnmt object and delete CNMT file.
            self._cnmt.close()
            os.remove(self._cnmt_path)

        if self._nacp:
            # Close Nacp object and delete NACP file.
            self._nacp.close()
            os.remove(self._nacp_path)

            # Delete DAT files.
            dat_list = glob.glob(os.path.join(self._tmp_path, '*.dat'))
            for dat in dat_list:
                os.remove(dat)

        if self._nsp_fd:
            # Close NSP file.
            self._nsp_fd.close()

            if delete_nsp:
                # Delete NSP file.
                os.remove(self._nsp_path)
            else:
                # Move NSP out of the temporary directory for this thread.
                new_path = os.path.join(OUTPUT_PATH, self._nsp_filename)
                shutil.move(self._nsp_path, new_path)

                # Update path.
                self._nsp_path = new_path

        # Update flag.
        self._cleanup_called = True

    def __exit__(self) -> None:
        #print('nsp: __exit__ called', flush=True)
        self._cleanup(True)

    def __del__(self) -> None:
        #print('nsp: __del__ called', flush=True)
        self._cleanup(True)

def utilsProcessMetaNcaList(meta_nca_list_chunks: list[list[NcaInfo]], results: list[list[NspGenerator]]) -> None:
    thrd_id = int(threading.current_thread().name)

    meta_nca_list = meta_nca_list_chunks[thrd_id]
    thrd_res: list[NspGenerator] = []

    # Create temporary directory for this thread.
    tmp_path = os.path.join(OUTPUT_PATH, f'proc_{utilsGetRandomString(16)}_{thrd_id}')
    os.makedirs(tmp_path, exist_ok=True)

    # Generate NSP files.
    for meta_nca in meta_nca_list:
        try:
            nsp_gen = NspGenerator(meta_nca, tmp_path, thrd_id)
        except NspGenerator.Exception as e:
            eprint(str(e))
            continue

        # Update output list.
        thrd_res.append(nsp_gen)

    # Update results entry.
    results[thrd_id] = thrd_res

    # Remove temporary directory for this thread.
    shutil.rmtree(tmp_path, ignore_errors=True)

def utilsGetMetaNcaList(path: str) -> list[NcaInfo]:
    meta_nca_infos: list[NcaInfo] = []

    print(f'Building list with parsed Meta NCA data from "{path}"...', flush=True)

    # Recursively scan the provided directory. We'll look for all the available Meta NCAs.
    meta_nca_list = glob.glob(os.path.join(path, '**', '*.cnmt.nca'), recursive=True)

    for cur_path in meta_nca_list:
        cur_path = os.path.join(path, cur_path)

        # Skip directories.
        if os.path.isdir(cur_path):
            continue

        # Skip empty files.
        nca_size = os.path.getsize(cur_path)
        if not nca_size:
            continue

        try:
            # Retrieve Meta NCA information.
            nca_info = NcaInfo(cur_path, nca_size, '', -1, 'meta')
        except NcaInfo.Exception as e:
            eprint(str(e))
            continue

        # Update Meta NCA list.
        meta_nca_infos.append(nca_info)

    # Deduplicate Meta NCA list.
    meta_nca_infos = list(set(meta_nca_infos))

    return meta_nca_infos

def utilsGetNspFileList(path: str) -> FileList:
    nsp_list: FileList = []

    print('Building NSP/NSZ file list...', flush=True)

    # Scan directory.
    dir_entries = glob.glob(pathname='**', root_dir=path, recursive=True)
    for cur_path in dir_entries:
        cur_path = os.path.join(path, cur_path)
        entry_name = os.path.basename(cur_path).lower()

        # Skip directories and files that don't match our criteria.
        if os.path.isdir(cur_path) or (not (entry_name.endswith('.nsp') or entry_name.endswith('.nsz'))):
            continue

        # Skip empty files.
        file_size = os.path.getsize(cur_path)
        if not file_size:
            continue

        # Update list.
        nsp_list.append((cur_path, file_size))

    if nsp_list:
        print(f'{len(nsp_list)} NSP/NSZ file(s) located.', flush=True)
    else:
        print('Warning: "--process-nsp" was used, but no NSP/NSZ files could be located within the CDN directory.', flush=True)

    return nsp_list

def utilsConvertNsz(nsz_path: str, tmp_path: str) -> str:
    print(f'Converting "{nsz_path}" to NSP...', flush=True)

    nsz_args = ['nsz', '-D', '-o', tmp_path, nsz_path]
    nsp_path = os.path.join(tmp_path, f'{os.path.splitext(os.path.basename(nsz_path))[0]}.nsp')

    proc = subprocess.run(nsz_args, capture_output=True, encoding='utf-8')
    new_nsp_size = (os.path.getsize(nsp_path) if os.path.exists(nsp_path) else 0)

    if (not proc.stdout) or (proc.returncode != 0) or (new_nsp_size <= 0):
        print(f'Error: failed to convert NSZ to NSP.', flush=True)

        if os.path.exists(nsp_path):
            os.remove(nsp_path)

        return ''

    return nsp_path

def utilsExtractNsp(nsp_path: str, tmp_path: str) -> str:
    print(f'Extracting "{nsp_path}"...', flush=True)

    # Extract files from the provided NSP.
    nsz_args = ['nsz', '-x', '-o', tmp_path, nsp_path]
    ext_nsp_path = os.path.join(tmp_path, os.path.splitext(os.path.basename(nsp_path))[0])

    proc = subprocess.run(nsz_args, capture_output=True, encoding='utf-8')
    if (not proc.stdout) or (proc.returncode != 0) or (not os.path.exists(ext_nsp_path)):
        print(f'Error: failed to extract NSP.', flush=True)

        if os.path.exists(ext_nsp_path):
            shutil.rmtree(ext_nsp_path, ignore_errors=True)

        return ''

    # Rename extracted NSP directory.
    new_ext_nsp_path = os.path.join(tmp_path, f'nsp_{utilsGetRandomString(16)}')
    os.rename(ext_nsp_path, new_ext_nsp_path)

    return new_ext_nsp_path

def utilsBuildMetaNcaListFromNspFiles(input_path: str, tmp_path: str) -> list[NcaInfo]:
    cnt = 0

    # Get NSP file list.
    nsp_list = utilsGetNspFileList(input_path)
    if not nsp_list:
        return []

    for (nsp_path, _) in nsp_list:
        is_nsz = nsp_path.lower().endswith('.nsz')

        # Convert NSZ to NSP, if needed.
        if is_nsz:
            nsp_path = utilsConvertNsz(nsp_path, tmp_path)
            if not nsp_path:
                continue

        # Extract NSP.
        ext_nsp_path = utilsExtractNsp(nsp_path, tmp_path)

        # Delete NSZ -> NSP conversion, if needed.
        if is_nsz:
            os.remove(nsp_path)

        # Check if the extraction went okay.
        if not ext_nsp_path:
            continue

        # Update counter.
        cnt += 1

    if cnt <= 0:
        print(f'Error: failed to extract any NSP(s) from the input directory.', flush=True)
        return []

    # Return list with Meta NCA information.
    return utilsGetMetaNcaList(tmp_path)

def utilsProcessCdnDirectory() -> None:
    meta_nca_infos: list[NcaInfo] = []
    nsp_gen_list: list[NspGenerator] = []

    if PROCESS_NSP:
        # Build Meta NCA list from NSP files.
        meta_nca_infos = utilsBuildMetaNcaListFromNspFiles(CDN_PATH, EXT_NSP_DATA_PATH)

    # Collect information from all available Meta NCAs.
    meta_nca_infos.extend(utilsGetMetaNcaList(CDN_PATH))
    if not meta_nca_infos:
        raise FileNotFoundError('Error: failed to locate and parse any Meta NCAs.')

    print(f'{len(meta_nca_infos)} Meta NCA(s) located and parsed.\n', flush=True)

    # Create processing threads.
    meta_nca_list_chunks: list[list[NcaInfo]] = list(filter(None, list(utilsGetListChunks(meta_nca_infos, NUM_THREADS))))
    num_threads = len(meta_nca_list_chunks)

    threads: list[threading.Thread] = []
    results: list[list[NspGenerator]] = [[]] * num_threads

    for i in range(num_threads):
        cur_thread = threading.Thread(name=str(i), target=utilsProcessMetaNcaList, args=(meta_nca_list_chunks, results), daemon=True)
        cur_thread.start()
        threads.append(cur_thread)

    # Wait until all threads finish doing their job.
    while len(threading.enumerate()) > 1:
        time.sleep(1)

    # Generate full list with results from all threads.
    for res in results:
        nsp_gen_list.extend(res)

    # Check if we were able to populate our NSP list.
    if not nsp_gen_list:
        raise ValueError('Error: failed to generate any NSP files.')

    # Display results.
    print('\nResults:\n')
    for nsp_gen in nsp_gen_list:
        print(f'\t- {nsp_gen.filename} (0x{os.path.getsize(nsp_gen.path)} bytes long).')

def utilsPrepareNspRequirements() -> None:
    global EXT_NSP_DATA_PATH

    if not PROCESS_NSP:
        return

    # Check if nsz has been installed.
    if not shutil.which('nsz'):
        raise ValueError('Error: "nsz" package unavailable.')

    # Copy keys file (required by nsz since it offers no way to provide a keys file path).
    utilsCopyKeysFile()

    # Update extracted NSP data path.
    EXT_NSP_DATA_PATH = os.path.join(OUTPUT_PATH, 'ext_nsp_data')
    os.makedirs(EXT_NSP_DATA_PATH, exist_ok=True)

def utilsValidateCommonCertChain() -> None:
    # Validate certificate chain size.
    cert_chain_size = os.path.getsize(CERT_PATH)
    if cert_chain_size != COMMON_CERT_SIZE:
        raise ValueError(f'Invalid common certificate chain size (got 0x{cert_chain_size:X}, expected 0x{COMMON_CERT_SIZE:X}).')

    # Validate certificate chain checksum.
    cert_chain_hash = Sha256.from_path(CERT_PATH).value
    if cert_chain_hash != COMMON_CERT_HASH:
        raise ValueError(f'Invalid common certificate SHA-256 checksum (got "{cert_chain_hash.upper()}", expected "{COMMON_CERT_HASH}").')

def utilsValidateThreadCount(num_threads: str) -> int:
    val = int(num_threads)
    if (val <= 0) or (val > MAX_CPU_THREAD_COUNT):
        raise argparse.ArgumentTypeError(f'Invalid thread count provided. Value must be in the range [1, {MAX_CPU_THREAD_COUNT}].')
    return val

def main() -> int:
    global CDN_PATH, HACTOOLNET_PATH, KEYS_PATH, CERT_PATH, OUTPUT_PATH, PROCESS_NSP, NUM_THREADS

    # Reconfigure terminal output whenever possible.
    utilsReconfigureTerminalOutput()

    parser = argparse.ArgumentParser(description='Deterministically recreates Nintendo Submission Packages (NSP) files from extracted CDN data following NSP generation guidelines from nxdumptool.')

    parser.add_argument('--cdndir', type=str, metavar='DIR', default='', help=f'Path to directory with extracted CDN data (will be processed recursively). Defaults to "{CDN_PATH}".')
    parser.add_argument('--hactoolnet', type=str, metavar='FILE', default='', help=f'Path to hactoolnet binary. Defaults to "{HACTOOLNET_PATH}".')
    parser.add_argument('--keys', type=str, metavar='FILE', default='', help=f'Path to Nintendo Switch keys file. Defaults to "{KEYS_PATH}".')
    parser.add_argument('--cert', type=str, metavar='FILE', default='', help=f'Path to 0x{COMMON_CERT_SIZE:x}-byte long Nintendo Switch common certificate chain with SHA-256 checksum "{COMMON_CERT_HASH.upper()}". Defaults to "{CERT_PATH}".')
    parser.add_argument('--outdir', type=str, metavar='DIR', default='', help=f'Path to output directory. Defaults to "{OUTPUT_PATH}".')
    parser.add_argument('--process-nsp', action='store_true', default=PROCESS_NSP, help='Unpacks any NSP/NSZ files found within the provided CDN directory and repacks them into deterministic NSPs whenever possible. Disabled by default. Requires nsz to be installed.')
    parser.add_argument('--num-threads', type=utilsValidateThreadCount, metavar='VALUE', default=NUM_THREADS, help=f'Sets the number of threads used to process CDN data. Defaults to {NUM_THREADS} if not provided. This value must not be exceeded.')

    print(f'{SCRIPT_NAME}.\nMade by DarkMatterCore.\n', flush=True)

    # Parse arguments. Make sure to escape characters where needed.
    args = parser.parse_args()

    CDN_PATH = utilsGetPath(args.cdndir, os.path.join(INITIAL_DIR, CDN_PATH), False)
    HACTOOLNET_PATH = utilsGetPath(args.hactoolnet, os.path.join(INITIAL_DIR, HACTOOLNET_PATH), True)
    KEYS_PATH = utilsGetPath(args.keys, KEYS_PATH, True)
    CERT_PATH = utilsGetPath(args.cert, CERT_PATH, True)
    OUTPUT_PATH = utilsGetPath(args.outdir, os.path.join(INITIAL_DIR, OUTPUT_PATH), False, True)
    PROCESS_NSP = args.process_nsp
    NUM_THREADS = args.num_threads

    # Validate common certificate chain.
    utilsValidateCommonCertChain()

    # Prepare NSP processing requirements.
    utilsPrepareNspRequirements()

    # Create bogus titlekeys file.
    utilsCreateBogusTitleKeysFile()

    # Do our thing.
    utilsProcessCdnDirectory()

    # Delete bogus titlekeys file.
    utilsDeleteBogusTitleKeysFile()

    if PROCESS_NSP:
        # Remove extracted NSP data.
        shutil.rmtree(EXT_NSP_DATA_PATH, ignore_errors=True)

    return 0

if __name__ == '__main__':
    ret: int = 1

    try:
        ret = main()
    except KeyboardInterrupt:
        time.sleep(0.2)
        eprint('\nScript interrupted.')
    except (ValueError, FileNotFoundError) as e:
        print(str(e))
    except Exception:
        traceback.print_exc()

    try:
        sys.exit(ret)
    except SystemExit:
        os._exit(ret)
