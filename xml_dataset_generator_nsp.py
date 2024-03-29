#!/usr/bin/env python3

"""
 * xml_dataset_generator_nsp.py
 *
 * Copyright (c) 2022 - 2023, DarkMatterCore <pabloacurielz@gmail.com>.
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

import os, sys, re, subprocess, shutil, hashlib, zlib, random, string, datetime, glob, threading, psutil, time, argparse, io, traceback

from functools import total_ordering
from enum import IntEnum
from io import BytesIO
from dataclasses import dataclass
from typing import Generator, IO
from html import escape as html_escape

from structs.cnmt import Cnmt
from structs.tik import Tik
from structs.nacp import Nacp

FileListEntry = tuple[str, int]
FileList = list[FileListEntry]

SCRIPT_PATH: str = os.path.realpath(__file__)
SCRIPT_NAME: str = os.path.basename(SCRIPT_PATH)
SCRIPT_DIR:  str = os.path.dirname(SCRIPT_PATH)

CWD:         str = os.getcwd()
INITIAL_DIR: str = (CWD if CWD != SCRIPT_DIR else SCRIPT_DIR)

MAX_CPU_THREAD_COUNT: int = psutil.cpu_count()

DEFAULT_KEYS_PATH: str = os.path.join('~', '.switch', 'prod.keys')

NSP_PATH:        str = os.path.join('.', 'nsp')
HACTOOL_PATH:    str = os.path.join('.', ('hactool.exe' if os.name == 'nt' else 'hactool'))
HACTOOLNET_PATH: str = os.path.join('.', ('hactoolnet.exe' if os.name == 'nt' else 'hactoolnet'))
KEYS_PATH:       str = DEFAULT_KEYS_PATH
OUTPUT_PATH:     str = os.path.join('.', 'out')
EXCLUDE_NSP:     bool = False
EXCLUDE_TIK:     bool = False

DEFAULT_SECTION:  str = ''
DDATE_PROVIDED:   bool = False
DEFAULT_DDATE:    str = ''
RDATE_PROVIDED:   bool = False
DEFAULT_RDATE:    str = ''
DEFAULT_SECTION:  str = ''
DEFAULT_DUMPER:   str = '!unknown'
DEFAULT_PROJECT:  str = '!unknown'
DEFAULT_TOOL:     str = '!unknown'
DEFAULT_REGION:   str = 'Unknown'
DEFAULT_COMMENT2: str = ''

EXCLUDE_COMMENT:  bool = False
KEEP_FOLDERS:     bool = False
NUM_THREADS:      int  = MAX_CPU_THREAD_COUNT

HACTOOLNET_VERSION_REGEX            = re.compile(r'^hactoolnet (\d+\.\d+.\d+)$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_DISTRIBUTION_TYPE_REGEX  = re.compile(r'^Distribution type:\s+(.+)$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_CONTENT_TYPE_REGEX       = re.compile(r'^Content Type:\s+(.+)$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_ENCRYPTION_TYPE_REGEX    = re.compile(r'^Encryption Type:\s+(.+)$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_RIGHTS_ID_REGEX          = re.compile(r'^Rights ID:\s+([0-9a-f]{32})$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_VERIFICATION_FAIL_REGEX  = re.compile(r'\(FAIL\)', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_SAVING_REGEX             = re.compile(r'^section\d+:/(.+\.cnmt)$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_MISSING_TITLEKEY_REGEX   = re.compile(r'Missing NCA title key', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_ALT_RIGHTS_ID_REGEX      = re.compile(r'Title key for rights ID ([0-9a-f]{32})$', flags=(re.MULTILINE | re.IGNORECASE))

HACTOOL_DECRYPTED_TITLEKEY_REGEX    = re.compile(r'^Titlekey \(Decrypted\)(?: \(From CLI\))?\s+([0-9a-f]{32})$', flags=(re.MULTILINE | re.IGNORECASE))

NCA_DISTRIBUTION_TYPE: str = 'download'

DOM_LANGUAGES: dict[str, str] = {
    'american_english':       'En-US',
    'british_english':        'En-GB',
    'japanese':               'Ja',
    'french':                 'Fr-FR',
    'german':                 'De',
    'latin_american_spanish': 'Es-XL',
    'spanish':                'Es-ES',
    'italian':                'It',
    'dutch':                  'Nl',
    'canadian_french':        'Fr-CA',
    'portuguese':             'Pt-PT',
    'russian':                'Ru',
    'korean':                 'Ko',
    'traditional_chinese':    'Zh-Hant',
    'simplified_chinese':     'Zh-Hans',
    'brazilian_portuguese':   'Pt-BR'
}

XML_HEADER: str = '<?xml version="1.0" encoding="utf-8"?>\n'
XML_HEADER     += '<!DOCTYPE datafile PUBLIC "http://www.logiqx.com/Dats/datafile.dtd" "-//Logiqx//DTD ROM Management Datafile//EN">\n'
XML_HEADER     += '<datafile>\n'
XML_HEADER     += '  <header>\n'
XML_HEADER     += '  </header>\n'

XML_FOOTER: str = '</datafile>\n'

GIT_BRANCH: str = ''
GIT_COMMIT: str = ''
GIT_REV:    str = ''

HACTOOLNET_VERSION: str = ''

HASH_BLOCK_SIZE: int = 0x800000 # 8 MiB

def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)

def utilsGetPath(path_arg: str, fallback_path: str, is_file: bool, create: bool = False) -> str:
    path = os.path.abspath(os.path.expanduser(os.path.expandvars(path_arg if path_arg else fallback_path)))

    if not is_file and create:
        os.makedirs(path, exist_ok=True)

    if not os.path.exists(path) or (is_file and os.path.isdir(path)) or (not is_file and os.path.isfile(path)):
        raise ValueError(f'Error: "{path}" points to an invalid file/directory.')

    return path

def utilsGetRandomString(length: int) -> str:
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for _ in range(length))
    return result_str

def utilsCapitalizeString(input: str, sep: str = '') -> str:
    elem = [s.capitalize() for s in input.split('_')]
    return sep.join(elem)

def utilsIsAsciiString(s: str) -> bool:
    try:
        s.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False

def utilsGetListChunks(lst: list, n: int) -> Generator:
    for i in range(0, n):
        yield lst[i::n]

def utilsReconfigureTerminalOutput() -> None:
    if sys.version_info >= (3, 7):
        if isinstance(sys.stdout, io.TextIOWrapper):
            sys.stdout.reconfigure(encoding='utf-8')

        if isinstance(sys.stderr, io.TextIOWrapper):
            sys.stderr.reconfigure(encoding='utf-8')

def utilsRunGit(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(['git', '-C', SCRIPT_DIR] + args, capture_output=True, encoding='utf-8')

def utilsGetGitRepositoryInfo() -> None:
    global DEFAULT_COMMENT2, GIT_BRANCH, GIT_COMMIT, GIT_REV

    # Get git branch.
    proc = utilsRunGit(['rev-parse', '--abbrev-ref', 'HEAD'])
    if (not proc.stdout) or (proc.returncode != 0):
        raise ValueError('Failed to run git! (branch).')

    GIT_BRANCH = proc.stdout.strip()

    # Get git commit.
    proc = utilsRunGit(['rev-parse', '--short', 'HEAD'])
    if (not proc.stdout) or (proc.returncode != 0):
        raise ValueError('Failed to run git! (commit).')

    GIT_COMMIT = proc.stdout.strip()

    # Generate git revision string.
    proc = utilsRunGit(['status', '--porcelain'])
    if proc.returncode != 0:
        raise ValueError('Failed to run git! (porcelain).')

    GIT_REV = f'{GIT_BRANCH}-{GIT_COMMIT}{"-dirty" if proc.stdout.strip() else ""}'

    # Update default comment2 string.
    DEFAULT_COMMENT2 = html_escape(f'[{SCRIPT_NAME} revision {GIT_REV} used to generate XML files]' + (f'\n{DEFAULT_COMMENT2}' if DEFAULT_COMMENT2 else ''))

def utilsGetHactoolnetVersion() -> None:
    global HACTOOLNET_VERSION

    proc = subprocess.run([HACTOOLNET_PATH, '--help'], capture_output=True, encoding='utf-8')
    if proc.stdout:
        version = re.search(HACTOOLNET_VERSION_REGEX, proc.stdout)
        HACTOOLNET_VERSION = (version.group(1) if version else '')

    if not HACTOOLNET_VERSION:
        raise ValueError('Failed to get hactoolnet version!')

def utilsRunHactoolAtPath(tool_path: str, type: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    tool_args = [tool_path, '-t', type, '-k', KEYS_PATH, '--disablekeywarns'] + args
    return subprocess.run(tool_args, capture_output=True, encoding='utf-8')

def utilsRunHactool(type: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    return utilsRunHactoolAtPath(HACTOOL_PATH, type, args)

def utilsRunHactoolnet(type: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    return utilsRunHactoolAtPath(HACTOOLNET_PATH, type, args)

def utilsCopyKeysFile() -> None:
    hactoolnet_keys_path = os.path.abspath(os.path.expanduser(os.path.expandvars(DEFAULT_KEYS_PATH)))
    if KEYS_PATH != hactoolnet_keys_path:
        os.makedirs(hactoolnet_keys_path, exist_ok=True)
        shutil.copyfile(KEYS_PATH, hactoolnet_keys_path)

@dataclass(init=False)
class Checksums:
    crc32: str = ''
    md5: str = ''
    sha1: str = ''
    sha256: str = ''

    @classmethod
    def from_path(cls, path: str) -> Checksums:
        fd = open(path, 'rb')
        checksums = cls(fd)
        fd.close()
        return checksums

    @classmethod
    def from_bytes(cls, data: bytes) -> Checksums:
        fd = BytesIO(data)
        checksums = cls(fd)
        fd.close()
        return checksums

    @classmethod
    def from_string(cls, data: str, encoding: str = 'utf-8') -> Checksums:
        return cls.from_bytes(data.encode(encoding))

    def __init__(self, fd: IO) -> None:
        # Calculate checksums for the provided filepath.
        crc32_accum = 0
        md5_obj = hashlib.md5()
        sha1_obj = hashlib.sha1()
        sha256_obj = hashlib.sha256()

        while True:
            # Read file chunk.
            chunk = fd.read(HASH_BLOCK_SIZE)
            if not chunk:
                break

            # Update checksums.
            crc32_accum = zlib.crc32(chunk, crc32_accum)
            md5_obj.update(chunk)
            sha1_obj.update(chunk)
            sha256_obj.update(chunk)

        self.crc32 = f'{crc32_accum:08x}'
        self.md5 = md5_obj.hexdigest().lower()
        self.sha1 = sha1_obj.hexdigest().lower()
        self.sha256 = sha256_obj.hexdigest().lower()

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
    def checksums(self) -> Checksums | None:
        return self._checksums

    @property
    def cnt_id(self) -> str:
        # Content IDs are just the first half of the NCA's SHA-256 checksum.
        return (self._checksums.sha256[:32] if self._checksums else '')

    def __init__(self, nca_path: str, nca_size: int, thrd_id: int, tmp_titlekeys_path: str, expected_cnt_type: str = '') -> None:
        # Populate class variables.
        self._populate_vars(nca_path, nca_size, thrd_id, tmp_titlekeys_path, expected_cnt_type)

        # Run hactoolnet.
        proc = self._get_hactoolnet_output()

        # Parse hactoolnet output.
        self._parse_hactoolnet_output(proc)

        # Calculate NCA checksums.
        self._checksums = Checksums.from_path(self._nca_path)

    def _populate_vars(self, nca_path: str, nca_size: int, thrd_id: int, tmp_titlekeys_path: str, expected_cnt_type: str) -> None:
        self._nca_path = nca_path
        self._nca_size = nca_size
        self._nca_filename = os.path.basename(self._nca_path)

        self._thrd_id = thrd_id
        self._tmp_titlekeys_path = tmp_titlekeys_path

        self._expected_cnt_type = expected_cnt_type.lower()

        self._dist_type = ''
        self._cnt_type = ''
        self._crypto_type = ''
        self._rights_id = ''
        self._valid = False

        self._checksums: Checksums | None = None

    def _get_hactoolnet_output(self) -> subprocess.CompletedProcess[str]:
        # Run hactoolnet.
        proc = utilsRunHactoolnet('nca', ['--titlekeys', self._tmp_titlekeys_path, '-y', self._nca_path])
        if (not proc.stdout) or (proc.returncode != 0):
            # Check if we're dealing with a missing titlekey error.
            if proc.stderr and re.search(HACTOOLNET_MISSING_TITLEKEY_REGEX, proc.stderr):
                # Return prematurely, but provide the rights ID to the caller.
                rights_id = re.search(HACTOOLNET_ALT_RIGHTS_ID_REGEX, proc.stderr)
                rights_id = (rights_id.group(1).lower() if rights_id else '')
                raise self.Exception('placeholder', rights_id)
            else:
                hactoolnet_stderr = proc.stderr.strip()
                raise self.Exception(f'(Thread {self._thrd_id}) Failed to retrieve NCA info{f" ({hactoolnet_stderr})" if hactoolnet_stderr else ""}.')

        return proc

    def _parse_hactoolnet_output(self, proc: subprocess.CompletedProcess[str]) -> None:
        dist_type = re.search(HACTOOLNET_DISTRIBUTION_TYPE_REGEX, proc.stdout)
        cnt_type = re.search(HACTOOLNET_CONTENT_TYPE_REGEX, proc.stdout)
        crypto_type = re.search(HACTOOLNET_ENCRYPTION_TYPE_REGEX, proc.stdout)
        rights_id = re.search(HACTOOLNET_RIGHTS_ID_REGEX, proc.stdout)

        if (not dist_type) or (not cnt_type) or (not crypto_type):
            raise self.Exception(f'(Thread {self._thrd_id}) Failed to parse hactoolnet output.')

        self._dist_type = dist_type.group(1).lower()
        self._cnt_type = cnt_type.group(1).lower()
        self._crypto_type = crypto_type.group(1).lower().split()[0]
        self._rights_id = (rights_id.group(1).lower() if rights_id else '')
        self._valid = (len(re.findall(HACTOOLNET_VERIFICATION_FAIL_REGEX, proc.stdout)) == 0)

        if self._dist_type != NCA_DISTRIBUTION_TYPE:
            raise self.Exception(f'(Thread {self._thrd_id}) Invalid distribution type (got "{self._dist_type}", expected "{NCA_DISTRIBUTION_TYPE}").')

        if self._expected_cnt_type and (self._cnt_type != self._expected_cnt_type):
            raise self.Exception(f'(Thread {self._thrd_id}) Invalid content type (got "{self._cnt_type}", expected "{self._expected_cnt_type}").')

        if (self._crypto_type == 'titlekey') and (not self._rights_id):
            raise self.Exception(f'(Thread {self._thrd_id}) Failed to parse Rights ID from hactoolnet output.')

        if not self._valid:
            raise self.Exception(f'(Thread {self._thrd_id}) Signature/hash verification failed.')

@dataclass(init=False)
class TitleKeyInfo:
    filename: str = ''
    path: str = ''
    rights_id: str = ''
    value: str = ''
    raw_value: bytes = b''
    size: int = 16
    checksums: Checksums | None = None

    def __init__(self, titlekey: str, rights_id: str, data_path: str, is_decrypted: bool) -> None:
        # Populate properties.
        self.filename = f'{rights_id}.{"dec" if is_decrypted else "enc"}titlekey.tik'
        self.path = os.path.join(data_path, self.filename)
        self.rights_id = rights_id
        self.value = titlekey
        self.raw_value = bytes.fromhex(self.value)

        if KEEP_FOLDERS:
            # Write raw titlekey, if needed.
            with open(self.path, 'wb') as fd:
                fd.write(self.raw_value)

        # Calculate titlekey checksums.
        self.checksums = Checksums.from_bytes(self.raw_value)

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
    def checksums(self) -> Checksums:
        return self._tik_checksums

    @property
    def enc_titlekey(self) -> TitleKeyInfo | None:
        return self._enc_titlekey

    @property
    def dec_titlekey(self) -> TitleKeyInfo | None:
        return self._dec_titlekey

    def __init__(self, rights_id: str, data_path: str, nca_path: str, thrd_id: int) -> None:
        # Populate class variables.
        self._populate_vars(rights_id, data_path, nca_path, thrd_id)

        # Parse encrypted titlekey from ticket file.
        self._get_encrypted_titlekey()

        # Get decrypted titlekey.
        self._get_decrypted_titlekey()

    def _populate_vars(self, rights_id: str, data_path: str, nca_path: str, thrd_id: int) -> None:
        self._rights_id = rights_id.lower()
        self._data_path = data_path
        self._nca_path = nca_path
        self._thrd_id = thrd_id

        self._tik_filename = f'{self._rights_id}.tik'
        self._tik_path = os.path.join(self._data_path, self._tik_filename)
        self._tik_size = os.path.getsize(self._tik_path)
        self._tik_checksums: Checksums = Checksums.from_path(self._tik_path)

        self._enc_titlekey: TitleKeyInfo | None = None
        self._dec_titlekey: TitleKeyInfo | None = None

    def _get_encrypted_titlekey(self) -> None:
        # Make sure the ticket file exists.
        if not os.path.exists(self._tik_path):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: unable to locate ticket file "{self._tik_path}". Skipping current title.')

        # Parse ticket file.
        tik = Tik.from_file(self._tik_path)

        # Make sure the ticket uses common crypto.
        if tik.titlekey_type != Tik.TitlekeyType.common:
            raise self.Exception(f'(Thread {self._thrd_id}) Error: ticket "{self._tik_filename}" doesn\'t use common crypto. Skipping current title.')

        # Save encrypted titlekey.
        enc_titlekey = tik.titlekey_block[:16].hex().lower()
        self._enc_titlekey = TitleKeyInfo(enc_titlekey, self._rights_id, self._data_path, False)

        # Close ticket.
        tik.close()

    def _get_decrypted_titlekey(self) -> None:
        if not self._enc_titlekey:
            return

        # We'll actually use old hactool here.
        proc = utilsRunHactool('nca', [f'--titlekey={self._enc_titlekey.value}', self._nca_path])
        hactool_stderr = proc.stderr.strip()
        if (not proc.stdout) or (proc.returncode != 0):
            raise self.Exception(f'(Thread {self._thrd_id}) Failed to get decrypted titlekey{f" ({hactool_stderr})" if hactool_stderr else ""}.')

        dec_titlekey = re.search(HACTOOL_DECRYPTED_TITLEKEY_REGEX, proc.stdout)
        dec_titlekey = (dec_titlekey.group(1).lower() if dec_titlekey else '')
        if not dec_titlekey:
            raise self.Exception(f'(Thread {self._thrd_id}) Failed to parse decrypted titlekey from hactool output{f" ({hactool_stderr})" if hactool_stderr else ""}.')

        # Save decrypted titlekey.
        self._dec_titlekey = TitleKeyInfo(dec_titlekey, self._rights_id, self._data_path, True)

@dataclass(init=False)
class NacpLanguageEntry:
    name: str = ''
    publisher: str = ''
    lang: Nacp.Language | None = None

    def __init__(self, nacp_title: Nacp.Title, lang: int) -> None:
        self.name = nacp_title.name.strip()
        self.publisher = nacp_title.publisher.strip()
        self.lang = Nacp.Language(lang)

class TitleInfo:
    class Exception(Exception):
        def __init__(self, msg: str) -> None:
            super().__init__(msg)

    @property
    def id(self) -> str:
        return self._title_id

    @property
    def version(self) -> int:
        return self._title_version

    @property
    def type(self) -> Cnmt.ContentMetaType | None:
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
    def supported_dom_languages(self) -> list[str]:
        return self._supported_dom_languages

    @property
    def display_version(self) -> str:
        return self._display_version

    @property
    def is_demo(self) -> bool:
        return self._is_demo

    @property
    def contents(self) -> list[NcaInfo]:
        return self._contents

    def __init__(self, meta_nca: NcaInfo, data_path: str, tmp_titlekeys_path: str, thrd_id: int) -> None:
        # Populate class variables.
        self._populate_vars(meta_nca, data_path, tmp_titlekeys_path, thrd_id)

        # Extract CNMT file from the provided Meta NCA.
        self._extract_and_parse_cnmt()

        # Build NCA info list.
        self._build_content_list()

        # Perform cleanup.
        self._cleanup()

    def _populate_vars(self, meta_nca: NcaInfo, data_path: str, tmp_titlekeys_path: str, thrd_id: int) -> None:
        self._meta_nca = meta_nca
        self._data_path = data_path

        self._tmp_titlekeys_path = tmp_titlekeys_path
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

        # Retrieved from the NACP in the Control NCA. Placed here for convenience.
        self._lang_entries: list[NacpLanguageEntry] = []
        self._supported_dom_languages: list[str] = []
        self._display_version: str = ''
        self._is_demo: bool = False

        self._contents: list[NcaInfo] = []

        self._cleanup_called = False

    def _extract_and_parse_cnmt(self) -> None:
        # Extract files from Meta NCA FS section 0.
        proc = utilsRunHactoolnet('nca', ['--section0dir', self._data_path, self._meta_nca.path])
        if (not proc.stdout) or (proc.returncode != 0):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: failed to extract Meta NCA FS section 0. Skipping current title.')

        # Get extracted CNMT filename from hactoolnet's output.
        cnmt_filename = re.search(HACTOOLNET_SAVING_REGEX, proc.stdout)
        if (not cnmt_filename):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: failed to parse CNMT filename from hactool output. Skipping current title.')

        # Make sure the CNMT was extracted.
        cnmt_filename = cnmt_filename.group(1).strip()
        self._cnmt_path = os.path.join(self._data_path, cnmt_filename)
        if not os.path.exists(self._cnmt_path):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: failed to locate CNMT file after extraction. Skipping current title.')

        # Parse CNMT file.
        self._cnmt = Cnmt.from_file(self._cnmt_path)

        # Update class properties.
        self._title_id = f'{self._cnmt.header.title_id:016x}'

        titlever = self._cnmt.header.version.raw_version
        if isinstance(titlever, int):
            self._title_version = titlever

        self._title_type = Cnmt.ContentMetaType(self._cnmt.header.content_meta_type)

        # Make sure we're dealing with a supported title type.
        if (self._title_type.value < Cnmt.ContentMetaType.application.value) or (self._title_type.value > Cnmt.ContentMetaType.data_patch.value) or (self._title_type.value == Cnmt.ContentMetaType.delta.value):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: invalid content meta type value (0x{self._title_type.value:02x}). Skipping current title.')

    def _build_content_list(self) -> None:
        if not self._cnmt:
            return

        # Iterate over all content records.
        for i in range(self._cnmt.header.content_count):
            # Get current content info entry.
            packaged_content_info: Cnmt.PackagedContentInfo = self._cnmt.packaged_content_infos[i]

            # Generate NCA path.
            nca_filename = f'{packaged_content_info.info.id.hex().lower()}.nca'
            nca_path = os.path.join(self._data_path, nca_filename)
            cnt_type = Cnmt.ContentType(packaged_content_info.info.type).name

            print(f'(Thread {self._thrd_id}) Parsing {utilsCapitalizeString(cnt_type, " ")} NCA #{packaged_content_info.info.id_offset}: "{nca_filename}".', flush=True)

            # Check if this NCA actually exists. Don't proceed any further with the current title if this NCA isn't available.
            # We don't really care about missing DeltaFragment NCAs, though.
            if not os.path.exists(nca_path):
                msg = f'(Thread {self._thrd_id}) Error: file "{nca_path}" not found.'

                if cnt_type == 'delta_fragment':
                    eprint(f'{msg} Skipping NCA.')
                    continue

                raise self.Exception(f'{msg}. Skipping current title.')

            # Validate NCA size.
            nca_size = os.path.getsize(nca_path)
            if nca_size != packaged_content_info.info.raw_size:
                raise self.Exception(f'(Thread {self._thrd_id}) Error: invalid size for "{nca_path}" (got 0x{nca_size:x}, expected 0x{packaged_content_info.info.raw_size:x}).')

            # Retrieve NCA information.
            nca_info = self._get_nca_info(nca_path, nca_size)

            # Verify content ID.
            if (packaged_content_info.info.id != packaged_content_info.hash[:16]) or (packaged_content_info.info.id.hex().lower() != nca_info.cnt_id):
                raise self.Exception(f'(Thread {self._thrd_id}) Error: content ID / hash mismatch.')

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
            nca_info = NcaInfo(nca_path, nca_size, self._thrd_id, self._tmp_titlekeys_path)
        except NcaInfo.Exception as e:
            # Check if we're dealing with a missing titlekey.
            if e.rights_id and (not self._rights_id):
                # Set rights ID for this title.
                self._rights_id = e.rights_id

                # Retrieve ticket file info for this title.
                self._get_tik_info(nca_path)

                try:
                    # Try to retrieve NCA information once more, this time using proper titlekey crypto info.
                    nca_info = NcaInfo(nca_path, nca_size, self._thrd_id, self._tmp_titlekeys_path)
                except NcaInfo.Exception as e:
                    # Reraise the exception as a TitleInfo.Exception.
                    raise self.Exception(str(e))
            else:
                # Reraise the exception as a TitleInfo.Exception.
                raise self.Exception(str(e))

        return nca_info

    def _get_tik_info(self, nca_path: str) -> None:
        try:
            # Retrieve ticket file info.
            self._tik_info = TikInfo(self._rights_id, self._data_path, nca_path, self._thrd_id)
        except TikInfo.Exception as e:
            # Reraise the exception as a TitleInfo.Exception.
            raise self.Exception(str(e))

        # Update temporary titlekeys file for this thread.
        with open(self._tmp_titlekeys_path, 'a', encoding='utf-8') as fd:
            fd.write(f'{self._rights_id} = {self._tik_info.enc_titlekey.value if self._tik_info.enc_titlekey else ""}\n')

    def _extract_and_parse_nacp(self, nca_info: NcaInfo) -> None:
        # Extract files from Control NCA FS section 0.
        proc = utilsRunHactoolnet('nca', ['--section0dir', self._data_path, nca_info.path])
        if (not proc.stdout) or (proc.returncode != 0):
            eprint(f'(Thread {self._thrd_id}) Error: failed to extract Control NCA FS section 0. Skipping additional metadata retrieval for current title.')
            return

        # Make sure the NACP was extracted.
        self._nacp_path = os.path.join(self._data_path, 'control.nacp')
        if not os.path.exists(self._nacp_path):
            eprint(f'(Thread {self._thrd_id}) Error: failed to locate NACP file after extraction. Skipping additional metadata retrieval for current title.')
            return

        # Parse NACP file.
        self._nacp = Nacp.from_file(self._nacp_path)

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

            # Build a NacpLanguageEntry object using
            nacp_lang_entry = NacpLanguageEntry(nacp_title, lang.value)

            # Update language entry dictionary.
            self._lang_entries.append(nacp_lang_entry)

            # Update supported DoM languages list.
            dom_lang = DOM_LANGUAGES.get(nacp_lang_entry.lang.name if nacp_lang_entry.lang else '', '')
            if dom_lang:
                self._supported_dom_languages.append(dom_lang)

        # Get additional NACP properties.
        self._display_version = self._nacp.display_version
        self._is_demo = bool(self._nacp.attribute.demo)

    def _cleanup(self) -> None:
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
            dat_list = glob.glob(os.path.join(self._data_path, '*.dat'))
            for dat in dat_list:
                os.remove(dat)

        # Update flag.
        self._cleanup_called = True

    def __exit__(self) -> None:
        #print('title: __exit__ called', flush=True)
        self._cleanup()

    def __del__(self) -> None:
        #print('title: __del__ called', flush=True)
        self._cleanup()

class NspInfo:
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
    def is_nsz(self) -> bool:
        return self._is_nsz

    @property
    def checksums(self) -> Checksums | None:
        return self._checksums

    @property
    def titles(self) -> list[TitleInfo]:
        return self._titles

    def __init__(self, file_entry: FileListEntry, tmp_titlekeys_path: str, thrd_id: int) -> None:
        # Populate class variables.
        self._populate_vars(file_entry, tmp_titlekeys_path, thrd_id)

        # Handle filenames with non-ASCII codepoints.
        self._handle_nonascii_filename()

        # Convert NSZ back to NSP, if needed.
        self._convert_nsz()

        # Calculate NSP checksums, if needed.
        if not EXCLUDE_NSP:
            self._checksums = Checksums.from_path(self._nsp_path)

        # Extract NSP.
        self._extract_nsp()

        # Build NSP title list.
        self._build_title_list()

        # Perform cleanup.
        self._cleanup()

    def _populate_vars(self, file_entry: FileListEntry, tmp_titlekeys_path: str, thrd_id: int) -> None:
        self._orig_nsp_path = file_entry[0]
        self._nsp_path = file_entry[0]
        self._nsp_size = file_entry[1]
        self._nsp_filename = f'{os.path.splitext(os.path.basename(self._nsp_path))[0]}.nsp'

        self._is_nsz = self._nsp_path.lower().endswith('.nsz')
        self._tmp_path = ''

        self._tmp_titlekeys_path = tmp_titlekeys_path
        self._thrd_id = thrd_id

        self._checksums: Checksums | None = None

        self._ext_nsp_path = ''

        self._titles: list[TitleInfo] = []

        self._cleanup_called = False

    def _handle_nonascii_filename(self) -> None:
        if utilsIsAsciiString(self._nsp_path):
            return

        self._tmp_path = os.path.join(os.path.dirname(self._nsp_path), f'{utilsGetRandomString(16)}_{self._thrd_id}.{"nsz" if self._is_nsz else "nsp"}')
        os.rename(self._nsp_path, self._tmp_path)
        self._nsp_path = self._tmp_path

    def _convert_nsz(self) -> None:
        if not self._is_nsz:
            return

        print(f'(Thread {self._thrd_id}) Converting NSZ to NSP...', flush=True)

        nsz_args = ['nsz', '-D', '-o', OUTPUT_PATH, self._nsp_path]
        new_nsp_path = os.path.join(OUTPUT_PATH, f'{os.path.splitext(os.path.basename(self._nsp_path))[0]}.nsp')

        proc = subprocess.run(nsz_args, capture_output=True, encoding='utf-8')
        new_nsp_size = (os.path.getsize(new_nsp_path) if os.path.exists(new_nsp_path) else 0)

        if (not proc.stdout) or (proc.returncode != 0) or (new_nsp_size <= 0):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: failed to convert NSZ to NSP.')

        self._nsp_path = new_nsp_path
        self._nsp_size = new_nsp_size

    def _extract_nsp(self) -> None:
        # Generate path to extracted NSP directory.
        self._ext_nsp_path = os.path.join(OUTPUT_PATH, f'{GIT_REV}_{utilsGetRandomString(8)}_{self._thrd_id}')

        # Extract files from the provided NSP.
        proc = utilsRunHactoolnet('pfs0', ['--outdir', self._ext_nsp_path, self._nsp_path])
        if (not proc.stdout) or (proc.returncode != 0) or (not os.path.exists(self._ext_nsp_path)):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: failed to extract NSP.')

        # Delete unnecessary files.
        files_to_delete = [fn for fn in glob.glob(os.path.join(self._ext_nsp_path, '*')) if ((not fn.lower().endswith('.nca')) and (not fn.lower().endswith('.tik')))]
        for fn in files_to_delete:
            os.remove(fn)

    def _build_title_list(self) -> None:
        # Collect information from all available Meta NCAs.
        meta_nca_infos = self._get_meta_nca_infos()
        if not meta_nca_infos:
            raise self.Exception(f'(Thread {self._thrd_id}) Error: failed to locate any Meta NCAs within the extracted NSP data.')

        # Loop through all Meta NCAs.
        for meta_nca in meta_nca_infos:
            try:
                # Initialize TitleInfo object using the current Meta NCA.
                title_info = TitleInfo(meta_nca, self._ext_nsp_path, self._tmp_titlekeys_path, self._thrd_id)
            except TitleInfo.Exception as e:
                eprint(str(e))
                continue

            # Update title list.
            self._titles.append(title_info)

    def _get_meta_nca_infos(self) -> list[NcaInfo]:
        meta_nca_infos: list[NcaInfo] = []

        # Scan extracted NSP directory. We'll look for all the available Meta NCAs.
        meta_nca_list = glob.glob(os.path.join(self._ext_nsp_path, '*.cnmt.nca'))
        for cur_path in meta_nca_list:
            # Skip directories.
            if os.path.isdir(cur_path):
                continue

            # Skip empty files.
            nca_size = os.path.getsize(cur_path)
            if not nca_size:
                continue

            print(f'(Thread {self._thrd_id}) Parsing Meta NCA: "{os.path.basename(cur_path)}".', flush=True)

            try:
                # Retrieve Meta NCA information.
                nca_info = NcaInfo(cur_path, nca_size, self._thrd_id, self._tmp_titlekeys_path, 'meta')
            except NcaInfo.Exception as e:
                eprint(str(e))
                continue

            # Update Meta NCA list.
            meta_nca_infos.append(nca_info)

        return meta_nca_infos

    def _cleanup(self, override_keep_folders: bool = False) -> None:
        if self._cleanup_called:
            return

        if self._ext_nsp_path:
            if self._titles and KEEP_FOLDERS and (not override_keep_folders):
                # Rename extracted NSP directory.
                new_ext_nsp_path = os.path.join(OUTPUT_PATH, self._nsp_filename)
                if os.path.exists(new_ext_nsp_path):
                    if os.path.isdir(new_ext_nsp_path):
                        shutil.rmtree(new_ext_nsp_path, ignore_errors=True)
                    else:
                        os.remove(new_ext_nsp_path)

                os.rename(self._ext_nsp_path, new_ext_nsp_path)
            else:
                # Delete extracted data.
                shutil.rmtree(self._ext_nsp_path, ignore_errors=True)

        # Delete NSP if the original file is a NSZ.
        if self._is_nsz and self._ext_nsp_path:
            os.remove(self._nsp_path)

        # Rename NSP, if needed.
        if self._tmp_path:
            os.rename(self._tmp_path, self._orig_nsp_path)

        # Update flag.
        self._cleanup_called = True

    def __exit__(self) -> None:
        #print('nsp: __exit__ called', flush=True)
        self._cleanup(True)

    def __del__(self) -> None:
        #print('nsp: __del__ called', flush=True)
        self._cleanup(True)

class XmlDataset:
    @total_ordering
    class Type(IntEnum):
        APPLICATION = 0,
        UPDATE = 1,
        DLC = 2,
        DLC_UPDATE = 3,
        COUNT = 4

        @property
        def normalized_name(self) -> str:
            return utilsCapitalizeString(self.name, ' ').replace('Dlc', 'DLC')

        def __str__(self):
            return f'{self.__class__.__name__}.{self.name}'

        @classmethod
        def _missing_(cls, value: str) -> XmlDataset.Type:
            if isinstance(value, str):
                value_up = value.upper()
                if value_up in dir(cls):
                    return cls[value_up]

            raise ValueError(f'{value:r} is not a valid {cls.__name__}')

        def __lt__(self, other: XmlDataset.Type) -> bool:
            if self.__class__ is other.__class__:
                return (self.value < other.value)
            return NotImplemented

    @property
    def type(self) -> XmlDataset.Type:
        return self._type

    @property
    def path(self) -> str:
        return self._path

    @property
    def entry_count(self) -> int:
        return self._entry_count

    @property
    def is_finalized(self) -> bool:
        return self._is_finalized

    def __init__(self, type: XmlDataset.Type) -> None:
        self._type = type
        self._path = os.path.join(OUTPUT_PATH, f'nswd_{self._type.name.lower()}.xml')
        self._fd: IO | None = None
        self._comment2 = ('' if EXCLUDE_COMMENT else DEFAULT_COMMENT2)
        self._entry_count = 0
        self._is_finalized = False

    def add_entry(self, nsp_info: NspInfo, title_info: TitleInfo) -> None:
        if self._is_finalized or (not nsp_info) or (not nsp_info.checksums) or (not title_info) or (not title_info.type):
            return

        # Make sure we're dealing with a valid title type.
        if (self._type == XmlDataset.Type.APPLICATION and title_info.type != Cnmt.ContentMetaType.application) or (self._type == XmlDataset.Type.UPDATE and title_info.type != Cnmt.ContentMetaType.patch) or (self._type == XmlDataset.Type.DLC and title_info.type != Cnmt.ContentMetaType.add_on_content) or (self._type == XmlDataset.Type.DLC_UPDATE and title_info.type != Cnmt.ContentMetaType.data_patch):
            raise ValueError(f'Error: invalid content meta type value for {self._type.normalized_name} dataset (0x{title_info.type.value:02x}).')

        # Make sure the XML file has been opened.
        self._open_xml()

        # Generate archive name string.
        archive_name = self._get_archive_name(nsp_info, title_info)

        # Generate languages string.
        languages = self._get_languages(title_info)

        # Generate version strings.
        (version1, version2) = self._get_versions(title_info)

        # Generate dev status string.
        dev_status = self._get_dev_status(title_info)

        # Generate XML entry.
        title_str  = '  <game name="">\n'
        title_str += f'    <archive name="{archive_name}" name_alt="" region="{DEFAULT_REGION}" languages="{languages}" langchecked="0" version1="{version1}" version2="{version2}" devstatus="{dev_status}" additional="eShop" special1="" special2="" gameid1="{title_info.id}" />\n'

        if title_info.lang_entries or title_info.display_version:
            title_str += '    <media>\n'

            for lang_entry in title_info.lang_entries:
                if not lang_entry.lang:
                    continue

                cap_lang_name = utilsCapitalizeString(lang_entry.lang.name)

                if lang_entry.name:
                    title_str += f'      <field name="Original Name (NACP, {cap_lang_name})" value="{html_escape(lang_entry.name)}" />\n'

                if lang_entry.publisher:
                    title_str += f'      <field name="Publisher (NACP, {cap_lang_name})" value="{html_escape(lang_entry.publisher)}" />\n'

            if title_info.display_version:
                title_str += f'      <field name="Display Version (NACP)" value="{html_escape(title_info.display_version)}" />\n'

            title_str += '    </media>\n'

        title_str += '    <source>\n'
        title_str += f'      <details section="{DEFAULT_SECTION}" rominfo="" originalformat="NSP" d_date="{DEFAULT_DDATE}" d_date_info="{int(DDATE_PROVIDED)}" r_date="{DEFAULT_RDATE}" r_date_info="{int(RDATE_PROVIDED)}" dumper="{DEFAULT_DUMPER}" project="{DEFAULT_PROJECT}" tool="{DEFAULT_TOOL}" region="{DEFAULT_REGION}" origin="" comment1="" comment2="{self._comment2}" link1="" link2="" media_title="" />\n'
        title_str += f'      <serials media_serial1="" media_serial2="" pcb_serial="" romchip_serial1="" romchip_serial2="" lockout_serial="" savechip_serial="" chip_serial="" box_serial="" mediastamp="" box_barcode="" digital_serial1="{title_info.id}" digital_serial2="" />\n'

        if not EXCLUDE_NSP:
            # Add NSP information.
            title_str += self._generate_xml_file_elem('', 'nsp', 'NSP', '', title_info.version, nsp_info.size, nsp_info.checksums, '')

        for cnt in title_info.contents:
            if not cnt.checksums:
                continue

            # Add current NCA information.
            if cnt.rights_id and title_info.tik_info and title_info.tik_info.enc_titlekey and title_info.tik_info.enc_titlekey.checksums:
                nca_note = f'[Passed verification with titlekey with SHA256 {title_info.tik_info.enc_titlekey.checksums.sha256} using hactoolnet v{HACTOOLNET_VERSION}]'
            else:
                nca_note = f'[Passed verification, no titlekey required, using hactoolnet v{HACTOOLNET_VERSION}]'

            title_str += self._generate_xml_file_elem(cnt.filename, '', 'CDN', nca_note, title_info.version, cnt.size, cnt.checksums, utilsCapitalizeString(cnt.cnt_type))

        if (not EXCLUDE_TIK) and title_info.tik_info:
            # Add ticket info.
            title_str += self._generate_xml_file_elem(title_info.tik_info.filename, '', 'CDN', '', title_info.version, title_info.tik_info.size, title_info.tik_info.checksums, '')

            # Add encrypted titlekey info.
            if title_info.tik_info.enc_titlekey and title_info.tik_info.enc_titlekey.checksums:
                title_str += self._generate_xml_file_elem(title_info.tik_info.enc_titlekey.filename, '', 'CDN', '', title_info.version, title_info.tik_info.enc_titlekey.size, title_info.tik_info.enc_titlekey.checksums, '')

            # Add decrypted titlekey info.
            if title_info.tik_info.dec_titlekey and title_info.tik_info.dec_titlekey.checksums:
                title_str += self._generate_xml_file_elem(title_info.tik_info.dec_titlekey.filename, '', 'CDN', '', title_info.version, title_info.tik_info.dec_titlekey.size, title_info.tik_info.dec_titlekey.checksums, '')

        # Update title string.
        title_str += '    </source>\n'
        title_str += '  </game>\n'

        # Write metadata.
        if self._fd:
            self._fd.write(title_str)

        # Update entry count.
        self._entry_count += 1

    def finalize(self, force_deletion: bool = False) -> None:
        if self._is_finalized:
            return

        if self._fd:
            if (self._entry_count > 0) and (not force_deletion):
                # Write XML footer.
                self._fd.write(XML_FOOTER)

            # Close XML file.
            self._fd.close()

            if (self._entry_count <= 0) or force_deletion:
                # Delete XML file.
                os.remove(self._path)

        # Update flag.
        self._is_finalized = True

    def _open_xml(self) -> None:
        if self._fd:
            return

        # Open output XML file.
        self._fd = open(self._path, 'w', encoding='utf-8-sig')

        # Write XML file header.
        self._fd.write(XML_HEADER)

    def _get_archive_name(self, nsp_info: NspInfo, title_info: TitleInfo) -> str:
        if title_info.lang_entries:
            # Default to the first NACP language entry we found.
            archive_name = self._normalize_archive_name(title_info.lang_entries[0].name)
        else:
            # Use the NSP filename (gross, I know, but it's either this or using an external database).
            archive_name = self._normalize_archive_name(re.split(r'[\[\(]', os.path.splitext(nsp_info.filename)[0], 1)[0])
            if not archive_name:
                # Fallback to just using the title ID.
                archive_name = title_info.id

        return archive_name

    def _normalize_archive_name(self, name: str) -> str:
        # Remove illegal filesystem characters.
        out = re.sub(r'[\\/*?"<>|]', '', name)

        # Replace colons with dashes.
        out = re.sub(r'\s*:\s*', ' - ', out)

        # Replace consecutive whitespaces with a single one.
        out = ' '.join(out.split()).strip()

        # Escape HTML entities.
        return html_escape(out)

    def _get_languages(self, title_info: TitleInfo) -> str:
        return ('En' if not title_info.supported_dom_languages else ','.join(title_info.supported_dom_languages))

    def _get_versions(self, title_info: TitleInfo) -> tuple[str, str]:
        version1 = (f'v{title_info.version}' if (title_info.version > 0) else '')
        version2 = (html_escape(f'v{title_info.display_version}') if (title_info.display_version and title_info.type != Cnmt.ContentMetaType.application) else '')
        return (version1, version2)

    def _get_dev_status(self, title_info: TitleInfo) -> str:
        dev_status = (['Demo'] if title_info.is_demo else [])

        match title_info.type:
            case Cnmt.ContentMetaType.patch:
                dev_status.append('Update')
            case Cnmt.ContentMetaType.add_on_content:
                dev_status.append('DLC')
            case Cnmt.ContentMetaType.data_patch:
                dev_status.append('DLC Update')
            case _:
                pass

        return (','.join(dev_status) if dev_status else '')

    def _generate_xml_file_elem(self, forcename: str, extension: str, format: str, note: str, version: int, size: int, checksums: Checksums, filter: str) -> str:
        extension = (f' extension="{extension}" ' if extension else ' ')
        note = (f' note="{note}" ' if note else ' ')
        filter = (f' filter="{filter}" ' if filter else ' ')

        return f'      <file forcename="{forcename}"{extension}format="{format}"{note}version="{version}" size="{size}" crc32="{checksums.crc32}" md5="{checksums.md5}" sha1="{checksums.sha1}" sha256="{checksums.sha256}"{filter}/>\n'

    def __exit__(self) -> None:
        #print('xml: __exit__ called', flush=True)
        self.finalize(True)

    def __del__(self) -> None:
        #print('xml: __del__ called', flush=True)
        self.finalize(True)

def utilsGenerateXmlDataset(nsp_list: list[NspInfo]) -> None:
    xml_obj: list[XmlDataset] = []

    type_dict: dict[int, int] = {
        Cnmt.ContentMetaType.application.value: XmlDataset.Type.APPLICATION.value,
        Cnmt.ContentMetaType.patch.value: XmlDataset.Type.UPDATE.value,
        Cnmt.ContentMetaType.add_on_content.value: XmlDataset.Type.DLC.value,
        Cnmt.ContentMetaType.data_patch.value: XmlDataset.Type.DLC_UPDATE.value
    }

    # Initialize our XmlDataset objects.
    for i in range(XmlDataset.Type.COUNT.value):
        cur_xml_obj = XmlDataset(XmlDataset.Type(i))
        xml_obj.append(cur_xml_obj)

    # Process NSP info list.
    for nsp_info in nsp_list:
        # Process titles availables in current NSP.
        for title_info in nsp_info.titles:
            if not title_info.type:
                continue

            # Get XML object index based on the current title type.
            idx = type_dict.get(title_info.type.value, None)
            if idx is None:
                raise ValueError(f'Error: invalid content meta type value (0x{title_info.type.value:02x}).')

            # Add entry to XML object.
            xml_obj[idx].add_entry(nsp_info, title_info)

    print()

    # Finalize all XML objects.
    for cur_xml_obj in xml_obj:
        cur_xml_obj.finalize()

        if cur_xml_obj.entry_count > 0:
            print(f'Successfully wrote {cur_xml_obj.entry_count} {cur_xml_obj.type.normalized_name} {"entries" if cur_xml_obj.entry_count > 1 else "entry"} to "{cur_xml_obj.path}".', flush=True)

def utilsProcessNspList(file_list_chunks: list[FileList], results: list[list[NspInfo]]) -> None:
    thrd_id = int(threading.current_thread().name)

    file_list = file_list_chunks[thrd_id]
    thrd_res: list[NspInfo] = []

    # Generate temporary titlekeys file for this thread.
    tmp_titlekeys_path = os.path.join(OUTPUT_PATH, f'{GIT_REV}_{utilsGetRandomString(8)}_{thrd_id}_title.keys')
    with open(tmp_titlekeys_path, 'w'):
        pass

    # Process NSP files.
    for entry in file_list:
        print(f'(Thread {thrd_id}) Processing "{os.path.basename(entry[0])}" (0x{entry[1]:X} bytes long)...', flush=True)

        try:
            nsp_info = NspInfo(entry, tmp_titlekeys_path, thrd_id)
        except NspInfo.Exception as e:
            eprint(str(e))
            continue

        # Update output list.
        thrd_res.append(nsp_info)

    # Update results entry.
    results[thrd_id] = thrd_res

    # Remove temporary titlekeys file.
    if os.path.exists(tmp_titlekeys_path):
        os.remove(tmp_titlekeys_path)

def utilsGetNspFileList(path: str) -> FileList:
    file_list: FileList = []

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
        file_list.append((cur_path, file_size))

    return file_list

def utilsProcessNspDirectory() -> None:
    nsp_list: list[NspInfo] = []

    # Get NSP/NSZ file list.
    file_list = utilsGetNspFileList(NSP_PATH)
    if not file_list:
        raise FileNotFoundError('Error: input directory holds no NSP/NSZ files.')

    # Create processing threads.
    file_list_chunks: list[FileList] = list(filter(None, list(utilsGetListChunks(file_list, NUM_THREADS))))
    num_threads = len(file_list_chunks)

    threads: list[threading.Thread] = []
    results: list[list[NspInfo]] = [[]] * num_threads

    for i in range(num_threads):
        cur_thread = threading.Thread(name=str(i), target=utilsProcessNspList, args=(file_list_chunks, results), daemon=True)
        cur_thread.start()
        threads.append(cur_thread)

    # Wait until all threads finish doing their job.
    while len(threading.enumerate()) > 1:
        time.sleep(1)

    # Generate full list with results from all threads.
    for res in results:
        nsp_list.extend(res)

    # Check if we were able to populate our NSP list.
    if not nsp_list:
        raise ValueError('Error: failed to process any NSP files.')

    # Generate output XML dataset.
    utilsGenerateXmlDataset(nsp_list)

def utilsValidateThreadCount(num_threads: str) -> int:
    val = int(num_threads)
    if (val <= 0) or (val > MAX_CPU_THREAD_COUNT):
        raise argparse.ArgumentTypeError(f'Invalid thread count provided. Value must be in the range [1, {MAX_CPU_THREAD_COUNT}].')
    return val

def main() -> int:
    global NSP_PATH, HACTOOL_PATH, HACTOOLNET_PATH, KEYS_PATH, OUTPUT_PATH, EXCLUDE_NSP, EXCLUDE_TIK
    global DEFAULT_SECTION, DDATE_PROVIDED, DEFAULT_DDATE, RDATE_PROVIDED, DEFAULT_RDATE, DEFAULT_DUMPER, DEFAULT_PROJECT, DEFAULT_TOOL, DEFAULT_REGION
    global EXCLUDE_COMMENT, KEEP_FOLDERS, NUM_THREADS

    # Get git commit information.
    utilsGetGitRepositoryInfo()

    # Reconfigure terminal output whenever possible.
    utilsReconfigureTerminalOutput()

    parser = argparse.ArgumentParser(description='Generate a XML dataset from Nintendo Submission Package (NSP) files.')

    parser.add_argument('--nspdir', type=str, metavar='DIR', default='', help=f'Path to directory with NSP files. Defaults to "{NSP_PATH}".')
    parser.add_argument('--hactool', type=str, metavar='FILE', default='', help=f'Path to hactool binary. Defaults to "{HACTOOL_PATH}".')
    parser.add_argument('--hactoolnet', type=str, metavar='FILE', default='', help=f'Path to hactoolnet binary. Defaults to "{HACTOOLNET_PATH}".')
    parser.add_argument('--keys', type=str, metavar='FILE', default='', help=f'Path to Nintendo Switch keys file. Defaults to "{KEYS_PATH}".')
    parser.add_argument('--outdir', type=str, metavar='DIR', default='', help=f'Path to output directory. Defaults to "{OUTPUT_PATH}".')
    parser.add_argument('--exclude-nsp', action='store_true', default=EXCLUDE_NSP, help='Excludes NSP metadata from the output XML dataset. Disabled by default.')
    parser.add_argument('--exclude-tik', action='store_true', default=EXCLUDE_TIK, help='Excludes ticket metadata from the output XML dataset. Disabled by default.')

    parser.add_argument('--section', type=str, default='', help='Section string used in the output XML dataset. Optional.')
    parser.add_argument('--dump-date', type=datetime.date.fromisoformat, default=argparse.SUPPRESS, metavar='YYYY-MM-DD', help='Dump date used in the output XML dataset. Defaults to current date if not provided.')
    parser.add_argument('--release-date', type=datetime.date.fromisoformat, default=argparse.SUPPRESS, metavar='YYYY-MM-DD', help='Release date used in the output XML dataset. Optional.')
    parser.add_argument('--dumper', type=str, default=DEFAULT_DUMPER, help=f'Dumper string used in the output XML dataset. Defaults to "{DEFAULT_DUMPER}" if not provided.')
    parser.add_argument('--project', type=str, default=DEFAULT_PROJECT, help=f'Project string used in the output XML dataset. Defaults to "{DEFAULT_PROJECT}" if not provided.')
    parser.add_argument('--tool', type=str, default=DEFAULT_TOOL, help=f'Tool string used in the output XML dataset. Defaults to "{DEFAULT_TOOL}" if not provided.')
    parser.add_argument('--region', type=str, default=DEFAULT_REGION, help=f'Region string used in the output XML dataset. Defaults to "{DEFAULT_REGION}" if not provided.')

    parser.add_argument('--exclude-comment', action='store_true', default=EXCLUDE_COMMENT, help='Excludes information about this script from the comment2 field in XML entries. Disabled by default (comment2 fields hold information about this script).')
    parser.add_argument('--keep-folders', action='store_true', default=KEEP_FOLDERS, help='Keeps extracted NSP folders in the provided output directory. Disabled by default (all extracted folders are removed).')
    parser.add_argument('--num-threads', type=utilsValidateThreadCount, metavar='VALUE', default=NUM_THREADS, help=f'Sets the number of threads used to process input NSP/NSZ files. Defaults to {NUM_THREADS} if not provided. This value must not be exceeded.')

    print(f'{SCRIPT_NAME}.\nRevision: {GIT_REV}.\nMade by DarkMatterCore.\n', flush=True)

    # Parse arguments. Make sure to escape characters where needed.
    args = parser.parse_args()

    NSP_PATH = utilsGetPath(args.nspdir, os.path.join(INITIAL_DIR, NSP_PATH), False)
    HACTOOL_PATH = utilsGetPath(args.hactool, os.path.join(INITIAL_DIR, HACTOOL_PATH), True)
    HACTOOLNET_PATH = utilsGetPath(args.hactoolnet, os.path.join(INITIAL_DIR, HACTOOLNET_PATH), True)
    KEYS_PATH = utilsGetPath(args.keys, KEYS_PATH, True)
    OUTPUT_PATH = utilsGetPath(args.outdir, os.path.join(INITIAL_DIR, OUTPUT_PATH), False, True)
    EXCLUDE_NSP = args.exclude_nsp
    EXCLUDE_TIK = args.exclude_tik

    DEFAULT_SECTION = html_escape(args.section)
    DDATE_PROVIDED = ('dump_date' in args)
    DEFAULT_DDATE = (args.dump_date.isoformat() if DDATE_PROVIDED else datetime.datetime.now().date().isoformat())
    RDATE_PROVIDED = ('release_date' in args)
    DEFAULT_RDATE = (args.release_date.isoformat() if RDATE_PROVIDED else '')
    DEFAULT_DUMPER = html_escape(args.dumper)
    DEFAULT_PROJECT = html_escape(args.project)
    DEFAULT_TOOL = html_escape(args.tool)
    DEFAULT_REGION = html_escape(args.region)

    EXCLUDE_COMMENT = args.exclude_comment
    KEEP_FOLDERS = args.keep_folders
    NUM_THREADS = args.num_threads

    # Get hactoolnet version.
    utilsGetHactoolnetVersion()

    # Check if nsz has been installed.
    if not shutil.which('nsz'):
        raise ValueError('Error: "nsz" package unavailable.')

    # Copy keys file (required by nsz since it offers no way to provide a keys file path).
    utilsCopyKeysFile()

    # Do our thing.
    utilsProcessNspDirectory()

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
