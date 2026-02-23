#!/usr/bin/env python3

"""
 * xml_dataset_generator_nsp.py
 *
 * Copyright (c) 2022 - 2026, DarkMatterCore <pabloacurielz@gmail.com>.
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

from turtle import title
import os, sys, re, subprocess, shutil, hashlib, zlib, random, string, datetime, glob, threading, psutil, time, argparse, io, traceback, pathlib, rsa, struct, json

from functools import total_ordering
from enum import IntEnum
from dataclasses import dataclass
from typing import Generator, TypeAlias
from html import escape as html_escape

# Reference: https://github.com/python/typing/issues/182#issuecomment-1320974824
JSON: TypeAlias = dict[str, "JSON"] | list["JSON"] | str | int | float | bool | None

FileListEntry: TypeAlias = tuple[str, int]
FileList: TypeAlias = list[FileListEntry]

SCRIPT_PATH: str = os.path.realpath(__file__)
SCRIPT_NAME: str = os.path.basename(SCRIPT_PATH)
SCRIPT_DIR:  str = os.path.dirname(SCRIPT_PATH)

CWD:         str = os.getcwd()
INITIAL_DIR: str = (CWD if CWD != SCRIPT_DIR else SCRIPT_DIR)

MAX_CPU_THREAD_COUNT: int = psutil.cpu_count()

DEFAULT_KEYS_PATH: str = os.path.join('~', '.switch', 'prod.keys')

NSP_PATH:        str = os.path.join('.', 'nsp')
HACTOOLNET_PATH: str = os.path.join('.', ('hactoolnet.exe' if os.name == 'nt' else 'hactoolnet'))
KEYS_PATH:       str = DEFAULT_KEYS_PATH
OUTPUT_PATH:     str = os.path.join('.', 'out')
EXCLUDE_NSP:     bool = False
EXCLUDE_TIK:     bool = False

DEFAULT_SECTION:  str = 'Trusted Dump'
DDATE_PROVIDED:   bool = False
DEFAULT_DDATE:    str = ''
RDATE_PROVIDED:   bool = False
DEFAULT_RDATE:    str = ''
DEFAULT_DUMPER:   str = '!unknown'
DEFAULT_PROJECT:  str = '!unknown'
DEFAULT_TOOL:     str = '!unknown'
DEFAULT_REGION:   str = 'World'
DEFAULT_COMMENT2: str = ''

EXCLUDE_COMMENT:    bool = False
NSP_CDATE_AS_DDATE: bool = False
NUM_THREADS:        int  = MAX_CPU_THREAD_COUNT

HACTOOLNET_VERSION_REGEX           = re.compile(r'^hactoolnet\s+v?(.+?)$', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_VERIFICATION_FAIL_REGEX = re.compile(r'\(FAIL\)', flags=(re.MULTILINE | re.IGNORECASE))
HACTOOLNET_JSON_OUTPUT_REGEX       = re.compile(r'^═+\s+JSON\s+OUTPUT\n═+$', flags=(re.MULTILINE | re.IGNORECASE))

NCA_DISTRIBUTION_TYPE: str = 'download'

NCA_CRYPTO_TYPE_STANDARD: str = 'standard'
NCA_CRYPTO_TYPE_TITLEKEY: str = 'titlekey'

DOM_LANGUAGES: dict[str, str] = {
    'AmericanEnglish':      'En-US',
    'BritishEnglish':       'En-GB',
    'Japanese':             'Ja',
    'French':               'Fr-FR',
    'German':               'De',
    'LatinAmericanSpanish': 'Es-XL',
    'Spanish':              'Es-ES',
    'Italian':              'It',
    'Dutch':                'Nl',
    'CanadianFrench':       'Fr-CA',
    'Portuguese':           'Pt-PT',
    'Russian':              'Ru',
    'Korean':               'Ko',
    'TraditionalChinese':   'Zh-Hant',
    'SimplifiedChinese':    'Zh-Hans',
    'BrazilianPortuguese':  'Pt-BR',
    'Polish':               'Pl',
    'Thai':                 'Th'
}

XML_HEADER: str = '<?xml version="1.0" encoding="utf-8"?>\n'
XML_HEADER     += '<!DOCTYPE datafile PUBLIC "http://www.logiqx.com/Dats/datafile.dtd" "-//Logiqx//DTD ROM Management Datafile//EN">\n'
XML_HEADER     += '<datafile>\n'
XML_HEADER     += '  <header>\n'
XML_HEADER     += '  </header>\n'

XML_FOOTER: str = '</datafile>\n'

XML_ENTRY_LIMIT: int = 30

GIT_BRANCH: str = ''
GIT_COMMIT: str = ''
GIT_REV:    str = ''

HACTOOLNET_VERSION: str = ''

BOGUS_TITLEKEYS_PATH: str = ''

HASH_BLOCK_SIZE: int = 0x800000 # 8 MiB

def eprint(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, flush=True, **kwargs)

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

def utilsCapitalizeString(input: str, old_sep: str = '_', new_sep: str = '') -> str:
    elem = [s.capitalize() for s in input.split(old_sep)]
    return new_sep.join(elem)

def utilsIsAsciiString(s: str) -> bool:
    try:
        s.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False

def utilsSplitListIntoNChunks(lst: list, n: int) -> Generator:
    for i in range(0, n):
        yield lst[i::n]

def utilsSplitListIntoFixedSizeChunks(lst: list, n: int) -> Generator:
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

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

    proc = subprocess.run([HACTOOLNET_PATH, '--version'], capture_output=True, encoding='utf-8')
    if proc.stdout:
        version = re.search(HACTOOLNET_VERSION_REGEX, proc.stdout)
        HACTOOLNET_VERSION = (version.group(1) if version else '')

    if not HACTOOLNET_VERSION:
        raise ValueError('Failed to get hactoolnet version!')

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
        fd = io.BytesIO(data)
        checksums = cls(fd)
        fd.close()
        return checksums

    @classmethod
    def from_string(cls, data: str, encoding: str = 'utf-8') -> Checksums:
        return cls.from_bytes(data.encode(encoding))

    @classmethod
    def from_checksums_dict(cls, checksums: dict[str, str]) -> Checksums:
        if (checksums is None) or (not isinstance(checksums, dict)) or ('Crc32' not in checksums) or ('Md5' not in checksums) or ('Sha1' not in checksums) or ('Sha256' not in checksums):
            raise ValueError('Invalid input checksums JSON.')

        crc32: str = checksums['Crc32'].lower()
        md5: str = checksums['Md5'].lower()
        sha1: str = checksums['Sha1'].lower()
        sha256: str = checksums['Sha256'].lower()

        crc32_valid = re.fullmatch(r'[0-9a-f]{8}', crc32)
        md5_valid = re.fullmatch(r'[0-9a-f]{32}', md5)
        sha1_valid = re.fullmatch(r'[0-9a-f]{40}', sha1)
        sha256_valid = re.fullmatch(r'[0-9a-f]{64}', sha256)

        if (crc32_valid is None) or (md5_valid is None) or (sha1_valid is None) or (sha256_valid is None):
            raise ValueError('Invalid input checksum(s).')

        # Hacky, but gets the job done.
        checksums = cls.from_bytes(bytes([0]))

        checksums.crc32 = crc32
        checksums.md5 = md5
        checksums.sha1 = sha1
        checksums.sha256 = sha256

        return checksums

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

@total_ordering
class NcmContentMetaType(IntEnum):
    INVALID = 0x00,
    SYSTEM_PROGRAM = 0x01,
    SYSTEM_DATA = 0x02,
    SYSTEM_UPDATE = 0x03,
    BOOT_IMAGE_PACKAGE = 0x04,
    BOOT_IMAGE_PACKAGE_SAFE = 0x05,
    APPLICATION = 0x80,
    PATCH = 0x81,
    ADD_ON_CONTENT = 0x82,
    DELTA = 0x83,
    DATA_PATCH = 0x84

    def __str__(self):
        return f'{self.__class__.__name__}.{self.name}'

    def __lt__(self, other: NcmContentMetaType) -> bool:
        if self.__class__ is other.__class__:
            return (self.value < other.value)
        return NotImplemented

    @property
    def normalized_name(self) -> str:
        return self._normalize_name(self.name)

    @classmethod
    def _normalize_name(self, name: str) -> str:
        return utilsCapitalizeString(name)

    @classmethod
    def _missing_(cls, value: str | int) -> NcmContentMetaType | None:
        if isinstance(value, str):
            for name in dir(cls):
                if (name == value) or (cls._normalize_name(name) == value):
                    return cls[name]
        elif isinstance(value, int):
            if ((value >= cls.INVALID.value) and (value <= cls.BOOT_IMAGE_PACKAGE_SAFE.value)) or ((value >= cls.APPLICATION.value) and (value <= cls.DATA_PATCH.value)):
                return cls[value]

        return None

@total_ordering
class NcmContentType(IntEnum):
    META              = 0,
    PROGRAM           = 1,
    DATA              = 2,
    CONTROL           = 3,
    HTML_DOCUMENT     = 4,
    LEGAL_INFORMATION = 5,
    DELTA_FRAGMENT    = 6

    def __str__(self):
        return f'{self.__class__.__name__}.{self.name}'

    def __lt__(self, other: NcmContentType) -> bool:
        if self.__class__ is other.__class__:
            return (self.value < other.value)
        return NotImplemented

    @property
    def normalized_name(self) -> str:
        return self._normalize_name(self.name)

    @classmethod
    def _normalize_name(self, name: str) -> str:
        return utilsCapitalizeString(name)

    @classmethod
    def _missing_(cls, value: str | int) -> NcmContentType | None:
        if isinstance(value, str):
            for name in dir(cls):
                if (name == value) or (cls._normalize_name(name) == value):
                    return cls[name]
        elif isinstance(value, int):
            if (value >= cls.META.value) and (value <= cls.DELTA_FRAGMENT.value):
                return cls[value]

        return None

@total_ordering
class NacpLanguage(IntEnum):
    AMERICAN_ENGLISH       = 0,
    BRITISH_ENGLISH        = 1,
    JAPANESE               = 2,
    FRENCH                 = 3,
    GERMAN                 = 4,
    LATIN_AMERICAN_SPANISH = 5,
    SPANISH                = 6,
    ITALIAN                = 7,
    DUTCH                  = 8,
    CANADIAN_FRENCH        = 9,
    PORTUGUESE             = 10,
    RUSSIAN                = 11,
    KOREAN                 = 12,
    TRADITIONAL_CHINESE    = 13,
    SIMPLIFIED_CHINESE     = 14,
    BRAZILIAN_PORTUGUESE   = 15,
    POLISH                 = 16,
    THAI                   = 17,
    COUNT                  = 18

    def __str__(self):
        return f'{self.__class__.__name__}.{self.name}'

    def __lt__(self, other: NacpLanguage) -> bool:
        if self.__class__ is other.__class__:
            return (self.value < other.value)
        return NotImplemented

    @property
    def normalized_name(self) -> str:
        return self._normalize_name(self.name)

    @classmethod
    def _normalize_name(self, name: str) -> str:
        return utilsCapitalizeString(name)

    @classmethod
    def _missing_(cls, value: str | int) -> NacpLanguage | None:
        if isinstance(value, str):
            for name in dir(cls):
                if (name == value) or (cls._normalize_name(name) == value):
                    return cls[name]
        elif isinstance(value, int):
            if (value >= cls.AMERICAN_ENGLISH.value) and (value < cls.COUNT.value):
                return cls[value]

        return None

@dataclass(init=False)
class NacpLanguageEntry:
    name: str = ''
    publisher: str = ''
    lang: NacpLanguage | None = None

    def __init__(self, name: str, publisher: str, lang: int | str) -> None:
        self.name = name.strip()
        self.publisher = publisher.strip()
        self.lang = NacpLanguage(lang)

        if (not self.name) or (self.lang is None):
            raise ValueError('Invalid title name.')

class NcaInfo:
    class Exception(Exception):
        def __init__(self, msg: str) -> None:
            super().__init__(msg)

    @property
    def size(self) -> int:
        return self._size

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def dist_type(self) -> str:
        return self._dist_type

    @property
    def cnt_type(self) -> NcmContentType:
        return self._cnt_type

    @property
    def id_offset(self) -> int:
        return self._id_offset

    @property
    def crypto_type(self) -> str:
        return self._crypto_type

    @property
    def checksums(self) -> Checksums:
        return self._checksums

    @property
    def cnt_id(self) -> str:
        return self._filename.rsplit('.', 1)[0]

    def __init__(self, nca_info: JSON, thrd_id: int) -> None:
        self._thrd_id = thrd_id

        self._checksums = Checksums.from_checksums_dict(nca_info['checksums'])

        self._cnt_type = NcmContentType(nca_info['content_type'])

        # Content IDs are just the first half of the NCA's SHA-256 checksum.
        self._filename = f'{self._checksums.sha256[:32]}{".cnmt" if self._cnt_type == NcmContentType.META else ""}.nca'

        self._dist_type: str = nca_info['distribution_type'].lower()
        self._size: int = nca_info['size']
        self._id_offset: int = nca_info['id_offset']
        self._crypto_type: str = nca_info['encryption_type'].split(' ', 1)[0].lower()

        print(f'(Thread {self._thrd_id}) Adding {self._cnt_type.normalized_name} NCA #{self._id_offset} "{self._filename}".', flush=True)

        src_nca_filename = self._filename
        if self._filename != src_nca_filename:
            raise self.Exception(f'(Thread {self._thrd_id}) Error: content ID / hash / filename mismatch (got "{src_nca_filename}", expected "{self._filename}").')

        if self._dist_type != NCA_DISTRIBUTION_TYPE:
            raise self.Exception(f'(Thread {self._thrd_id}) Error: invalid distribution type (got "{self._dist_type}", expected "{NCA_DISTRIBUTION_TYPE}").')

        if (self._crypto_type != NCA_CRYPTO_TYPE_STANDARD) and (self._crypto_type != NCA_CRYPTO_TYPE_TITLEKEY):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: invalid encryption type (got "{self._crypto_type}").')

@dataclass(init=False)
class TitleKeyInfo:
    filename: str = ''
    rights_id: str = ''
    value: str = ''
    raw_value: bytes = b''
    size: int = 16
    checksums: Checksums | None = None

    def __init__(self, titlekey: str, rights_id: str, is_decrypted: bool) -> None:
        # Populate properties.
        self.filename = f'{rights_id}.{"dec" if is_decrypted else "enc"}titlekey.bin'
        self.rights_id = rights_id
        self.value = titlekey.lower()
        self.raw_value = bytes.fromhex(self.value)

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
    def size(self) -> int:
        return self._tik_size

    @property
    def checksums(self) -> Checksums:
        return self._tik_checksums

    @property
    def enc_titlekey(self) -> TitleKeyInfo:
        return self._enc_titlekey

    @property
    def dec_titlekey(self) -> TitleKeyInfo:
        return self._dec_titlekey

    def __init__(self, ticket_info: JSON, titlekey_info: JSON, thrd_id: int) -> None:
        self._thrd_id = thrd_id

        self._rights_id: str = ticket_info['rights_id'].lower()

        if re.fullmatch(r'[0-9a-f]{32}', self._rights_id) is None:
            raise self.Exception(f'(Thread {self._thrd_id}) Invalid input rights ID.')

        self._tik_filename = f'{self._rights_id}.tik'
        self._tik_size: int = ticket_info['size']

        self._tik_checksums = Checksums.from_checksums_dict(ticket_info['checksums'])

        self._enc_titlekey = TitleKeyInfo(titlekey_info['encrypted']['value'], self._rights_id, True)
        self._dec_titlekey = TitleKeyInfo(titlekey_info['decrypted']['value'], self._rights_id, False)

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
    def type(self) -> NcmContentMetaType:
        return self._title_type

    @property
    def rights_id(self) -> str:
        return self._rights_id

    @property
    def tik_info(self) -> TikInfo:
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

    def __init__(self, json_report: JSON, thrd_id: int) -> None:
        # Populate class variables.
        self._populate_vars(json_report, thrd_id)

        # Get language entries.
        self._get_language_entries(json_report['title_metadata'])

        # Build NCA info list.
        self._build_content_list(json_report['ncas'])

    def _populate_vars(self, json_report: JSON, thrd_id: int) -> None:
        self._thrd_id = thrd_id

        title_metadata: JSON = json_report['title_metadata']

        self._title_id: str = title_metadata['title_id'].lower()
        self._title_version = int(title_metadata['version'])
        self._title_type = NcmContentMetaType(title_metadata['content_meta_type'])

        # Make sure we're dealing with a supported title type.
        if (self._title_type < NcmContentMetaType.APPLICATION) or (self._title_type > NcmContentMetaType.DATA_PATCH) or (self._title_type == NcmContentMetaType.DELTA):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: invalid content meta type value (0x{self._title_type.value:02X}). Skipping current title.')

        # Titlekey crypto related fields.
        try:
            self._tik_info = TikInfo(json_report['ticket'], json_report['titlekey'], thrd_id)
            self._rights_id = self._tik_info.rights_id
        except Exception as e:
            # Re-raise the exception as a TitleInfo.Exception.
            raise self.Exception(str(e))

        # Retrieved from the NACP in the Control NCA. Placed here for convenience.
        self._lang_entries: list[NacpLanguageEntry] = []
        self._supported_dom_languages: list[str] = []
        self._display_version: str = (title_metadata['display_version'] if title_metadata['display_version'] else '')
        self._is_demo: bool = (title_metadata['nacp_attributes']['demo'] if title_metadata['nacp_attributes'] else False)

        self._contents: list[NcaInfo] = []

    def _get_language_entries(self, title_metadata: JSON) -> None:
        # Return immediately if we're dealing with a DLC / DLC Update.
        if (self._title_type == NcmContentMetaType.ADD_ON_CONTENT) or (self._title_type == NcmContentMetaType.DATA_PATCH):
            return

        # Retrieve NACP language entry data.
        localized_titles = title_metadata['localized_titles']
        localized_publishers = title_metadata['localized_publishers']

        for lang in title_metadata['languages']:
            normalized_lang = utilsCapitalizeString(lang, ' ')

            try:
                # Build a NacpLanguageEntry object using this Title entry.
                # Don't proceed any further if object initialization fails.
                nacp_lang_entry = NacpLanguageEntry(localized_titles[lang], localized_publishers[lang], normalized_lang)
            except Exception:
                continue

            # Update language entry dictionary.
            self._lang_entries.append(nacp_lang_entry)

            # Update supported DoM languages list.
            dom_lang = DOM_LANGUAGES.get(normalized_lang, '')
            self._supported_dom_languages.append(dom_lang)

        if (len(self._lang_entries) == 0) or (len(self._supported_dom_languages) == 0):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: failed to retrieve language entries.')

    def _build_content_list(self, ncas: JSON) -> None:
        meta_nca_info: NcaInfo | None = None

        # Iterate over all content records.
        for nca_info_json in ncas:
            # Instantiate NcaInfo object.
            try:
                nca_info = NcaInfo(nca_info_json, self._thrd_id)
            except Exception as e:
                # Re-raise the exception as a TitleInfo.Exception.
                raise self.Exception(str(e))

            # Skip current content if it's a Meta NCA.
            if nca_info.cnt_type == NcmContentType.META:
                meta_nca_info = nca_info
                continue

            # Update contents list.
            self._contents.append(nca_info)

        if (len(self._contents) == 0) or (meta_nca_info is None):
            raise self.Exception(f'(Thread {self._thrd_id}) Error: unable to build content list (content data is empty).')

        # Append Meta NCA to the list.
        self._contents.append(meta_nca_info)

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
    def creation_date(self) -> str:
        return self._creation_date

    @property
    def is_standard_nsp(self) -> bool:
        return self._is_standard_nsp

    @property
    def checksums(self) -> Checksums | None:
        return self._checksums

    @property
    def titles(self) -> list[TitleInfo]:
        return self._titles

    def __init__(self, file_entry: FileListEntry, thrd_id: int) -> None:
        # Populate class variables.
        self._populate_vars(file_entry, thrd_id)

        # Get creation date.
        self._get_creation_date()

        # Handle filenames with non-ASCII codepoints.
        self._handle_nonascii_filename()

        # Convert NSZ back to NSP, if needed.
        self._convert_nsz()

        # Run hactoolnet JSON report.
        json_report = self._get_hactoolnet_json_report()

        # Parse hactoolnet JSON report.
        self._parse_hactoolnet_json_report(json_report)

        # Perform cleanup.
        self._cleanup()

    def _populate_vars(self, file_entry: FileListEntry, thrd_id: int) -> None:
        self._orig_nsp_path = file_entry[0]
        self._nsp_path = file_entry[0]
        self._nsp_size = file_entry[1]
        self._nsp_filename = f'{os.path.splitext(os.path.basename(self._nsp_path))[0]}.nsp'

        self._is_nsz = self._nsp_path.lower().endswith('.nsz')
        self._nsz_converted = False
        self._tmp_path = ''

        self._creation_date = ''

        self._is_standard_nsp = False

        self._thrd_id = thrd_id

        self._checksums: Checksums | None = None

        self._titles: list[TitleInfo] = []

        self._cleanup_called = False

    def _get_creation_date(self) -> None:
        ctime = os.path.getctime(self._nsp_path)
        cdate = datetime.date.fromtimestamp(ctime)
        self._creation_date = cdate.isoformat()

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
        self._nsz_converted = True

    def _get_hactoolnet_json_report(self) -> JSON:
        # Run hactoolnet.
        proc = utilsRunHactoolnet('nsp', ['-y', '-v', '--nointro', '--json', self._nsp_path])

        if (not proc.stdout) or (proc.returncode != 0):
            hactoolnet_stderr = proc.stderr.strip()
            raise self.Exception(f'(Thread {self._thrd_id}) Failed to retrieve NSP info{f" ({hactoolnet_stderr})" if hactoolnet_stderr else ""}.')

        # Validate hactoolnet output.
        if len(re.findall(HACTOOLNET_VERIFICATION_FAIL_REGEX, proc.stdout)) > 0:
            raise self.Exception(f'(Thread {self._thrd_id}) NSP NCA signature/hash verification failed.')

        # Parse JSON report from stdout.
        json_output_tag = re.search(HACTOOLNET_JSON_OUTPUT_REGEX, proc.stdout)

        if (not json_output_tag):
            raise self.Exception(f'(Thread {self._thrd_id}) Failed to parse hactoolnet output.')

        json_report_str = proc.stdout[json_output_tag.end():].strip()

        return json.loads(json_report_str)['base_nsp']

    def _parse_hactoolnet_json_report(self, json_report: JSON) -> None:
        # Get standard NSP flag.
        standard_nsp_issues = json_report['standard_nsp_issues']
        self._is_standard_nsp = (json_report['standard_nsp_compliant'] and len(standard_nsp_issues) == 0)

        if not self._is_standard_nsp:
            for issue in standard_nsp_issues:
                print(f'(Thread {self._thrd_id}) Standard NSP issue: {issue}.')

        # Get NSP checksums.
        self._checksums = Checksums.from_checksums_dict(json_report['nsp_checksums'])

        # Build title list.
        self._build_title_list(json_report)

    def _build_title_list(self, json_report: JSON) -> None:
        """
        # Collect information from all available Meta NCAs.
        meta_nca_infos = self._get_meta_nca_infos()
        if not meta_nca_infos:
            raise self.Exception(f'(Thread {self._thrd_id}) Error: failed to locate any Meta NCAs within the extracted NSP data.')

        # Update Meta NCA count.
        self._meta_nca_count = len(meta_nca_infos)

        # Loop through all Meta NCAs.
        for meta_nca in meta_nca_infos:
            try:
                # Initialize TitleInfo object using the current Meta NCA.
                title_info = TitleInfo(meta_nca, self._ext_nsp_path, self._thrd_id)
            except TitleInfo.Exception as e:
                eprint(str(e))
                continue

            # Update title list.
            self._titles.append(title_info)
        """

        # Initialize TitleInfo object.
        # TODO: support multi-title NSPs.
        try:
            title_info = TitleInfo(json_report, self._thrd_id)
        except Exception as e:
            # Re-raise the exception as a NspInfo.Exception.
            raise self.Exception(str(e))

        # Update title list.
        self._titles.append(title_info)

    def _cleanup(self) -> None:
        if self._cleanup_called:
            return

        # Delete NSP if the original file is a NSZ.
        if self._is_nsz and self._nsz_converted:
            os.remove(self._nsp_path)

        # Rename NSP, if needed.
        if self._tmp_path:
            os.rename(self._tmp_path, self._orig_nsp_path)

        # Update flag.
        self._cleanup_called = True

    def __exit__(self) -> None:
        #print('nsp: __exit__ called', flush=True)
        self._cleanup()

    def __del__(self) -> None:
        #print('nsp: __del__ called', flush=True)
        self._cleanup()

class XmlDataset:
    XmlEntry: TypeAlias = tuple[str, str] # Archive name, XML entry string
    XmlEntryList: TypeAlias = list[XmlEntry]

    @total_ordering
    class Type(IntEnum):
        APPLICATION = 0,
        UPDATE      = 1,
        DLC         = 2,
        DLC_UPDATE  = 3,
        COUNT       = 4

        def __str__(self):
            return f'{self.__class__.__name__}.{self.name}'

        def __lt__(self, other: XmlDataset.Type) -> bool:
            if self.__class__ is other.__class__:
                return (self.value < other.value)
            return NotImplemented

        @property
        def normalized_name(self) -> str:
            return utilsCapitalizeString(self.name, ' ').replace('Dlc', 'DLC')

        @classmethod
        def _missing_(cls, value: str) -> XmlDataset.Type:
            if isinstance(value, str):
                value_up = value.upper()
                if value_up in dir(cls):
                    return cls[value_up]

            raise ValueError(f'{value:r} is not a valid {cls.__name__}')

    @property
    def type(self) -> XmlDataset.Type:
        return self._type

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def file_count(self) -> int:
        return self._xml_file_count

    @property
    def is_finalized(self) -> bool:
        return self._is_finalized

    def __init__(self, type: XmlDataset.Type) -> None:
        self._type = type
        self._comment2 = ('' if EXCLUDE_COMMENT else DEFAULT_COMMENT2)
        self._entries: XmlDataset.XmlEntryList = []
        self._xml_file_count = 0
        self._is_finalized = False

    def add_entry(self, nsp_info: NspInfo, title_info: TitleInfo) -> None:
        if self._is_finalized or (not nsp_info) or (not nsp_info.checksums) or (not title_info):
            return

        # Make sure we're dealing with a valid title type.
        if (self._type == XmlDataset.Type.APPLICATION and title_info.type != NcmContentMetaType.APPLICATION) or (self._type == XmlDataset.Type.UPDATE and title_info.type != NcmContentMetaType.PATCH) or (self._type == XmlDataset.Type.DLC and title_info.type != NcmContentMetaType.ADD_ON_CONTENT) or (self._type == XmlDataset.Type.DLC_UPDATE and title_info.type != NcmContentMetaType.DATA_PATCH):
            raise ValueError(f'Error: invalid content meta type value for {self._type.normalized_name} dataset (0x{title_info.type.value:02X}).')

        # Generate archive name string.
        archive_name = self._get_archive_name(nsp_info, title_info)

        # Generate languages string.
        languages = self._get_languages(title_info)

        # Generate version strings.
        (version1, version2) = self._get_versions(title_info)

        # Generate dev status string.
        dev_status = self._get_dev_status(title_info)

        # Generate source format string.
        src_format = ('StandardNSP' if nsp_info.is_standard_nsp else 'NSP')

        # Generate dump date properties.
        ddate = (nsp_info.creation_date if NSP_CDATE_AS_DDATE else DEFAULT_DDATE)
        ddate_provided = (NSP_CDATE_AS_DDATE or DDATE_PROVIDED)

        # Generate XML entry.
        title_str  = '  <game name="">\n'
        title_str += f'    <archive name="{html_escape(archive_name)}" name_alt="" region="{DEFAULT_REGION}" languages="{languages}" langchecked="0" version1="{version1}" version2="{version2}" devstatus="{dev_status}" additional="eShop" special1="" special2="" gameid1="{title_info.id}" />\n'

        if title_info.lang_entries or title_info.display_version:
            title_str += '    <media>\n'

            for lang_entry in title_info.lang_entries:
                cap_lang_name = lang_entry.lang.normalized_name

                if lang_entry.name:
                    title_str += f'      <field name="Original Name (NACP, {cap_lang_name})" value="{html_escape(lang_entry.name)}" />\n'

                if lang_entry.publisher:
                    title_str += f'      <field name="Publisher (NACP, {cap_lang_name})" value="{html_escape(lang_entry.publisher)}" />\n'

            if title_info.display_version:
                title_str += f'      <field name="Display Version (NACP)" value="{html_escape(title_info.display_version)}" />\n'

            title_str += '    </media>\n'

        title_str += '    <source>\n'
        title_str += f'      <details section="{DEFAULT_SECTION}" rominfo="" originalformat="{src_format}" d_date="{ddate}" d_date_info="{int(ddate_provided)}" r_date="{DEFAULT_RDATE}" r_date_info="{int(RDATE_PROVIDED)}" dumper="{DEFAULT_DUMPER}" project="{DEFAULT_PROJECT}" tool="{DEFAULT_TOOL}" region="{DEFAULT_REGION}" origin="" comment1="" comment2="{self._comment2}" link1="" link2="" media_title="" />\n'
        title_str += f'      <serials media_serial1="" media_serial2="" pcb_serial="" romchip_serial1="" romchip_serial2="" lockout_serial="" savechip_serial="" chip_serial="" box_serial="" mediastamp="" box_barcode="" digital_serial1="{title_info.id}" digital_serial2="" />\n'

        if not EXCLUDE_NSP:
            # Add NSP information.
            title_str += self._generate_xml_file_elem('', 'nsp', src_format, '', title_info.version, nsp_info.size, nsp_info.checksums, '')

        for cnt in title_info.contents:
            if cnt.checksums is None:
                continue

            # Add current NCA information.
            if (cnt.crypto_type == NCA_CRYPTO_TYPE_TITLEKEY) and title_info.tik_info and title_info.tik_info.enc_titlekey and title_info.tik_info.enc_titlekey.checksums:
                nca_note = f'[Passed verification with titlekey with SHA256 {title_info.tik_info.enc_titlekey.checksums.sha256} using hactoolnet v{HACTOOLNET_VERSION}]'
            else:
                nca_note = f'[Passed verification, no titlekey required, using hactoolnet v{HACTOOLNET_VERSION}]'

            title_str += self._generate_xml_file_elem(cnt.filename, '', 'CDN', nca_note, title_info.version, cnt.size, cnt.checksums, cnt.cnt_type.normalized_name)

        if (not EXCLUDE_TIK) and title_info.tik_info and title_info.tik_info.checksums:
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

        # Append generated XML entry.
        self._entries.append((archive_name, title_str))

    def finalize(self) -> None:
        if self._is_finalized:
            return

        # Short-circuit: don't do anything if we have no entries to write.
        if not self._entries:
            self._is_finalized = True
            return

        # Sort entries by archive name.
        if len(self._entries) > 1:
            self._entries.sort(key=lambda x: x[0])

        # Get XML entries chunks.
        xml_entries_chunks = utilsSplitListIntoFixedSizeChunks(self._entries, XML_ENTRY_LIMIT)

        # Loop through our XML entries chunks.
        for i, xml_entries in enumerate(xml_entries_chunks):
            # Generate current file path.
            xml_path = os.path.join(OUTPUT_PATH, f'nswd_{self._type.name.lower()}')
            xml_path += (f'_idx{self._xml_file_count}.xml' if len(self._entries) > XML_ENTRY_LIMIT else '.xml')

            # Open output XML file.
            xml_fd = open(xml_path, 'w', encoding='utf-8-sig')

            # Write XML file header.
            xml_fd.write(XML_HEADER)

            # Write XML entries.
            for _, xml_entry in enumerate(xml_entries):
                #print(f'Writing entry "{xml_entry[0]}" to "{xml_path}"...', flush=True)
                xml_fd.write(xml_entry[1])

            # Write XML footer.
            xml_fd.write(XML_FOOTER)

            # Close XML file.
            xml_fd.close()

            # Increment file count.
            self._xml_file_count += 1

        # Update flag.
        self._is_finalized = True

    def _get_archive_name(self, nsp_info: NspInfo, title_info: TitleInfo) -> str:
        if title_info.lang_entries:
            # Default to the first NACP language entry we found.
            archive_name = self._normalize_archive_name(title_info.lang_entries[0].name)
        else:
            # Use a portion of the NSP filename, if possible (gross, I know, but it's either this or using an external database).
            extracted_name = re.split(r'\[[a-fA-F0-9]{16}\]', nsp_info.filename, maxsplit=1)[0]
            if extracted_name != nsp_info.filename:
                # Normalize the extracted filename.
                archive_name = self._normalize_archive_name(extracted_name)
            else:
                # Fallback to just using the title ID.
                archive_name = title_info.id

        return archive_name

    def _normalize_archive_name(self, name: str) -> str:
        articles = {'a', 'an', 'the'}
        link_words = {'and', 'or', 'but', 'nor', 'so', 'yet', 'for', 'at', 'by', 'in', 'on', 'to', 'of', 'up', 'with', 'as', 'per'}

        # Remove illegal filesystem characters.
        out = re.sub(r'[\\/*?"<>|`]', '', name)

        # Replace colons, em dashes and en dashes with regular dashes.
        out = re.sub(r'\s*[:–—]\s*', ' - ', out)

        # Replace consecutive whitespaces with a single one.
        out = ' '.join(out.split()).strip()

        # Handle string capitalization.
        words = out.split()

        formatted_words = [
            word.lower() if (word.lower() in articles or word.lower() in link_words) else
            word if (word.isupper() or word.isalpha()) else word.capitalize()
            for word in words
        ]

        if formatted_words[0].lower() in articles:
            article = formatted_words.pop(0).capitalize()
            try:
                sep_index = formatted_words.index('-')
                formatted_words[sep_index - 1] += ','
                formatted_words.insert(sep_index, article)
            except ValueError:
                formatted_words[-1] += ','
                formatted_words.append(article)

        return ' '.join(formatted_words)

    def _get_languages(self, title_info: TitleInfo) -> str:
        return ('En' if not title_info.supported_dom_languages else ','.join(title_info.supported_dom_languages))

    def _get_versions(self, title_info: TitleInfo) -> tuple[str, str]:
        version1 = (f'v{title_info.version}' if (title_info.version > 0) else '')
        version2 = (html_escape(f'v{title_info.display_version}') if (title_info.display_version and title_info.type != NcmContentMetaType.APPLICATION) else '')
        return (version1, version2)

    def _get_dev_status(self, title_info: TitleInfo) -> str:
        dev_status = (['Demo'] if title_info.is_demo else [])

        match title_info.type:
            case NcmContentMetaType.PATCH:
                dev_status.append('Update')
            case NcmContentMetaType.ADD_ON_CONTENT:
                dev_status.append('DLC')
            case NcmContentMetaType.DATA_PATCH:
                dev_status.append('DLC Update')
            case _:
                pass

        return (', '.join(dev_status) if dev_status else '')

    def _generate_xml_file_elem(self, forcename: str, extension: str, format: str, note: str, version: int, size: int, checksums: Checksums, filter: str) -> str:
        extension = (f' extension="{extension}" ' if extension else ' ')
        note = (f' note="{note}" ' if note else ' ')
        filter = (f' filter="{filter}" ' if filter else ' ')

        return f'      <file forcename="{forcename}"{extension}format="{format}"{note}version="{version}" size="{size}" crc32="{checksums.crc32}" md5="{checksums.md5}" sha1="{checksums.sha1}" sha256="{checksums.sha256}"{filter}/>\n'

def utilsGenerateXmlDataset(nsp_list: list[NspInfo]) -> None:
    xml_obj: list[XmlDataset] = []

    type_dict: dict[int, int] = {
        NcmContentMetaType.APPLICATION.value: XmlDataset.Type.APPLICATION.value,
        NcmContentMetaType.PATCH.value: XmlDataset.Type.UPDATE.value,
        NcmContentMetaType.ADD_ON_CONTENT.value: XmlDataset.Type.DLC.value,
        NcmContentMetaType.DATA_PATCH.value: XmlDataset.Type.DLC_UPDATE.value
    }

    # Initialize our XmlDataset objects.
    for i in range(XmlDataset.Type.COUNT.value):
        cur_xml_obj = XmlDataset(XmlDataset.Type(i))
        xml_obj.append(cur_xml_obj)

    # Process NSP info list.
    for nsp_info in nsp_list:
        # Process titles availables in current NSP.
        for title_info in nsp_info.titles:
            # Get XML object index based on the current title type.
            idx = type_dict.get(title_info.type.value, None)
            if idx is None:
                eprint(f'Error: invalid content meta type value (0x{title_info.type.value:02X}).')
                continue

            # Add entry to XML object.
            xml_obj[idx].add_entry(nsp_info, title_info)

    print(flush=True)

    # Finalize all XML objects.
    for cur_xml_obj in xml_obj:
        cur_xml_obj.finalize()

        if cur_xml_obj.entry_count > 0:
            print(f'Successfully wrote {cur_xml_obj.entry_count} {cur_xml_obj.type.normalized_name} {"entries" if cur_xml_obj.entry_count > 1 else "entry"} to {cur_xml_obj.file_count} {"files" if cur_xml_obj.file_count > 1 else "file"}.', flush=True)

def utilsProcessNspList(file_list_chunks: list[FileList], results: list[list[NspInfo]]) -> None:
    thrd_id = int(threading.current_thread().name)

    file_list = file_list_chunks[thrd_id]
    thrd_res: list[NspInfo] = []

    # Process NSP files.
    for entry in file_list:
        print(f'(Thread {thrd_id}) Processing "{entry[0]}" (0x{entry[1]:X} bytes long)...', flush=True)

        try:
            nsp_info = NspInfo(entry, thrd_id)
        except NspInfo.Exception as e:
            eprint(str(e))
            continue

        # Update output list.
        thrd_res.append(nsp_info)

    # Update results entry.
    results[thrd_id] = thrd_res

def utilsGetNspFileList(path: str) -> FileList:
    file_list: FileList = []

    # Scan directory.
    for fileref in pathlib.Path(path).rglob('*'):
        cur_path = str(fileref)
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
        eprint('Error: input directory holds no NSP/NSZ files.')
        return

    # Create processing threads.
    file_list_chunks: list[FileList] = list(filter(None, list(utilsSplitListIntoNChunks(file_list, NUM_THREADS))))
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
        eprint('Error: failed to process any NSP files.')
        return

    # Generate output XML dataset.
    utilsGenerateXmlDataset(nsp_list)

def utilsValidateThreadCount(num_threads: str) -> int:
    val = int(num_threads)
    if (val <= 0) or (val > MAX_CPU_THREAD_COUNT):
        raise argparse.ArgumentTypeError(f'Invalid thread count provided. Value must be in the range [1, {MAX_CPU_THREAD_COUNT}].')
    return val

def main() -> int:
    global NSP_PATH, HACTOOLNET_PATH, KEYS_PATH, OUTPUT_PATH, EXCLUDE_NSP, EXCLUDE_TIK
    global DEFAULT_SECTION, DDATE_PROVIDED, DEFAULT_DDATE, RDATE_PROVIDED, DEFAULT_RDATE, DEFAULT_DUMPER, DEFAULT_PROJECT, DEFAULT_TOOL, DEFAULT_REGION
    global EXCLUDE_COMMENT, NSP_CDATE_AS_DDATE, NUM_THREADS

    # Get git commit information.
    utilsGetGitRepositoryInfo()

    # Reconfigure terminal output whenever possible.
    utilsReconfigureTerminalOutput()

    parser = argparse.ArgumentParser(description='Generate importable DAT-o-MATIC (DoM) XML datasets from Nintendo Submission Package (NSP) files.', epilog=f'A XML dataset will be generated per each detected title type (application/update/dlc/dlc update).\n\nIn order to avoid issues related to DoM\'s server limitations, output XMLs will only hold up to {XML_ENTRY_LIMIT} entries. Splitting will be carried out if needed.')

    parser.add_argument('--nspdir', type=str, metavar='DIR', default='', help=f'Path to directory with NSP files. Defaults to "{NSP_PATH}".')
    parser.add_argument('--hactoolnet', type=str, metavar='FILE', default='', help=f'Path to hactoolnet binary. Defaults to "{HACTOOLNET_PATH}".')
    parser.add_argument('--keys', type=str, metavar='FILE', default='', help=f'Path to Nintendo Switch keys file. Defaults to "{KEYS_PATH}".')
    parser.add_argument('--outdir', type=str, metavar='DIR', default='', help=f'Path to output directory. Defaults to "{OUTPUT_PATH}".')
    parser.add_argument('--exclude-nsp', action='store_true', default=EXCLUDE_NSP, help='Excludes NSP metadata from the output XML dataset. Disabled by default.')
    parser.add_argument('--exclude-tik', action='store_true', default=EXCLUDE_TIK, help='Excludes ticket metadata from the output XML dataset. Disabled by default.')

    parser.add_argument('--section', type=str, default=DEFAULT_SECTION, help=f'Section string used in the output XML dataset. Defaults to "{DEFAULT_SECTION}" if not provided.')
    parser.add_argument('--dump-date', type=datetime.date.fromisoformat, default=argparse.SUPPRESS, metavar='YYYY-MM-DD', help='Dump date used in the output XML dataset. Defaults to current date if not provided.')
    parser.add_argument('--release-date', type=datetime.date.fromisoformat, default=argparse.SUPPRESS, metavar='YYYY-MM-DD', help='Release date used in the output XML dataset. Optional.')
    parser.add_argument('--dumper', type=str, default=DEFAULT_DUMPER, help=f'Dumper string used in the output XML dataset. Defaults to "{DEFAULT_DUMPER}" if not provided.')
    parser.add_argument('--project', type=str, default=DEFAULT_PROJECT, help=f'Project string used in the output XML dataset. Defaults to "{DEFAULT_PROJECT}" if not provided.')
    parser.add_argument('--tool', type=str, default=DEFAULT_TOOL, help=f'Tool string used in the output XML dataset. Defaults to "{DEFAULT_TOOL}" if not provided.')
    parser.add_argument('--region', type=str, default=DEFAULT_REGION, help=f'Region string used in the output XML dataset. Defaults to "{DEFAULT_REGION}" if not provided.')

    parser.add_argument('--exclude-comment', action='store_true', default=EXCLUDE_COMMENT, help='Excludes information about this script from the comment2 field in XML entries. Disabled by default (comment2 fields hold information about this script).')
    parser.add_argument('--nsp-cdate-as-ddate', action='store_true', default=NSP_CDATE_AS_DDATE, help='Uses NSP file date information as the dump date. Disabled by default (current date is used for all files if no date is explicitly provided).')
    parser.add_argument('--num-threads', type=utilsValidateThreadCount, metavar='VALUE', default=NUM_THREADS, help=f'Sets the number of threads used to process input NSP/NSZ files. Defaults to {NUM_THREADS} if not provided. This value must not be exceeded.')

    print(f'{SCRIPT_NAME}.\nRevision: {GIT_REV}.\nMade by DarkMatterCore.\n', flush=True)

    # Parse arguments. Make sure to escape characters where needed.
    args = parser.parse_args()

    NSP_PATH = utilsGetPath(args.nspdir, os.path.join(INITIAL_DIR, NSP_PATH), False)
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
    NSP_CDATE_AS_DDATE = args.nsp_cdate_as_ddate
    NUM_THREADS = args.num_threads

    # Get hactoolnet version.
    utilsGetHactoolnetVersion()

    print(f'Using hactoolnet v{HACTOOLNET_VERSION}.\n', flush=True)

    # Check if nsz has been installed.
    if not shutil.which('nsz'):
        raise ValueError('Error: "nsz" package unavailable.')

    # Copy keys file (required by nsz since it offers no way to provide a keys file path).
    utilsCopyKeysFile()

    # Create bogus titlekeys file.
    utilsCreateBogusTitleKeysFile()

    # Do our thing.
    utilsProcessNspDirectory()

    # Delete bogus titlekeys file.
    utilsDeleteBogusTitleKeysFile()

    return 0

if __name__ == '__main__':
    ret: int = 1

    try:
        ret = main()
    except KeyboardInterrupt:
        time.sleep(0.2)
        eprint('\nScript interrupted.')
    except ValueError as e:
        eprint(str(e))
    except Exception:
        traceback.print_exc()

    try:
        sys.exit(ret)
    except SystemExit:
        os._exit(ret)
