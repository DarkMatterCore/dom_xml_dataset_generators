#!/usr/bin/env python3

"""
 * xml_dataset_generator_nsp.py
 *
 * Copyright (c) 2022, DarkMatterCore <pabloacurielz@gmail.com>.
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

from __future__ import print_function

import os
import sys
import re
import base64
import subprocess
import traceback
import struct
import shutil
import hashlib
import zlib
import random
import string
from cnmt import Cnmt
from tik import Tik
from nacp import Nacp
import copy

from argparse import ArgumentParser
from typing import List, Union, Tuple, Dict, Pattern, TYPE_CHECKING

SCRIPT_NAME: str = os.path.basename(sys.argv[0])

INITIAL_DIR: str = os.path.abspath(os.path.dirname(__file__))

NSP_PATH:     str = os.path.join('.', 'nsp')
HACTOOL_PATH: str = os.path.join('.', ('hactool.exe' if os.name == 'nt' else 'hactool'))
KEYS_PATH:    str = os.path.join('~', '.switch', 'prod.keys')
OUTPUT_PATH:  str = os.path.join('.', 'out')

HACTOOL_DISTRIBUTION_TYPE_REGEX  = re.compile(r"^Distribution type:\s+(.+)$", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_CONTENT_TYPE_REGEX       = re.compile(r"^Content Type:\s+(.+)$", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_ENCRYPTION_TYPE_REGEX    = re.compile(r"^Encryption Type:\s+(.+)$", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_RIGHTS_ID_REGEX          = re.compile(r"^Rights ID:\s+([0-9a-f]{32})$", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_DECRYPTED_TITLEKEY_REGEX = re.compile(r"^Titlekey \(Decrypted\) \(From CLI\)\s+([0-9a-f]{32})$", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_VERIFY_REGEX            = re.compile(r"\(FAIL\)", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_SAVING_REGEX            = re.compile(r"^Saving (.+) to", flags=(re.MULTILINE | re.IGNORECASE))

TICKET_SIZE: int = 0x2C0

NCA_DISTRIBUTION_TYPE: str = 'download'







DEFAULT_COMMENT2:  str = ''

GIT_BRANCH: str = ''
GIT_COMMIT: str = ''
GIT_REV:    str = ''

WINDOWS_LINE_BREAK: str = '\r\n'

HASH_BLOCK_SIZE: int = 0x800000 # 8 MiB

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def utilsGetPath(path_arg: str, fallback_path: str, is_file: bool, create: bool = False) -> str:
    path = os.path.abspath(os.path.expanduser(os.path.expandvars(path_arg if path_arg else fallback_path)))

    if not is_file and create: os.makedirs(path, exist_ok=True)

    if not os.path.exists(path) or (is_file and os.path.isdir(path)) or (not is_file and os.path.isfile(path)):
        raise Exception("Error: '%s' points to an invalid file/directory." % (path))

    return path

def utilsGetRandomString(length: int) -> str:
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def utilsCapitalizeString(input: str, sep: str = '') -> str:
    input = input.split('_')
    for i in range(len(input)): input[i] = input[i].capitalize()
    return sep.join(input)

def utilsRunGit(args: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(['git'] + args, capture_output=True, encoding='utf-8')

def utilsGetGitInfo() -> None:
    global DEFAULT_COMMENT2, GIT_BRANCH, GIT_COMMIT, GIT_REV

    # Get git branch.
    proc = utilsRunGit(['rev-parse', '--abbrev-ref', 'HEAD'])
    if not proc.stdout or proc.returncode != 0: raise Exception('Failed to run git!')
    GIT_BRANCH = proc.stdout.strip()

    # Get git commit.
    proc = utilsRunGit(['rev-parse', '--short', 'HEAD'])
    if not proc.stdout or proc.returncode != 0: raise Exception('Failed to run git!')
    GIT_COMMIT = proc.stdout.strip()

    # Generate git revision string.
    GIT_REV = GIT_BRANCH + '-' + GIT_COMMIT
    proc = utilsRunGit(['status', '--porcelain'])
    if proc.returncode != 0: raise Exception('Failed to run git!')
    proc = proc.stdout.strip()
    if proc: GIT_REV += '-dirty'

    # Update default comment2 string.
    comment2_str = DEFAULT_COMMENT2
    DEFAULT_COMMENT2 = '[%s revision %s used to generate XML files]' % (SCRIPT_NAME, GIT_REV)
    if comment2_str: DEFAULT_COMMENT2 += '%s%s' % (HTML_LINE_BREAK, comment2_str)

def utilsRunHactool(hactool: str, keys: str, type: str, args: List[str]) -> subprocess.CompletedProcess:
    hactool_args = [hactool, '-t', type, '-k', keys, '--disablekeywarns'] + args
    proc = subprocess.run(hactool_args, capture_output=True, encoding='utf-8')
    return proc

def utilsExtractNsp(nsp_path: str, hactool: str, keys: str, outdir: str) -> None:
    # Extract files from the provided NSP.
    proc = utilsRunHactool(hactool, keys, 'pfs0', ['--outdir=' + outdir, nsp_path])
    if (not proc.stdout) or (proc.returncode != 0) or (not os.path.exists(outdir)): raise Exception('Error: failed to extract NSP "%s".' % (os.path.basename(nsp_path)))

def utilsExtractCnmtNca(nca_path: str, hactool: str, keys: str, outdir: str) -> str:
    # Extract files from NCA FS section 0.
    proc = utilsRunHactool(hactool, keys, 'nca', ['--section0dir=' + outdir, nca_path])
    if (not proc.stdout) or (proc.returncode != 0) or (not os.path.exists(outdir)): raise Exception('Error: failed to extract PFS0 from NCA "%s".' % (os.path.basename(nca_path)))

    # Get extracted CNMT filename from hactool's output.
    cnmt_filename = re.search(HACTOOL_SAVING_REGEX, proc.stdout)
    if (not cnmt_filename): raise Exception('Error: failed to extract PFS0 from NCA "%s".' % (os.path.basename(nca_path)))

    cnmt_filename = cnmt_filename.group(1).strip()
    if not os.path.exists(os.path.join(outdir, cnmt_filename)): raise Exception('Error: failed to extract PFS0 from NCA "%s".' % (os.path.basename(nca_path)))

    return cnmt_filename

def utilsExtractNcaFsSection(nca_path: str, hactool: str, keys: str, outdir: str, idx: int) -> None:
    # Extract files from the selected NCA FS section.
    if (idx < 0) or (idx > 3): raise Exception('Error: invalid NCA FS section index for "%s" (%d).' % (os.path.basename(nca_path), idx))
    proc = utilsRunHactool(hactool, keys, 'nca', ['--section' + str(idx) + 'dir=' + outdir, nca_path])
    if (not proc.stdout) or (proc.returncode != 0) or (not os.path.exists(outdir)): raise Exception('Error: failed to extract section %d from NCA "%s".' % (idx, os.path.basename(nca_path)))

def utilsGetFileList(dir: str, extension: str, recursive: bool = False) -> List:
    file_list: List = []

    extension = extension.lower().strip().strip('.')

    # Scan directory.
    dir_scan = os.scandir(dir)

    # Get available files.
    for entry in dir_scan:
        # Skip directories and files that don't match our criteria.
        if (entry.is_dir() and (not recursive)) or (not entry.name.lower().endswith('.' + extension)): continue

        if entry.is_file():
            # Skip empty files.
            file_size = entry.stat().st_size
            if not file_size: continue

            # Update list.
            file_list.append([entry.path, file_size])
        else:
            file_list.extend(utilsGetFileList(entry.path, extension, True))

    return file_list

def utilsCalculateFileChecksums(file: str) -> Dict:
    crc32_hash = 0
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file, 'rb') as fd:
        while True:
            # Read file chunk.
            chunk = fd.read(HASH_BLOCK_SIZE)
            if not chunk: break

            # Update checksums.
            crc32_hash = zlib.crc32(chunk, crc32_hash)
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    checksums = {
        'crc': '{:08x}'.format(crc32_hash),
        'md5': md5_hash.hexdigest().lower(),
        'sha1': sha1_hash.hexdigest().lower(),
        'sha256': sha256_hash.hexdigest().lower()
    }

    return checksums

def utilsCalculateDataChecksums(data: bytes) -> Dict:
    crc32_hash = 0
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    # Calculate checksums.
    crc32_hash = zlib.crc32(data, crc32_hash)
    md5_hash.update(data)
    sha1_hash.update(data)
    sha256_hash.update(data)

    checksums = {
        'crc': '{:08x}'.format(crc32_hash),
        'md5': md5_hash.hexdigest().lower(),
        'sha1': sha1_hash.hexdigest().lower(),
        'sha256': sha256_hash.hexdigest().lower()
    }

    return checksums

def utilsGetNcaInfo(hactool: str, keys: str, nca_path: str, titlekey: str = '', expected_cnt_type: str = '') -> Dict:
    # Run hactool.
    args = []
    if titlekey: args.append('--titlekey=' + titlekey)
    args.extend([ '-y', nca_path ])

    proc = utilsRunHactool(hactool, keys, 'nca', args)
    if not proc.stdout or proc.returncode != 0:
        print('\t\t- Failed to retrieve NCA info for "%s".' % (os.path.basename(nca_path)))
        return {}

    # Parse hactool's output.
    dist_type = re.search(HACTOOL_DISTRIBUTION_TYPE_REGEX, proc.stdout)
    cnt_type = re.search(HACTOOL_CONTENT_TYPE_REGEX, proc.stdout)
    crypto_type = re.search(HACTOOL_ENCRYPTION_TYPE_REGEX, proc.stdout)
    rights_id = re.search(HACTOOL_RIGHTS_ID_REGEX, proc.stdout)
    dec_titlekey = re.search(HACTOOL_DECRYPTED_TITLEKEY_REGEX, proc.stdout)
    verify = (len(re.findall(HACTOOL_VERIFY_REGEX, proc.stdout)) == 0)

    if (not dist_type) or (not cnt_type) or (not crypto_type):
        print('\t\t- Failed to retrieve NCA info for "%s".' % (os.path.basename(nca_path)))
        return {}

    dist_type = dist_type.group(1).lower()
    cnt_type = cnt_type.group(1).lower()
    crypto_type = crypto_type.group(1).lower().split()[0]

    if (crypto_type == 'titlekey') and (not rights_id):
        print('\t\t- Rights ID unavailable for NCA "%s".' % (os.path.basename(nca_path)))
        return {}

    rights_id = (rights_id.group(1).lower() if rights_id else '')
    dec_titlekey = (dec_titlekey.group(1).lower() if dec_titlekey else '')

    if dist_type != 'download':
        print('\t\t- Invalid distribution type for NCA "%s" (got "%s", expected "%s").' % (os.path.basename(nca_path), dist_type, NCA_DISTRIBUTION_TYPE))
        return {}

    expected_cnt_type = expected_cnt_type.lower()
    if expected_cnt_type and cnt_type != expected_cnt_type:
        print('\t\t- Invalid content type for NCA "%s" (got "%s", expected "%s").' % (os.path.basename(nca_path), cnt_type, expected_cnt_type))
        return {}

    if (not verify) and ((crypto_type != 'titlekey') or titlekey):
        print('\t\t- Signature/hash verification failed for NCA "%s".' % (os.path.basename(nca_path)))
        return {}

    nca_info = {
        'stdout': proc.stdout,
        'dist_type': dist_type,
        'cnt_type': cnt_type,
        'crypto_type': crypto_type,
        'rights_id': rights_id,
        'dec_titlekey': dec_titlekey,
        'verify': verify
    }

    # Calculate file checksums and merge dictionaries.
    file_checksums = utilsCalculateFileChecksums(nca_path)
    nca_info = nca_info | file_checksums

    # Set missing NCA properties.
    nca_info.update({
        'size': os.path.getsize(nca_path),
        'cnt_id': file_checksums['sha256'][:32] # Content IDs are just the first half of the NCA's SHA-256 checksum.
    })

    return nca_info

def utilsBuildNspTitleList(ext_nsp_dir: str, hactool: str, keys: str) -> List:
    # Empty dictionary, used to hold the NSP title list.
    titles = []
    nca_info = {}
    cnmt = tik = nacp = None

    # Scan extracted NSP directory.
    dir_scan = os.scandir(ext_nsp_dir)

    # Parse available CNMT NCAs.
    for entry in dir_scan:
        contents = []

        rights_id = ''
        ticket = {}
        enc_titlekey = { 'value': '' }
        dec_titlekey = { 'value': '' }

        display_name = ''
        publisher = ''
        display_version = ''
        demo = False
        supported_languages = []

        success = True

        # Skip directories.
        if entry.is_dir(): continue

        # Skip files that don't match out criteria.
        if not entry.name.lower().endswith('.cnmt.nca'): continue

        # Skip empty files.
        file_size = entry.stat().st_size
        if not file_size: continue

        print('\t- Parsing Meta NCA: "%s".' % (os.path.basename(entry.path)))

        # Retrieve CNMT NCA information using hactool.
        nca_info = utilsGetNcaInfo(hactool, keys, entry.path, enc_titlekey['value'], 'meta')
        if not nca_info: continue

        # Append NCA info.
        contents.append(nca_info)

        # Extract CNMT file from NCA.
        cnmt_path = os.path.join(ext_nsp_dir, utilsExtractCnmtNca(entry.path, hactool, keys, ext_nsp_dir))

        # Parse CNMT file.
        cnmt = Cnmt.from_file(cnmt_path)
        for i in range(cnmt.header.content_count):
            # Get current content info entry.
            packaged_content_info = cnmt.packaged_content_infos[i]

            # Generate content filename.
            content_filename = packaged_content_info.info.id.hex().lower() + '.nca'
            content_path = os.path.join(ext_nsp_dir, content_filename)
            content_type = utilsCapitalizeString(Cnmt.ContentType(packaged_content_info.info.type).name, ' ')

            print('\t- Parsing %s NCA: "%s".' % (content_type, content_filename))

            # Retrieve NCA information using hactool.
            nca_info = utilsGetNcaInfo(hactool, keys, content_path, enc_titlekey['value'])
            if not nca_info: continue

            # Check if we're missing the titlekey.
            if (not nca_info['verify']) and (nca_info['crypto_type'] == 'titlekey') and (not rights_id):
                # Set rights ID for this title.
                rights_id = nca_info['rights_id']

                # Parse ticket file.
                tik_filename = rights_id + '.tik'
                tik_path = os.path.join(ext_nsp_dir, tik_filename)

                tik = Tik.from_file(tik_path)
                if tik.titlekey_type != Tik.TitlekeyType.common:
                    print('\t\t- Error: ticket "%s" doesn\'t use common crypto. Skipping current title.' % (tik_filename))
                    success = False
                    break

                # Set encrypted titlekey.
                enc_titlekey['value'] = tik.titlekey_block[:16].hex().lower()

                # Close ticket.
                tik.close()

                # Parse NCA once more.
                nca_info = utilsGetNcaInfo(hactool, keys, content_path, enc_titlekey['value'])
                if not nca_info: continue

                # Set decrypted titlekey.
                dec_titlekey['value'] = nca_info['dec_titlekey']

                # Calculate checksums.
                ticket = utilsCalculateFileChecksums(tik_path)
                ticket.update({ 'size': os.path.getsize(tik_path) })

                enc_titlekey = enc_titlekey | utilsCalculateDataChecksums(bytes.fromhex(enc_titlekey['value']))
                enc_titlekey.update({ 'size': 16 })

                dec_titlekey = dec_titlekey | utilsCalculateDataChecksums(bytes.fromhex(dec_titlekey['value']))
                dec_titlekey.update({ 'size': 16 })

            # Verify content ID.
            if (packaged_content_info.info.id != packaged_content_info.hash[:16]) or (packaged_content_info.info.id.hex().lower() != nca_info['sha256'][:32]):
                print('\t\t- Error: content ID / hash mismatch.')
                continue

            # Append NCA info.
            contents.append(nca_info)

            # Check if we're dealing with the first control NCA.
            if (packaged_content_info.info.type == Cnmt.ContentType.control) and (packaged_content_info.info.id_offset == 0):
                # Extract control NCA.
                utilsExtractNcaFsSection(content_path, hactool, keys, ext_nsp_dir, 0)

                # Parse NACP file.
                nacp = Nacp.from_file(os.path.join(ext_nsp_dir, 'control.nacp'))

                # Get relevant info.
                display_name = nacp.title[Nacp.Language.american_english.value].name
                publisher = nacp.title[Nacp.Language.american_english.value].publisher
                display_version = nacp.display_version
                demo = nacp.attribute.demo

                for data in Nacp.Language:
                    if data.name == 'count': break
                    if nacp.supported_language.languages[data.value]: supported_languages.append(utilsCapitalizeString(data.name))

                # Close NACP.
                nacp.close()

        if success:
            # Update output list.
            titles.append({
                'title_id': '{:016x}'.format(cnmt.header.title_id),
                'version': cnmt.header.version.raw_version,
                'title_type': utilsCapitalizeString(cnmt.header.content_meta_type.name),
                'display_name': display_name,
                'publisher': publisher,
                'display_version': display_version,
                'demo': demo,
                'supported_languages': supported_languages,
                'crypto': {
                    'rights_id': rights_id,
                    'ticket': ticket,
                    'enc_titlekey': enc_titlekey,
                    'dec_titlekey': dec_titlekey
                },
                'contents': contents
            })

        # Close CNMT.
        cnmt.close()

    # Close directory scan.
    dir_scan.close()

    return titles

def utilsProcessNspFile(hactool: str, keys: str, outdir: str, nsp: List) -> Dict:
    nsp_dict: Dict = {}

    # Get NSP info.
    nsp_path, nsp_size = nsp
    nsp_info = utilsCalculateFileChecksums(nsp_path)
    nsp_info.update({
        'filename': os.path.basename(nsp_path),
        'size': nsp_size
    })
    nsp_dict.update({ 'nsp': nsp_info })

    # Extract NSP.
    ext_nsp_dir = os.path.join(outdir, GIT_REV + '_' + utilsGetRandomString(8))
    utilsExtractNsp(nsp_path, hactool, keys, ext_nsp_dir)

    # Build NSP title list from extracted files.
    nsp_title_list = utilsBuildNspTitleList(ext_nsp_dir, hactool, keys)

    # Delete extracted data.
    shutil.rmtree(ext_nsp_dir)

    # Check if we actually retrieved meaningful data.
    if not nsp_title_list: return {}

    # Update output dictionary.
    nsp_dict.update({ 'titles': nsp_title_list })

    return nsp_dict

def utilsProcessNspDir(nspdir: str, hactool: str, keys: str, outdir: str) -> None:
    # Get NSP list.
    nsp_list = utilsGetFileList(nspdir, 'nsp', True)
    if not nsp_list: raise Exception("Error: input directory holds no NSP files.")



    import pprint
    pp = pprint.PrettyPrinter(indent=4)




    # Process NSP files.
    for nsp in nsp_list:
        print('Processing "%s"...' % (os.path.basename(nsp[0])))

        nsp_dict = utilsProcessNspFile(hactool, keys, outdir, nsp)
        if not nsp_dict: continue

        pp.pprint(nsp_dict)

def main() -> int:
    # Get git commit information.
    utilsGetGitInfo()

    parser = ArgumentParser(description='Generate a XML dataset from Nintendo Submission Package (NSP) files.')
    parser.add_argument('--nspdir', type=str, metavar='DIR', help='Path to directory with NSP files. Defaults to "' + NSP_PATH + '".')
    parser.add_argument('--hactool', type=str, metavar='FILE', help='Path to hactool binary. Defaults to "' + HACTOOL_PATH + '".')
    parser.add_argument('--keys', type=str, metavar='FILE', help='Path to Nintendo Switch keys file. Defaults to "' + KEYS_PATH + '".')
    parser.add_argument('--outdir', type=str, metavar='DIR', help='Path to output directory. Defaults to "' + OUTPUT_PATH + '".')

    print(SCRIPT_NAME + '.\nRevision: ' + GIT_REV + '.\nMade by DarkMatterCore.\n')

    # Parse arguments.
    args = parser.parse_args()
    nspdir = utilsGetPath(args.nspdir, os.path.join(INITIAL_DIR, NSP_PATH), False)
    hactool = utilsGetPath(args.hactool, os.path.join(INITIAL_DIR, HACTOOL_PATH), True)
    keys = utilsGetPath(args.keys, KEYS_PATH, True)
    outdir = utilsGetPath(args.outdir, os.path.join(INITIAL_DIR, OUTPUT_PATH), False, True)

    # Do our thing.
    utilsProcessNspDir(nspdir, hactool, keys, outdir)

    return 0

if __name__ == "__main__":
    ret: int = 1

    try:
        ret = main()
    except KeyboardInterrupt:
        eprint('\nScript interrupted.')
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        #eprint(str(e))

    try:
        sys.exit(ret)
    except SystemExit:
        os._exit(ret)
