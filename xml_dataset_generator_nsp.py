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
import datetime
import glob

import argparse
from typing import List, Union, Tuple, Dict, Pattern, TYPE_CHECKING

SCRIPT_PATH: str = os.path.realpath(__file__)
SCRIPT_NAME: str = os.path.basename(SCRIPT_PATH)
SCRIPT_DIR:  str = os.path.dirname(SCRIPT_PATH)

CWD:         str = os.getcwd()
INITIAL_DIR: str = (CWD if CWD != SCRIPT_DIR else SCRIPT_DIR)

NSP_PATH:     str = os.path.join('.', 'nsp')
HACTOOL_PATH: str = os.path.join('.', ('hactool.exe' if os.name == 'nt' else 'hactool'))
KEYS_PATH:    str = os.path.join('~', '.switch', 'prod.keys')
OUTPUT_PATH:  str = os.path.join('.', 'out')

HACTOOL_DISTRIBUTION_TYPE_REGEX  = re.compile(r"^Distribution type:\s+(.+)$", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_CONTENT_TYPE_REGEX       = re.compile(r"^Content Type:\s+(.+)$", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_ENCRYPTION_TYPE_REGEX    = re.compile(r"^Encryption Type:\s+(.+)$", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_RIGHTS_ID_REGEX          = re.compile(r"^Rights ID:\s+([0-9a-f]{32})$", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_DECRYPTED_TITLEKEY_REGEX = re.compile(r"^Titlekey \(Decrypted\)(?: \(From CLI\))?\s+([0-9a-f]{32})$", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_VERIFY_REGEX             = re.compile(r"\(FAIL\)", flags=(re.MULTILINE | re.IGNORECASE))
HACTOOL_SAVING_REGEX             = re.compile(r"^Saving (.+) to", flags=(re.MULTILINE | re.IGNORECASE))

NCA_DISTRIBUTION_TYPE: str = 'download'

OUTPUT_XML_NAME: str = 'nsw_nsp.xml'

DOM_LANGUAGES: Dict = {
    'american_english':       'En-US',
    'british_english':        'En-GB',
    'japanese':               'Ja',
    'french':                 'Fr-FR',
    'german':                 'De',
    'latin_american_spanish': 'Es-LX',
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
XML_HEADER +=     '<!DOCTYPE datafile PUBLIC "http://www.logiqx.com/Dats/datafile.dtd" "-//Logiqx//DTD ROM Management Datafile//EN">\n'
XML_HEADER +=     '<datafile>\n'
XML_HEADER +=     '  <header>\n'
XML_HEADER +=     '  </header>\n'

XML_FOOTER: str = '</datafile>\n'

HTML_LINE_BREAK:  str = '&#xA;'
HTML_AMPERSAND:   str = '&amp;'

DEFAULT_DUMPER:   str = '!unknown'
DEFAULT_PROJECT:  str = '!unknown'
DEFAULT_TOOL:     str = '!unknown'
DEFAULT_REGION:   str = 'Unknown'
DEFAULT_COMMENT2: str = ''

GIT_BRANCH: str = ''
GIT_COMMIT: str = ''
GIT_REV:    str = ''

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
    return subprocess.run(['git', '-C', SCRIPT_DIR] + args, capture_output=True, encoding='utf-8')

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

def utilsConvertNszToNsp(outdir: str, nsz_path: str) -> List:
    nsz_args = ['nsz', '-D', '-o', outdir, nsz_path]
    nsp_path = os.path.join(outdir, nsz_path[:-4] + '.nsp')

    proc = subprocess.run(nsz_args, capture_output=True, encoding='utf-8')
    nsp_size = (os.path.getsize(nsp_path) if os.path.exists(nsp_path) else 0)

    if (not proc.stdout) or (proc.returncode != 0) or (not nsp_size): raise Exception('Error: failed to convert NSZ "%s" to NSP.' % (os.path.basename(nsz_path)))

    return [nsp_path, nsp_size]

def utilsCopyKeysFile(keys: str) -> None:
    hactool_keys_path = os.path.abspath(os.path.expanduser(os.path.expandvars(KEYS_PATH)))
    if keys != hactool_keys_path: shutil.copyfile(keys, hactool_keys_path)

def utilsGetFileList(dir: str, recursive: bool = False) -> List:
    file_list: List = []

    # Scan directory.
    dir_scan = os.scandir(dir)

    # Get available files.
    for entry in dir_scan:
        # Skip directories and files that don't match our criteria.
        entry_name = entry.name.lower()
        if (entry.is_dir() and (not recursive)) or (not (entry_name.endswith('.nsp') or entry_name.endswith('.nsz'))): continue

        if entry.is_file():
            # Skip empty files.
            file_size = entry.stat().st_size
            if not file_size: continue

            # Update list.
            file_list.append([entry.path, file_size])
        else:
            file_list.extend(utilsGetFileList(entry.path, True))

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
        'sha256': sha256_hash.hexdigest().lower(),
        'size': os.path.getsize(file)
    }

    return checksums

def utilsGetNcaInfo(hactool: str, keys: str, nca_path: str, titlekey: str = '', expected_cnt_type: str = '') -> Dict:
    # Run hactool.
    args = []
    if titlekey: args.append('--titlekey=' + titlekey)
    args.extend([ '-y', nca_path ])

    proc = utilsRunHactool(hactool, keys, 'nca', args)
    if not proc.stdout or proc.returncode != 0:
        print('\t\t- Failed to retrieve NCA info (%s).' % (proc.stderr.strip()))
        return {}

    # Parse hactool's output.
    dist_type = re.search(HACTOOL_DISTRIBUTION_TYPE_REGEX, proc.stdout)
    cnt_type = re.search(HACTOOL_CONTENT_TYPE_REGEX, proc.stdout)
    crypto_type = re.search(HACTOOL_ENCRYPTION_TYPE_REGEX, proc.stdout)
    rights_id = re.search(HACTOOL_RIGHTS_ID_REGEX, proc.stdout)
    dec_titlekey = re.search(HACTOOL_DECRYPTED_TITLEKEY_REGEX, proc.stdout)
    verify = (len(re.findall(HACTOOL_VERIFY_REGEX, proc.stdout)) == 0)

    if (not dist_type) or (not cnt_type) or (not crypto_type):
        print('\t\t- Failed to parse hactool\'s output.')
        return {}

    dist_type = dist_type.group(1).lower()
    cnt_type = cnt_type.group(1).lower()
    crypto_type = crypto_type.group(1).lower().split()[0]

    if (crypto_type == 'titlekey') and (not rights_id):
        print('\t\t- Failed to parse Rights ID from hactool\'s output.')
        return {}

    rights_id = (rights_id.group(1).lower() if rights_id else '')
    dec_titlekey = (dec_titlekey.group(1).lower() if dec_titlekey else '')

    if dist_type != 'download':
        print('\t\t- Invalid distribution type (got "%s", expected "%s").' % (dist_type, NCA_DISTRIBUTION_TYPE))
        return {}

    expected_cnt_type = expected_cnt_type.lower()
    if expected_cnt_type and cnt_type != expected_cnt_type:
        print('\t\t- Invalid content type (got "%s", expected "%s").' % (cnt_type, expected_cnt_type))
        return {}

    if (not verify) and ((crypto_type != 'titlekey') or titlekey):
        print('\t\t- Signature/hash verification failed.')
        return {}

    nca_info = {
        #'stdout': proc.stdout,
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

    # Set NCA ID.
    # Content IDs are just the first half of the NCA's SHA-256 checksum.
    nca_info.update({ 'cnt_id': file_checksums['sha256'][:32] })

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

        control = {
            'languages': {},
            'display_version': '',
            'demo': False,
            'supported_languages': []
        }

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
            sys.stdout.flush()

            # Get current content info entry.
            packaged_content_info = cnmt.packaged_content_infos[i]

            # Generate content filename.
            content_filename = packaged_content_info.info.id.hex().lower() + '.nca'
            content_path = os.path.join(ext_nsp_dir, content_filename)
            content_type = Cnmt.ContentType(packaged_content_info.info.type).name

            print('\t- Parsing %s NCA: "%s".' % (utilsCapitalizeString(content_type, ' '), content_filename))

            # Retrieve NCA information using hactool.
            nca_info = utilsGetNcaInfo(hactool, keys, content_path, enc_titlekey['value'])
            if not nca_info: continue

            # Check if we're missing the titlekey.
            titlekey_needed = ((nca_info['crypto_type'] == 'titlekey') and nca_info['rights_id'] and (not rights_id))
            if titlekey_needed:
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

                # Parse NCA once more, if needed.
                if not nca_info['verify']:
                    nca_info = utilsGetNcaInfo(hactool, keys, content_path, enc_titlekey['value'])
                    if not nca_info: continue

                # Set decrypted titlekey.
                dec_titlekey['value'] = nca_info['dec_titlekey']

                # Calculate ticket checksums.
                ticket = utilsCalculateFileChecksums(tik_path)
                ticket.update({ 'filename': tik_filename })

                # Generate encrypted titlekey properties.
                enc_titlekey_filename = rights_id + '.enctitlekey.tik'
                enc_titlekey_path = os.path.join(ext_nsp_dir, enc_titlekey_filename)
                with open(enc_titlekey_path, 'wb') as etk: etk.write(bytes.fromhex(enc_titlekey['value']))
                enc_titlekey = enc_titlekey | utilsCalculateFileChecksums(enc_titlekey_path)
                enc_titlekey.update({ 'filename': enc_titlekey_filename })

                # Generate decrypted titlekey properties.
                dec_titlekey_filename = rights_id + '.dectitlekey.tik'
                dec_titlekey_path = os.path.join(ext_nsp_dir, dec_titlekey_filename)
                with open(dec_titlekey_path, 'wb') as dtk: dtk.write(bytes.fromhex(dec_titlekey['value']))
                dec_titlekey = dec_titlekey | utilsCalculateFileChecksums(dec_titlekey_path)
                dec_titlekey.update({ 'filename': dec_titlekey_filename })

                # Remove cert file.
                cert_path = os.path.join(ext_nsp_dir, rights_id + '.cert')
                if os.path.exists(cert_path): os.remove(cert_path)

            # Verify content ID.
            if (packaged_content_info.info.id != packaged_content_info.hash[:16]) or (packaged_content_info.info.id.hex().lower() != nca_info['sha256'][:32]):
                print('\t\t- Error: content ID / hash mismatch.')
                continue

            # Replace NCA info's content type with the type stored in the CNMT, because it's more descriptive.
            nca_info['cnt_type'] = content_type

            # Append NCA info.
            contents.append(nca_info)

            # Check if we're dealing with the first control NCA.
            if (packaged_content_info.info.type == Cnmt.ContentType.control) and (packaged_content_info.info.id_offset == 0):
                # Extract control NCA.
                utilsExtractNcaFsSection(content_path, hactool, keys, ext_nsp_dir, 0)

                # Parse NACP file.
                nacp_path = os.path.join(ext_nsp_dir, 'control.nacp')
                nacp = Nacp.from_file(nacp_path)

                # Get relevant info.
                for lang in Nacp.Language:
                    if lang.name == 'count': break

                    if not nacp.supported_language.languages[lang.value]: continue

                    control_title = nacp.title[lang.value]

                    control['languages'].update({
                        lang.name: {
                            'display_name': control_title.name.replace('&', HTML_AMPERSAND),
                            'publisher': control_title.publisher.replace('&', HTML_AMPERSAND)
                        }
                    })

                    dom_lang = DOM_LANGUAGES.get(lang.name, '')
                    if dom_lang: control['supported_languages'].append(dom_lang)

                control['display_version'] = nacp.display_version.replace('&', HTML_AMPERSAND)
                control['demo'] = nacp.attribute.demo

                # Close and delete NACP.
                nacp.close()
                os.remove(nacp_path)

                # Delete DAT files.
                dat_list = glob.glob(os.path.join(ext_nsp_dir, '*.dat'))
                for dat in dat_list: os.remove(dat)

        if success:
            # Update output list.
            titles.append({
                'title_id': '{:016x}'.format(cnmt.header.title_id),
                'version': cnmt.header.version.raw_version,
                'title_type': cnmt.header.content_meta_type.name,
                'control': control,
                'crypto': {
                    'rights_id': rights_id,
                    'ticket': ticket,
                    'enc_titlekey': enc_titlekey,
                    'dec_titlekey': dec_titlekey
                },
                'contents': contents
            })

        # Close and delete CNMT.
        cnmt.close()
        os.remove(cnmt_path)

        sys.stdout.flush()

    # Close directory scan.
    dir_scan.close()

    return titles

def utilsProcessNspFile(args: argparse.Namespace, nsp: List) -> Dict:
    nsp_info: Dict = {}
    nsp_path, nsp_size = nsp
    orig_nsp_path = nsp_path
    is_nsz = orig_nsp_path.lower().endswith('.nsz')
    temp_path = ''
    nsp_filename = os.path.splitext(os.path.basename(orig_nsp_path))[0] + '.nsp'

    # Handle filenames with non-ASCII codepoints.
    try:
        ascii = orig_nsp_path.encode('ascii')
    except Exception:
        # Rename NSP.
        temp_path = os.path.join(os.path.dirname(orig_nsp_path), utilsGetRandomString(16) + os.path.splitext(orig_nsp_path)[1])
        os.rename(orig_nsp_path, temp_path)
        nsp_path = temp_path

    # Convert NSZ back to NSP, if needed.
    if is_nsz:
        print('\t- Converting NSZ to NSP...')
        nsp_path, nsp_size = utilsConvertNszToNsp(args.outdir, nsp_path)

    if not args.exclude_nsp:
        # Get NSP info.
        nsp_properties = utilsCalculateFileChecksums(nsp_path)
        nsp_properties.update({ 'filename': nsp_filename.replace('&', HTML_AMPERSAND) })
        nsp_info.update({ 'nsp': nsp_properties })

    # Extract NSP.
    ext_nsp_dir = os.path.join(args.outdir, GIT_REV + '_' + utilsGetRandomString(8))
    utilsExtractNsp(nsp_path, args.hactool, args.keys, ext_nsp_dir)

    # Build NSP title list from extracted files.
    nsp_title_list = utilsBuildNspTitleList(ext_nsp_dir, args.hactool, args.keys)

    if nsp_title_list and args.keep_folders:
        # Rename extracted NSP directory.
        new_ext_nsp_dir = os.path.join(args.outdir, nsp_filename)
        if os.path.exists(new_ext_nsp_dir):
            if os.path.isdir(new_ext_nsp_dir):
                shutil.rmtree(new_ext_nsp_dir)
            else:
                os.remove(new_ext_nsp_dir)

        os.rename(ext_nsp_dir, new_ext_nsp_dir)
    else:
        # Delete extracted data.
        shutil.rmtree(ext_nsp_dir)

    # Delete NSP, if needed.
    if is_nsz: os.remove(nsp_path)

    # Rename NSP, if needed.
    if temp_path: os.rename(temp_path, orig_nsp_path)

    # Check if we actually retrieved meaningful data.
    if not nsp_title_list: return {}

    # Update output dictionary.
    nsp_info.update({ 'titles': nsp_title_list })

    return nsp_info

def utilsGenerateXmlDataset(args: argparse.Namespace, nsp_list: List) -> None:
    dump_date_provided = (len(args.dump_date) > 0)
    if not dump_date_provided: args.dump_date = datetime.datetime.now().date().isoformat()

    release_date_provided = (len(args.release_date) > 0)

    comment2_str = (DEFAULT_COMMENT2 if args.include_comment else '').replace('&', HTML_AMPERSAND)

    # Open output XML file.
    xml_path = os.path.join(args.outdir, OUTPUT_XML_NAME)
    with open(xml_path, 'w', encoding='utf-8') as xml_file:
        # Write XML file header.
        xml_file.write(XML_HEADER)

        # Process NSP info list.
        for entry in nsp_list:
            # Process titles available in current NSP.
            for title in entry['titles']:
                nsp = (None if args.exclude_nsp else entry['nsp'])

                control = title['control']
                archive_name = ''

                # Generate archive name string.
                for lang in Nacp.Language:
                    if lang.name == 'count': break
                    if lang.name not in control['languages']: continue
                    archive_name = control['languages'][lang.name]['display_name']
                    break

                if not archive_name: archive_name = title['title_id']

                # Generate dev status string.
                dev_status = ''
                if control['demo']: dev_status += 'Demo'
                if (title['title_type'] == 'patch') or (title['title_type'] == 'add_on_content'):
                    if dev_status: dev_status += ','
                    dev_status += ('Update' if (title['title_type'] == 'patch') else 'DLC')

                # Generate XML entry.
                title_str  = '  <game name="">\n'
                title_str += '    <archive name="%s" namealt="" region="%s" languages="%s" langchecked="0" version="%s" devstatus="%s" additional="" special1="" special2="" />\n' % (archive_name, args.region, ','.join(control['supported_languages']), '' if (title['version'] == 0) else 'v{:d}'.format(title['version']), dev_status)
                title_str += '    <flags bios="0" licensed="1" pirate="0" physical="0" complete="1" nodump="0" public="1" dat="1" />\n'

                if control['languages'] or control['display_version']:
                    title_str += '    <media>\n'

                    if control['languages']:
                        for lang in Nacp.Language:
                            if lang.name == 'count': break
                            if lang.name not in control['languages']: continue

                            control_lang = control['languages'][lang.name]
                            cap_lang_name = utilsCapitalizeString(lang.name)

                            if control_lang['display_name']: title_str += '      <field name="Original Name (NACP, %s)" value="%s" />\n' % (cap_lang_name, control_lang['display_name'])
                            if control_lang['publisher']:    title_str += '      <field name="Publisher (NACP, %s)" value="%s" />\n' % (cap_lang_name, control_lang['publisher'])

                    if control['display_version']: title_str += '      <field name="Display Version (NACP)" value="%s" />\n' % (control['display_version'])

                    title_str += '    </media>\n'

                title_str += '    <source>\n'
                title_str += '      <details section="%s" rominfo="" originalformat="NSP" dumpdate="%s" knowndumpdate="%d" releasedate="%s" knownreleasedate="%d" dumper="%s" project="%s" tool="%s" region="%s" origin="" comment1="" comment2="%s" link1="" link2="" mediatitle="" />\n' % (args.section, args.dump_date, int(dump_date_provided), args.release_date, int(release_date_provided), args.dumper, args.project, args.tool, args.region, comment2_str)
                title_str += '      <serials mediaserial1="" mediaserial2="" pcbserial="" romchipserial1="" romchipserial2="" lockoutserial="" savechipserial="" chipserial="" boxserial="" mediastamp="" boxbarcode="" digitalserial1="%s" digitalserial2="" />\n' % (title['title_id'])

                # Generate ROM entries.
                rom_str = ''

                if nsp:
                    # Add NSP information.
                    rom_str += '      <rom forcename="%s" format="NSP" version="%d" size="%d" crc="%s" md5="%s" sha1="%s" sha256="%s" />\n' % (nsp['filename'], title['version'], nsp['size'], nsp['crc'], nsp['md5'], nsp['sha1'], nsp['sha256'])

                for cnt in title['contents']:
                    # Add current NCA information.
                    cnt_filename = cnt['cnt_id']
                    if cnt['cnt_type'] == 'meta': cnt_filename += '.cnmt'
                    cnt_filename += '.nca'

                    rom_str += '      <rom forcename="%s" format="CDN" version="%d" size="%d" crc="%s" md5="%s" sha1="%s" sha256="%s" />\n' % (cnt_filename, title['version'], cnt['size'], cnt['crc'], cnt['md5'], cnt['sha1'], cnt['sha256'])

                    if (cnt['cnt_type'] != 'program') and (cnt['cnt_type'] != 'data') and (cnt['cnt_type'] != 'delta_fragment'):
                        rom_str += '      <rom forcename="%s" format="CDNMeta" version="%d" size="%d" crc="%s" md5="%s" sha1="%s" sha256="%s" />\n' % (cnt_filename, title['version'], cnt['size'], cnt['crc'], cnt['md5'], cnt['sha1'], cnt['sha256'])

                crypto = title['crypto']
                if crypto['rights_id'] and crypto['ticket']:
                    tik = crypto['ticket']
                    etk = crypto['enc_titlekey']
                    dtk = crypto['dec_titlekey']

                    # Add ticket info.
                    rom_str += '      <rom forcename="%s" format="CDN" version="%d" size="%d" crc="%s" md5="%s" sha1="%s" sha256="%s" />\n' % (tik['filename'], title['version'], tik['size'], tik['crc'], tik['md5'], tik['sha1'], tik['sha256'])

                    # Add encrypted titlekey info.
                    rom_str += '      <rom forcename="%s" format="CDN" version="%d" size="%d" crc="%s" md5="%s" sha1="%s" sha256="%s" />\n' % (etk['filename'], title['version'], etk['size'], etk['crc'], etk['md5'], etk['sha1'], etk['sha256'])

                    # Add decrypted titlekey info.
                    rom_str += '      <rom forcename="%s" format="CDN" version="%d" size="%d" crc="%s" md5="%s" sha1="%s" sha256="%s" />\n' % (dtk['filename'], title['version'], dtk['size'], dtk['crc'], dtk['md5'], dtk['sha1'], dtk['sha256'])

                # Update title string.
                title_str += rom_str
                title_str += '    </source>\n'
                title_str += '  </game>\n'

                # Write metadata.
                xml_file.write(title_str)

        # Write XML footer.
        xml_file.write(XML_FOOTER)

    print('Successfully saved output XML dataset to "%s".' % (xml_path), flush=True)

def utilsProcessNspDir(args: argparse.Namespace) -> None:
    nsp_list: List = []
    file_list: List = []

    # Get NSP/NSZ file list.
    file_list = utilsGetFileList(args.nspdir, True)
    if not file_list: raise Exception("Error: input directory holds no NSP/NSZ files.")

    # Process NSP files.
    for nsp in file_list:
        print('Processing "%s"...' % (os.path.basename(nsp[0])))

        nsp_info = utilsProcessNspFile(args, nsp)
        if not nsp_info:
            print('')
            continue

        # Update NSP list.
        nsp_list.append(nsp_info)
        print('')

    # Generate output XML dataset.
    if nsp_list: utilsGenerateXmlDataset(args, nsp_list)

def main() -> int:
    # Get git commit information.
    utilsGetGitInfo()

    parser = argparse.ArgumentParser(description='Generate a XML dataset from Nintendo Submission Package (NSP) files.')
    parser.add_argument('--nspdir', type=str, metavar='DIR', help='Path to directory with NSP files. Defaults to "' + NSP_PATH + '".')
    parser.add_argument('--hactool', type=str, metavar='FILE', help='Path to hactool binary. Defaults to "' + HACTOOL_PATH + '".')
    parser.add_argument('--keys', type=str, metavar='FILE', help='Path to Nintendo Switch keys file. Defaults to "' + KEYS_PATH + '".')
    parser.add_argument('--outdir', type=str, metavar='DIR', help='Path to output directory. Defaults to "' + OUTPUT_PATH + '".')
    parser.add_argument('--exclude-nsp', action='store_true', default=False, help='Excludes NSP metadata from the output XML dataset. Disabled by default.')
    parser.add_argument('--section', type=str, default='', help='Section string used in the output XML dataset. Optional.')
    parser.add_argument('--dump-date', type=datetime.date.fromisoformat, default=argparse.SUPPRESS, metavar='YYYY-MM-DD', help='Dump date used in the output XML dataset. Defaults to current date if not provided.')
    parser.add_argument('--release-date', type=datetime.date.fromisoformat, default=argparse.SUPPRESS, metavar='YYYY-MM-DD', help='Release date used in the output XML dataset. Optional.')
    parser.add_argument('--dumper', type=str, default=DEFAULT_DUMPER, help='Dumper string used in the output XML dataset. Defaults to "' + DEFAULT_DUMPER + '" if not provided.')
    parser.add_argument('--project', type=str, default=DEFAULT_PROJECT, help='Project string used in the output XML dataset. Defaults to "' + DEFAULT_PROJECT + '" if not provided.')
    parser.add_argument('--tool', type=str, default=DEFAULT_TOOL, help='Tool string used in the output XML dataset. Defaults to "' + DEFAULT_TOOL + '" if not provided.')
    parser.add_argument('--region', type=str, default=DEFAULT_REGION, help='Region string used in the output XML dataset. Defaults to "' + DEFAULT_REGION + '" if not provided.')
    parser.add_argument('--include-comment', action='store_true', default=False, help='Sets the comment2 value to a string that holds information about this script. Disabled by default.')
    parser.add_argument('--keep-folders', action='store_true', default=False, help='Keeps extracted NSP folders in the provided output directory. Disabled by default (all extracted folders are removed).')

    print(SCRIPT_NAME + '.\nRevision: ' + GIT_REV + '.\nMade by DarkMatterCore.\n')

    # Parse arguments. Make sure to escape ampersand characters in input strings.
    args = parser.parse_args()
    args.nspdir = utilsGetPath(args.nspdir, os.path.join(INITIAL_DIR, NSP_PATH), False)
    args.hactool = utilsGetPath(args.hactool, os.path.join(INITIAL_DIR, HACTOOL_PATH), True)
    args.keys = utilsGetPath(args.keys, KEYS_PATH, True)
    args.outdir = utilsGetPath(args.outdir, os.path.join(INITIAL_DIR, OUTPUT_PATH), False, True)
    args.section = args.section.replace('&', HTML_AMPERSAND)
    args.__setattr__('dump_date', args.dump_date.isoformat() if "dump_date" in args else '')
    args.__setattr__('release_date', args.release_date.isoformat() if "release_date" in args else '')
    args.dumper = args.dumper.replace('&', HTML_AMPERSAND)
    args.project = args.project.replace('&', HTML_AMPERSAND)
    args.tool = args.tool.replace('&', HTML_AMPERSAND)
    args.region = args.region.replace('&', HTML_AMPERSAND)

    # Check if nsz has been installed.
    if not shutil.which('nsz'): raise Exception('Error: "nsz" package isn\'t installed.')

    # Copy keys file (required by nsz since it offers no way to provide a keys file path).
    utilsCopyKeysFile(args.keys)

    # Do our thing.
    utilsProcessNspDir(args)

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
