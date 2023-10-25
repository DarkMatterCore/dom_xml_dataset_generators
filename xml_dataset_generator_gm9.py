#!/usr/bin/env python3

"""
 * xml_dataset_generator_gm9.py
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

from datetime import datetime
from argparse import ArgumentParser
from typing import List, Union, Tuple, Dict, Pattern, TYPE_CHECKING

SCRIPT_NAME: str = os.path.basename(sys.argv[0])

INITIAL_DIR: str = os.path.abspath(os.path.dirname(__file__))

HASHES_PATH: str = os.path.join('.', 'hashes')
OUTPUT_PATH: str = os.path.join('.', 'out')

PROPERTIES_COUNT: int = 6

XML_HEADER: str = '<?xml version="1.0" encoding="utf-8"?>\n'
XML_HEADER +=     '<!DOCTYPE datafile PUBLIC "http://www.logiqx.com/Dats/datafile.dtd" "-//Logiqx//DTD ROM Management Datafile//EN">\n'
XML_HEADER +=     '<datafile>\n'
XML_HEADER +=     '  <header>\n'
XML_HEADER +=     '  </header>\n'

XML_FOOTER: str = '</datafile>\n'

HTML_LINE_BREAK:   str = '&#xA;'

DEFAULT_COMMENT2:  str = ''

GIT_BRANCH: str = ''
GIT_COMMIT: str = ''
GIT_REV:    str = ''

GM9_PRODUCT_CODE_REGEX: Pattern[str] = re.compile(r"Product\s+Code\s*:\s*(.+)", flags=re.IGNORECASE)
GM9_CART_ID_REGEX:      Pattern[str] = re.compile(r"Cart\s+ID\s*:\s*(.+)", flags=re.IGNORECASE)
GM9_PLATFORM_REGEX:     Pattern[str] = re.compile(r"Platform\s*:\s*(.+)", flags=re.IGNORECASE)
GM9_SAVE_CHIP_ID_REGEX: Pattern[str] = re.compile(r"Save\s+chip\s+ID\s*:\s*(?:0x)?(.+)", flags=re.IGNORECASE)
GM9_TIMESTAMP_REGEX:    Pattern[str] = re.compile(r"Timestamp\s*:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", flags=re.IGNORECASE)
GM9_VERSION_REGEX:      Pattern[str] = re.compile(r"GM9\s+Version\s*:\s*(.+)", flags=re.IGNORECASE)

WHITESPACE_REGEX:       Pattern[str] = re.compile(r"\s+")

ROM_PROPERTIES: Dict = {
    'ds': [ 'nds', 'Decrypted' ],
    'dsi enhanced': [ 'nds', 'Decrypted' ],
    'dsi exclusive': [ 'dsi', 'Decrypted' ],
    'o3ds': [ '3ds', 'Encrypted' ],
    'n3ds': [ '3ds', 'Encrypted' ]
}

DEFAULT_EARLIEST_DATE: datetime = datetime.strptime('2021-03-22', '%Y-%m-%d')

MEDIA_PICTURE_TYPES: List = [
    'back',
    'front'
]

MEDIA_PICTURE_EXTENSIONS: List = [
    'png',
    'jpg',
    'jpeg',
    'bmp'
]

HASH_FILE_NAME: str = 'HASHES.txt'

HASH_ENTRY_FILE_NAME_REGEX: Pattern[str] = re.compile(r"^File:\s*(.+)", flags=(re.MULTILINE | re.IGNORECASE))
HASH_ENTRY_FILE_SIZE_REGEX: Pattern[str] = re.compile(r"^Size\s*\(Bytes\):\s*(\d+)", flags=(re.MULTILINE | re.IGNORECASE))
HASH_ENTRY_CRC32_REGEX:     Pattern[str] = re.compile(r"^CRC32:\s*([\da-f]{8})", flags=(re.MULTILINE | re.IGNORECASE))
HASH_ENTRY_MD5_REGEX:       Pattern[str] = re.compile(r"^MD5:\s*([\da-f]{32})", flags=(re.MULTILINE | re.IGNORECASE))
HASH_ENTRY_SHA1_REGEX:      Pattern[str] = re.compile(r"^SHA1:\s*([\da-f]{40})", flags=(re.MULTILINE | re.IGNORECASE))
HASH_ENTRY_SHA256_REGEX:    Pattern[str] = re.compile(r"^SHA256:\s*([\da-f]{64})", flags=(re.MULTILINE | re.IGNORECASE))

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def utilsGetPath(path_arg: str, fallback_path: str, is_file: bool, create: bool = False) -> str:
    path = os.path.abspath(os.path.expanduser(os.path.expandvars(path_arg if path_arg else fallback_path)))

    if not is_file and create: os.makedirs(path, exist_ok=True)

    if not os.path.exists(path) or (is_file and os.path.isdir(path)) or (not is_file and os.path.isfile(path)):
        raise Exception("Error: '%s' points to an invalid file/directory." % (path))

    return path

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

def utilsGetRegexResult(cur_value: str, regex: Pattern[str], search_str: str) -> str:
    if not cur_value:
        cur_value = re.search(regex, search_str)
        if cur_value: cur_value = cur_value.group(1).strip()

    return cur_value

def utilsGetBase64EncodedMediaPictures(indir: str, basename: str) -> Dict:
    # Empty dictionary to hold the Base64-encoded media pictures.
    media_pictures = {}

    # Loop through all possible media picture combinations.
    for media_picture_type in MEDIA_PICTURE_TYPES:
        for media_picture_ext in MEDIA_PICTURE_EXTENSIONS:
            # Generate path. Skip entry if the file doesn't exist or if it's empty.
            media_path = os.path.join(indir, basename + '_' + media_picture_type + '.' + media_picture_ext)
            if (not os.path.exists(media_path)) or os.path.isdir(media_path) or (not os.path.getsize(media_path)): continue

            # Read whole file into memory.
            with open(media_path, 'rb') as media_fd: media_data = media_fd.read()

            # Convert media picture data into a Base64-encoded string.
            media_data = base64.b64encode(media_data).decode('utf-8')

            # Update dictionary.
            media_pictures.update({ media_picture_type: media_data })

            break

    return media_pictures

def utilsBuildGM9Cache(indir: str) -> Dict:
    # Empty dictionary, used to hold the GodMode9 cache.
    gm9_cache = {}

    # Get current date.
    now = datetime.utcnow()

    # Scan GodMode9 dump directory.
    dir_scan = os.scandir(indir)

    # Parse available TXT files.
    for entry in dir_scan:
        # Skip files without a TXT extension.
        if (not entry.is_file()) or (not entry.name.lower().endswith('.txt')) or (entry.name.lower() == 'hashes.txt'): continue

        # Initialize variables.
        filename:     str = os.path.splitext(entry.name)[0]
        product_code: str = ''
        cart_id:      str = ''
        platform:     str = ''
        save_chip_id: str = ''
        timestamp:    str = ''
        gm9_version:  str = ''
        extension:    str = ''
        crypto:       str = ''

        # Parse TXT file.
        with open(entry.path, 'r') as txt:
            for idx, line in enumerate(txt):
                # Strip current line.
                cur_line = line.strip()

                # Look for relevant data.
                product_code = utilsGetRegexResult(product_code, GM9_PRODUCT_CODE_REGEX, cur_line)
                cart_id = utilsGetRegexResult(cart_id, GM9_CART_ID_REGEX, cur_line)
                platform = utilsGetRegexResult(platform, GM9_PLATFORM_REGEX, cur_line)
                save_chip_id = utilsGetRegexResult(save_chip_id, GM9_SAVE_CHIP_ID_REGEX, cur_line)
                timestamp = utilsGetRegexResult(timestamp, GM9_TIMESTAMP_REGEX, cur_line)
                gm9_version = utilsGetRegexResult(gm9_version, GM9_VERSION_REGEX, cur_line)

        # Skip this entry if we're missing critical data.
        if (not product_code) or (not cart_id) or (not platform) or (not timestamp) or (not gm9_version): continue

        # Sanitize data.
        platform = platform.lower()
        timestamp = WHITESPACE_REGEX.sub(' ', timestamp).strip().split(' ')[0]

        # Get ROM properties. Skip entry if we're dealing with an invalid platform.
        properties = ROM_PROPERTIES.get(platform, [])
        if not properties: continue
        (extension, crypto) = properties

        # Get the last modified date from this file.
        file_mtime = datetime.utcfromtimestamp(os.path.getmtime(entry.path)).replace(hour=0, minute=0, second=0)
        gm9_mtime = datetime.strptime(timestamp, '%Y-%m-%d')

        # Compare dates. Emit a warning if there's a mismatch.
        if file_mtime != gm9_mtime:
            eprint('WARNING: last modification date from \'%s\' doesn\'t match GodMode9\'s timestamp! (%s != %s).\n' % (entry.name, file_mtime.strftime('%Y-%m-%d'), gm9_mtime.strftime('%Y-%m-%d')))
        elif file_mtime < DEFAULT_EARLIEST_DATE:
            eprint('WARNING: dump date from \'%s\' is too old! (%s < %s).\n' % (entry.name, file_mtime.strftime('%Y-%m-%d'), DEFAULT_EARLIEST_DATE.strftime('%Y-%m-%d')))
        elif file_mtime > now:
            eprint('WARNING: dump date from \'%s\' exceeds current UTC timestamp! (%s > %s).\n' % (entry.name, file_mtime.strftime('%Y-%m-%d'), now.strftime('%Y-%m-%d')))

        # Check if there's any media pictures available.
        media_pictures = utilsGetBase64EncodedMediaPictures(indir, filename)

        # Update GodMode9 dictionary.
        platform_dict = gm9_cache.get(extension, {})

        file_dict = platform_dict.get(filename, {})

        file_dict.update({
            'product_code': product_code,
            'cart_id': cart_id,
            'timestamp': timestamp,
            'gm9_version': gm9_version,
            'crypto': crypto
        })

        # Only store the Save Chip ID if we actually got it.
        if save_chip_id: file_dict.update({ 'save_chip_id': save_chip_id })

        # Merge file and media pictures dictionaries if we have picture data.
        if media_pictures: file_dict = file_dict | media_pictures

        platform_dict.update({ filename: file_dict })

        gm9_cache.update({ extension: platform_dict })

    return gm9_cache

def utilsGetChecksumData(indir: str, gm9_cache: Dict) -> Dict:
    hash_entries: List = []
    cur_hash_entry: str = ''
    save_flag: bool = False

    # Generate hash file path.
    hash_file_path = os.path.join(indir, HASH_FILE_NAME)
    if (not os.path.exists(hash_file_path)) or os.path.isdir(hash_file_path) or (not os.path.getsize(hash_file_path)): raise Exception('File \'%s\' unavailable or empty!' % (hash_file_path))

    # Get hash entries from the hash file.
    with open(hash_file_path, mode='r', encoding='utf-16') as hash_file:
        for idx, line in enumerate(hash_file):
            cur_line = line.strip()

            if (not save_flag) and (cur_line == '----| File Data |--------------------------------------------------'):
                save_flag = True
            elif save_flag and ((cur_line == '-------------------------------------------------------------------') or (cur_line[0:5] == '----|')):
                hash_entries.append(cur_hash_entry)
                cur_hash_entry = ''
                save_flag = False
            elif save_flag:
                cur_hash_entry += line

    if not hash_entries: raise Exception('No valid File Data entries found in \'%s\'!' % (hash_file_path))

    # Process hash entries.
    for cur_hash_entry in hash_entries:
        # Initialize variables.
        filename: str = ''
        size:     str = ''
        crc32:    str = ''
        md5:      str = ''
        sha1:     str = ''
        sha256:   str = ''

        # Look for relevant data.
        filename = utilsGetRegexResult(filename, HASH_ENTRY_FILE_NAME_REGEX, cur_hash_entry)
        size = utilsGetRegexResult(size, HASH_ENTRY_FILE_SIZE_REGEX, cur_hash_entry)
        crc32 = utilsGetRegexResult(crc32, HASH_ENTRY_CRC32_REGEX, cur_hash_entry)
        md5 = utilsGetRegexResult(md5, HASH_ENTRY_MD5_REGEX, cur_hash_entry)
        sha1 = utilsGetRegexResult(sha1, HASH_ENTRY_SHA1_REGEX, cur_hash_entry)
        sha256 = utilsGetRegexResult(sha256, HASH_ENTRY_SHA256_REGEX, cur_hash_entry)

        # Skip entry if we couldn't find any relevant data.
        if (not filename) or (not size) or ((not crc32) and (not md5) and (not sha1) and (not sha256)): continue

        # Get basename and extension.
        (basename, extension) = os.path.splitext(filename)
        extension = extension[1:].lower()

        # Get dictionary for this file.
        platform_dict = gm9_cache.get(extension, {})
        if not platform_dict:
            eprint('WARNING: unrecognized file extension for \'%s\'! Skipping...\n' % (filename))
            continue

        file_dict = platform_dict.get(basename, {})
        if not file_dict:
            eprint('WARNING: GodMode9 data not found for \'%s\'! Skipping...\n' % (filename))
            continue

        # Update file dictionary.
        file_dict.update({ 'size': int(size) })
        if crc32: file_dict.update({ 'crc32': crc32.lower() })
        if md5: file_dict.update({ 'md5': md5.lower() })
        if sha1: file_dict.update({ 'sha1': sha1.lower() })
        if sha256: file_dict.update({ 'sha256': sha256.lower() })

        # Update cache.
        platform_dict.update({ basename: file_dict })

        gm9_cache.update({ extension: platform_dict })

    return gm9_cache

def utilsGenerateXmlDatasets(gm9_cache: Dict, outdir: str, section: str, dumper: str, project: str) -> None:
    for platform_dict in gm9_cache.items():
        extension = platform_dict[0]
        file_dict = platform_dict[1]

        xml_path = os.path.join(outdir, extension + '.xml')

        with open(xml_path, 'w') as xml_file:
            # Write XML file header.
            xml_file.write(XML_HEADER)

            # Process file entries.
            for source_dict in file_dict.items():
                basename = source_dict[0]
                product_code = source_dict[1]['product_code']
                cart_id = source_dict[1]['cart_id']
                timestamp = source_dict[1]['timestamp']
                gm9_version = source_dict[1]['gm9_version']
                crypto = source_dict[1]['crypto']
                save_chip_id = (source_dict[1]['save_chip_id'] if 'save_chip_id' in source_dict[1] else '')

                back = (source_dict[1]['back'] if 'back' in source_dict[1] else '')
                front = (source_dict[1]['front'] if 'front' in source_dict[1] else '')

                size = (source_dict[1]['size'] if 'size' in source_dict[1] else 0)
                crc = (source_dict[1]['crc32'] if 'crc32' in source_dict[1] else '')
                md5 = (source_dict[1]['md5'] if 'md5' in source_dict[1] else '')
                sha1 = (source_dict[1]['sha1'] if 'sha1' in source_dict[1] else '')
                sha256 = (source_dict[1]['sha256'] if 'sha256' in source_dict[1] else '')

                # Filter out invalid entries.
                if (not size) or ((not crc) and (not md5) and (not sha1) and (not sha256)):
                    eprint('WARNING: no size or checksum data available for \'%s.%s\'! Skipping...\n' % (basename, extension))
                    continue

                # Generate comment2 string.
                comment2_str = '%s%s[Cart ID: %s]' % (DEFAULT_COMMENT2, HTML_LINE_BREAK, cart_id)
                if save_chip_id: comment2_str = '%s%s[Save Chip ID: %s]' % (comment2_str, HTML_LINE_BREAK, save_chip_id)

                # Generate metadata.
                source_str  = '  <game>\n'
                source_str += '    <source>\n'
                source_str += '      <details section="%s" dumpdate="%s" originalformat="%s" knowndumpdate="1" dumper="%s" project="%s" tool="GodMode9 %s" comment2="%s" />\n' % (section, timestamp, crypto, dumper, project, gm9_version, comment2_str)
                source_str += '      <rom extension="%s" format="%s" size="%d" serial="%s" ' % (extension, crypto, size, product_code)

                if crc:    source_str += 'crc="%s" ' % (crc)
                if md5:    source_str += 'md5="%s" ' % (md5)
                if sha1:   source_str += 'sha1="%s" ' % (sha1)
                if sha256: source_str += 'sha256="%s" ' % (sha256)

                source_str += '/>\n'

                if back:  source_str += '      <attachment description="Media back" base64="%s" />\n' % (back)
                if front: source_str += '      <attachment description="Media front" base64="%s" />\n' % (front)

                source_str += '    </source>\n'
                source_str += '  </game>\n'

                # Write metadata.
                xml_file.write(source_str)

            # Write XML footer.
            xml_file.write(XML_FOOTER)

def utilsProcessData(indir: str, outdir: str, section: str, dumper: str, project: str) -> None:
    gm9_cache: Dict = {}

    # Build GodMode9 cache dictionary.
    gm9_cache = utilsBuildGM9Cache(indir)

    # Update dictionary to add checksum data.
    gm9_cache = utilsGetChecksumData(indir, gm9_cache)

    # Generate output XML datasets.
    utilsGenerateXmlDatasets(gm9_cache, outdir, section, dumper, project)

def main() -> int:
    # Get git commit information.
    utilsGetGitInfo()

    parser = ArgumentParser(description='Generate XML dataset from GodMode9 dumps.')
    parser.add_argument('--indir', type=str, metavar='DIR', help='Path to directory with GodMode9 dumps. Defaults to \'' + HASHES_PATH + '\'.')
    parser.add_argument('--outdir', type=str, metavar='DIR', help='Path to output directory. Defaults to \'' + OUTPUT_PATH + '\'.')
    parser.add_argument('--section', type=str, required=True, help='Section string used in the output XML dataset. Must be provided.')
    parser.add_argument('--dumper', type=str, required=True, help='Dumper string used in the output XML dataset. Must be provided.')
    parser.add_argument('--project', type=str, required=True, help='Project string used in the output XML dataset. Must be provided.')

    print(SCRIPT_NAME + '.\nRevision: ' + GIT_REV + '.\nMade by DarkMatterCore.\n')

    # Parse arguments.
    args = parser.parse_args()
    indir = utilsGetPath(args.indir, os.path.join(INITIAL_DIR, HASHES_PATH), False)
    outdir = utilsGetPath(args.outdir, os.path.join(INITIAL_DIR, OUTPUT_PATH), False, True)

    # Do our thing.
    utilsProcessData(indir, outdir, args.section, args.dumper, args.project)

    return 0

if __name__ == "__main__":
    ret: int = 1

    try:
        ret = main()
    except KeyboardInterrupt:
        eprint('\nScript interrupted.')
    except Exception as e:
        traceback.print_exc(file=sys.stderr)

    try:
        sys.exit(ret)
    except SystemExit:
        os._exit(ret)
