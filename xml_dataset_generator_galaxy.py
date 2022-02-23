#!/usr/bin/env python3

"""
 * xml_dataset_generator_galaxy.py
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

from argparse import ArgumentParser
from typing import List, Union, Tuple, Dict, Pattern, TYPE_CHECKING

SCRIPT_NAME: str = os.path.basename(sys.argv[0])

INITIAL_DIR: str = os.path.abspath(os.path.dirname(__file__))

CSV_PATH:    str = os.path.join('.', 'all_hashes')
HTTP_PATH:   str = os.path.join('.', 'head-requests')
OUTPUT_PATH: str = os.path.join('.', 'out')

SYSTEM_PREFIXES: List = [
    '3DS_3DSAddOnDLC',
    '3DS_3DSDemo',
    '3DS_3DSGameUpdate',
    '3DS_3DSWare',
    '3DS_DSi_Ports',
    '3DS_System',
    'New_3DS_3DSAddOnDLC',
    'New_3DS_3DSDemo',
    'New_3DS_3DSGameUpdate',
    'New_3DS_3DSWare',
    'New_3DS_System',
    'Wii_Disc',
    'Wii_System',
    'Wii_WiiAddOnDLC',
    'Wii_WiiWare',
    'WiiU_System',
    'WiiU_Virtual_Wii',
    'WiiU_WiiUAddOnDLC',
    'WiiU_WiiUDemo',
    'WiiU_WiiUGameUpdate',
    'WiiU_WiiUWare'
]

DUMP_TYPES: List = [
    'CETK',
    'CONTENT',
    'TMD'
]

HASH_TYPES: List = [
    'CRC32',
    'MD5',
    'SHA1'
]

XML_HEADER: str = '<?xml version="1.0" encoding="utf-8"?>\n'
XML_HEADER +=     '<!DOCTYPE datafile PUBLIC "http://www.logiqx.com/Dats/datafile.dtd" "-//Logiqx//DTD ROM Management Datafile//EN">\n'
XML_HEADER +=     '<datafile>\n'
XML_HEADER +=     '  <header>\n'
XML_HEADER +=     '  </header>\n'

XML_FOOTER: str = '</datafile>\n'

HTML_LINE_BREAK:   str = '&#xA;'

DEFAULT_DUMP_DATE: str = '2021-08-23'
DEFAULT_DUMPER:    str = 'Galaxy'
DEFAULT_COMMENT2:  str = '[Sizes from HTTP response header]%s[Sensitive fields (&quot;Date&quot; at least) removed from HTTP Response Header by dumper]' % (HTML_LINE_BREAK)

CONTENT_LENGTH_REGEX: Pattern[str] = re.compile(r"^Content-Length:\s*(\d+)", flags=(re.MULTILINE | re.IGNORECASE))

GIT_BRANCH: str = ''
GIT_COMMIT: str = ''
GIT_REV:    str = ''

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
    DEFAULT_COMMENT2 = '[%s revision %s used to generate XML files]%s%s' % (SCRIPT_NAME, GIT_REV, HTML_LINE_BREAK, DEFAULT_COMMENT2)

def utilsGenerateDictionaryFromCsvFile(csv_path: str) -> Dict:
    csv_dict: Dict = {}

    with open(csv_path, 'r') as csv:
        for idx, line in enumerate(csv):
            # Get Title ID, filename and hash for the current entry.
            (tid, file, hash) = line.strip().split(' ')

            # Convert all strings to lowercase.
            tid = tid.lower()
            file = file.lower()
            hash = hash.lower()

            # Get dictionary for this Title ID.
            tid_dict = csv_dict.get(tid, {})

            # Update entry dictionary.
            tid_dict.update({file: hash})

            # Update CSV dictionary.
            csv_dict.update({tid: tid_dict})

    return csv_dict

def utilsGetHttpResponseHeaderData(http_path: str) -> Tuple:
    http_data: bytes = b''

    # Read binary HTTP response header.
    with open(http_path, 'rb') as http_file:
        http_data = http_file.read()

    # Convert binary HTTP response header to Base64.
    http_data_b64 = base64.b64encode(http_data).decode('utf-8')

    # Decode binary data into a string.
    http_data = http_data.decode('utf-8')

    # Perform a regex search to get the content size.
    size = re.search(CONTENT_LENGTH_REGEX, http_data)
    if not size: raise Exception('Error: Content-Length attribute not available in \'%s\'.' % (http_path))

    size = int(size.group(1))
    if not size: raise Exception('Error: Content-Length attribute in \'%s\' is zero.' % (http_path))

    return (size, http_data_b64)

def utilsGenerateXmlDatasets(xml_dict: Dict, outdir: str) -> None:
    for system_dict in xml_dict.items():
        system_name = system_dict[0].lower()
        tid_dict = system_dict[1]

        xml_path = os.path.join(outdir, system_name + '.xml')

        with open(xml_path, 'w') as xml_file:
            # Write XML file header.
            xml_file.write(XML_HEADER)

            # Process titles.
            for title_dict in tid_dict.items():
                tid = title_dict[0]
                files_dict = title_dict[1]
                headerless_files: List = []
                crcless_files: List = []
                md5less_files: List = []
                sha1less_files: List = []

                # Generate metadata.
                title_str  = '  <game name="">\n'
                title_str += '    <archive name="%s" namealt="" region="Unknown" languages="En" showlang="2" version="" devstatus="" additional="" special1="" special2="" gameid="" clone="" regionalparent="" mergeof="" datternote="" stickynote="" />\n' % (tid)
                title_str += '    <flags bios="0" licensed="1" pirate="0" physical="0" complete="1" nodump="0" public="1" dat="1" />\n'
                title_str += '    <source>\n'
                title_str += '      <details section="Trusted Dump" rominfo="" dumpdate="%s" originalformat="Default" knowndumpdate="1" releasedate="" knownreleasedate="0" dumper="%s" project="" tool="Custom" origin="" comment1="" ' % (DEFAULT_DUMP_DATE, DEFAULT_DUMPER)

                comment2_str = DEFAULT_COMMENT2

                rom_str = ''

                # Process file entries.
                for source_dict in files_dict.items():
                    name = source_dict[0]
                    size = source_dict[1]['size']
                    header = source_dict[1]['header']
                    crc = (source_dict[1]['crc32'] if 'crc32' in source_dict[1] else '')
                    md5 = (source_dict[1]['md5'] if 'md5' in source_dict[1] else '')
                    sha1 = (source_dict[1]['sha1'] if 'sha1' in source_dict[1] else '')

                    # Generate metadata.
                    if header:
                        rom_str += '      <rom forcename="%s" emptydir="0" extension="" item="" date="" format="Default" version="" utype="" size="%d" crc="%s" md5="%s" sha1="%s" sha256="" serial="" bad="0" unique="1" mergename="" unique_attachment="%s"/>\n' % (name, size, crc, md5, sha1, header)
                    else:
                        rom_str += '      <rom forcename="%s" emptydir="0" extension="" item="" date="" format="Default" version="" utype="" size="%d" crc="%s" md5="%s" sha1="%s" sha256="" serial="" bad="0" unique="1" mergename="" />\n' % (name, size, crc, md5, sha1)

                    # Update lists (if needed).
                    if not size: headerless_files.append(name)
                    if not crc: crcless_files.append(name)
                    if not md5: md5less_files.append(name)
                    if not sha1: sha1less_files.append(name)

                # Update comment2 (if needed).
                if headerless_files: comment2_str += '%s[No HTTP Response Header(s) for the following file(s) was included in data provided by dumper: %s]' % (HTML_LINE_BREAK, ', '.join(headerless_files))

                if crcless_files or md5less_files or sha1less_files:
                    comment2_str += '%s[The following hashes (out of the provided hashes - CRC32, MD5 and SHA1) weren\'t included in the data provided by the dumper: ' % (HTML_LINE_BREAK)

                    if crcless_files:
                        comment2_str += 'CRC32 for %s' % (', '.join(crcless_files))
                        if md5less_files: comment2_str += '; '

                    if md5less_files:
                        comment2_str += 'MD5 for %s' % (', '.join(md5less_files))
                        if sha1less_files: comment2_str += '; '

                    if sha1less_files: comment2_str += 'SHA1 for %s' % (', '.join(sha1less_files))

                    comment2_str += ']'

                # Update title string.
                title_str += 'comment2="%s" link1="" link2="" region="" mediatitle="" />\n' % (comment2_str)
                title_str += '      <serials mediaserial1="" mediaserial2="" pcbserial="" romchipserial1="" romchipserial2="" lockoutserial="" savechipserial="" chipserial="" boxserial="" mediastamp="" boxbarcode="" digitalserial1="%s" digitalserial2="" />\n' % (tid)
                title_str += rom_str
                title_str += '    </source>\n'
                title_str += '  </game>\n'

                # Write metadata.
                xml_file.write(title_str)

            # Write XML footer.
            xml_file.write(XML_FOOTER)

def utilsProcessData(csvdir: str, httpdir: str, outdir: str) -> None:
    xml_dict: Dict = {
        '3DS': {},
        'Wii': {},
        'WiiU': {}
    }

    # Loop through all posible string combinations.
    for system_prefix in SYSTEM_PREFIXES:
        for dump_type in DUMP_TYPES:
            for hash_type in HASH_TYPES:
                # Generate dictionary for the current combination.
                csv_path: str = os.path.join(csvdir, system_prefix + '_' + dump_type + '_' + hash_type + '.txt')

                try:
                    csv_dict = utilsGenerateDictionaryFromCsvFile(csv_path)
                except Exception as e:
                    #traceback.print_exc(file=sys.stderr)
                    continue

                # Merge generated dictionary with our XML dictionary.
                word = system_prefix.split('_')[0]
                if word == 'New': word = '3DS'

                system_dict = xml_dict.get(word, {})

                for item1 in csv_dict.items():
                    tid = item1[0]
                    contents_dict = item1[1]

                    tid_dict = system_dict.get(tid, {})

                    for item2 in contents_dict.items():
                        name = item2[0]
                        hash = item2[1]

                        size = 0
                        http_data_b64 = ''

                        file_dict = tid_dict.get(name, {})

                        get_response = ((not file_dict) or ('size' not in file_dict) or ('header' not in file_dict))
                        if get_response:
                            # Get HTTP response header for this file.
                            try:
                                (size, http_data_b64) = utilsGetHttpResponseHeaderData(os.path.join(httpdir, tid + '-' + name + '.txt'))
                                file_dict.update({'size': size, 'header': http_data_b64})
                            except Exception as e:
                                #traceback.print_exc(file=sys.stderr)
                                file_dict.update({'size': size, 'header': http_data_b64})

                        file_dict.update({hash_type.lower(): hash})
                        tid_dict.update({name: file_dict})
                        system_dict.update({tid: tid_dict})

                xml_dict.update({word: system_dict})

    # Generate output XML datasets.
    utilsGenerateXmlDatasets(xml_dict, outdir)

def main() -> int:
    # Get git commit information.
    utilsGetGitInfo()

    parser = ArgumentParser(description='Generate XML datasets from Galaxy\'s comma-separated text files.')
    parser.add_argument('--csvdir', type=str, metavar='DIR', help='Path to directory with comma-separated text files. Defaults to \'' + CSV_PATH + '\'.')
    parser.add_argument('--httpdir', type=str, metavar='DIR', help='Path to directory with HTTP response headers. Defaults to \'' + HTTP_PATH + '\'.')
    parser.add_argument('--outdir', type=str, metavar='DIR', help='Path to output directory. Defaults to \'' + OUTPUT_PATH + '\'.')

    print(SCRIPT_NAME + '.\nRevision: ' + GIT_REV + '.\nMade by DarkMatterCore.\n')

    # Parse arguments.
    args = parser.parse_args()
    csvdir = utilsGetPath(args.csvdir, os.path.join(INITIAL_DIR, CSV_PATH), False)
    httpdir = utilsGetPath(args.csvdir, os.path.join(INITIAL_DIR, HTTP_PATH), False)
    outdir = utilsGetPath(args.outdir, os.path.join(INITIAL_DIR, OUTPUT_PATH), False, True)

    # Do our thing.
    utilsProcessData(csvdir, httpdir, outdir)

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
