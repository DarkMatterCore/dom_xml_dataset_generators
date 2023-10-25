#!/usr/bin/env python3

"""
 * xml_dataset_generator_nold.py
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

NOLD_DATA_PATH: str = os.path.join('.', 'nold')
OUTPUT_PATH:    str = os.path.join('.', 'out')

TITLE_TYPES: List = [
    'addons',
    'system',
    'wiiware'
]

FILE_SUFFIXES: List = [
    '.md5',
    '_spider.log'
]

NUS_URL_MD5_REGEX:   Pattern[str] = re.compile(r"nus\.cdn\.shop\.wii\.com/ccs/download/([\da-f]{16})/(.+)", flags=re.IGNORECASE)
NUS_URL_HTTP_REGEX:  Pattern[str] = re.compile(r"http://nus\.cdn\.shop\.wii\.com/ccs/download/([\da-f]{16})/(.+)$", flags=(re.MULTILINE | re.IGNORECASE))

HTTP_RESPONSE_REGEX: Pattern[str] = re.compile(r"^\s+.+$", flags=(re.MULTILINE | re.IGNORECASE))

WINDOWS_LINE_BREAK: str = '\r\n'

XML_HEADER: str = '<?xml version="1.0" encoding="utf-8"?>\n'
XML_HEADER +=     '<!DOCTYPE datafile PUBLIC "http://www.logiqx.com/Dats/datafile.dtd" "-//Logiqx//DTD ROM Management Datafile//EN">\n'
XML_HEADER +=     '<datafile>\n'
XML_HEADER +=     '  <header>\n'
XML_HEADER +=     '  </header>\n'

XML_FOOTER: str = '</datafile>\n'

HTML_LINE_BREAK:   str = '&#xA;'

DEFAULT_DUMP_DATE: str = '2019-01-28'
DEFAULT_DUMPER:    str = 'nold'
DEFAULT_COMMENT2:  str = '[Sizes from HTTP response header]%s[Downloaded twice to verify]%s[HTTP Response Headers retrieved via head requests after download, not as part of download]%s[Only MD5 hashes provided by dumper]' % (HTML_LINE_BREAK, HTML_LINE_BREAK, HTML_LINE_BREAK)

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
    comment2_str = DEFAULT_COMMENT2
    DEFAULT_COMMENT2 = '[%s revision %s used to generate XML files]' % (SCRIPT_NAME, GIT_REV)
    if comment2_str: DEFAULT_COMMENT2 += '%s%s' % (HTML_LINE_BREAK, comment2_str)

def utilsGenerateDictionaryFromMd5File(md5_path: str) -> Dict:
    md5_dict: Dict = {}

    with open(md5_path, 'r') as csv:
        for idx, line in enumerate(csv):
            # Get MD5 hash and URL for the current entry.
            (md5, url) = list(filter(None, line.strip().split(' ')))

            # Convert all strings to lowercase.
            md5 = md5.lower()
            url = url.lower()

            # Get Title ID and filename from the URL.
            regex = re.search(NUS_URL_MD5_REGEX, url)
            if not regex: raise Exception('Error: unknown URL format in \'%s\' (\'%s\').' % (md5_path, url))

            tid = regex.group(1)
            file = regex.group(2)

            # Skip this file if it's a TMD with no version suffix.
            if file == 'tmd': continue

            # Get dictionary for this Title ID.
            tid_dict = md5_dict.get(tid, {})

            # Get dictionary for this file.
            file_dict = tid_dict.get(file, {})

            # Update file dictionary.
            file_dict.update({'md5': md5})

            # Update Title ID dictionary.
            tid_dict.update({file: file_dict})

            # Update MD5 dictionary.
            md5_dict.update({tid: tid_dict})

    return md5_dict

def utilsGenerateDictionaryFromHttpLogFile(http_path: str) -> Dict:
    http_dict: Dict = {}
    responses: List = []
    cur_response: str = ''

    # Get HTTP response headers from the input file.
    with open(http_path, 'r') as http_file:
        for idx, line in enumerate(http_file):
            if not line.strip():
                responses.append(cur_response)
                cur_response = ''
            else:
                cur_response += line

    # Parse HTTP response headers.
    for res in responses:
        # Get Title ID and filename from the response header using the requested URL.
        regex = re.search(NUS_URL_HTTP_REGEX, res)
        if not regex: raise Exception('Error: unknown HTTP response header format in \'%s\':\n\n%s' % (http_path, res))

        tid = regex.group(1).lower()
        file = regex.group(2).lower()

        # Skip this file if it's a TMD with no version suffix.
        if file == 'tmd': continue

        # Get all lines belonging to the raw HTTP response header.
        regex = re.findall(HTTP_RESPONSE_REGEX, res)
        if not regex: raise Exception('Error: unknown HTTP response header format in \'%s\':\n\n%s' % (http_path, res))

        # Remove leading whitespaces and regenerate the raw response header.
        for k, v in enumerate(regex): regex[k] = regex[k].strip()
        cur_response = WINDOWS_LINE_BREAK.join(regex) + (WINDOWS_LINE_BREAK * 2)

        # Generate Base64-encoded HTTP response header.
        http_data_b64 = base64.b64encode(cur_response.encode('utf-8')).decode('utf-8')

        # Get content size.
        regex = re.search(CONTENT_LENGTH_REGEX, cur_response)
        if not regex: raise Exception('Error: Content-Length attribute not available in HTTP response header from \'%s\':\n\n%s' % (http_path, cur_response))
        size = int(regex.group(1))

        # Get dictionary for this Title ID.
        tid_dict = http_dict.get(tid, {})

        # Get dictionary for this file.
        file_dict = tid_dict.get(file, {})

        # Update file dictionary.
        file_dict.update({'size': size, 'header': http_data_b64})

        # Update Title ID dictionary.
        tid_dict.update({file: file_dict})

        # Update HTTP dictionary.
        http_dict.update({tid: tid_dict})

    return http_dict

def utilsGenerateXmlDataset(xml_dict: Dict, outdir: str) -> None:
    xml_path = os.path.join(outdir, 'wii.xml')
    with open(xml_path, 'w') as xml_file:
        # Write XML file header.
        xml_file.write(XML_HEADER)

        # Process titles.
        for item1 in xml_dict.items():
            tid = item1[0]
            contents_dict = item1[1]

            # Generate metadata.
            title_str  = '  <game name="">\n'
            title_str += '    <archive name="%s" namealt="" region="Unknown" languages="En" showlang="2" version="" devstatus="" additional="" special1="" special2="" gameid="" clone="" regionalparent="" mergeof="" datternote="" stickynote="" />\n' % (tid)
            title_str += '    <flags bios="0" licensed="1" pirate="0" physical="0" complete="1" nodump="0" public="1" dat="1" />\n'
            title_str += '    <source>\n'
            title_str += '      <details section="Trusted Dump" rominfo="" dumpdate="%s" originalformat="Default" knowndumpdate="1" releasedate="" knownreleasedate="0" dumper="%s" project="" tool="Custom" origin="" comment1="" comment2="%s" link1="" link2="" region="" mediatitle="" />\n' % (DEFAULT_DUMP_DATE, DEFAULT_DUMPER, DEFAULT_COMMENT2)
            title_str += '      <serials mediaserial1="" mediaserial2="" pcbserial="" romchipserial1="" romchipserial2="" lockoutserial="" savechipserial="" chipserial="" boxserial="" mediastamp="" boxbarcode="" digitalserial1="%s" digitalserial2="" />\n' % (tid)

            rom_str = ''

            # Process file entries.
            for source_dict in contents_dict.items():
                name = source_dict[0]
                size = source_dict[1]['size']
                header = source_dict[1]['header']
                md5 = (source_dict[1]['md5'] if 'md5' in source_dict[1] else '')

                # Skip entry if there's no MD5 hash.
                if not md5: continue

                # Generate metadata.
                rom_str += '      <rom forcename="%s" emptydir="0" extension="" item="" date="" format="Default" version="" utype="" size="%d" crc="" md5="%s" sha1="" sha256="" serial="" bad="0" unique="1" mergename="" unique_attachment="%s" />\n' % (name, size, md5, header)

            # Skip title entirely if there are no valid rom entries.
            if not rom_str: continue

            # Update title string.
            title_str += rom_str
            title_str += '    </source>\n'
            title_str += '  </game>\n'

            # Write metadata.
            xml_file.write(title_str)

        # Write XML footer.
        xml_file.write(XML_FOOTER)

def utilsProcessData(indir: str, outdir: str) -> None:
    xml_dict: Dict = {}

    # Loop through all posible string combinations.
    for title_type in TITLE_TYPES:
        for file_suffix in FILE_SUFFIXES:
            # Generate dictionary for the current file.
            file_path: str = os.path.join(indir, title_type + file_suffix)
            file_dict: Dict = {}
            is_md5 = (file_suffix == '.md5')

            try:
                if is_md5:
                    file_dict = utilsGenerateDictionaryFromMd5File(file_path)
                else:
                    file_dict = utilsGenerateDictionaryFromHttpLogFile(file_path)
            except Exception as e:
                traceback.print_exc(file=sys.stderr)
                continue

            # Merge generated dictionary with our XML dictionary.
            for item1 in file_dict.items():
                tid = item1[0]
                contents_dict = item1[1]

                tid_dict = xml_dict.get(tid, {})

                for item2 in contents_dict.items():
                    name = item2[0]
                    properties_dict = item2[1]

                    content_dict = tid_dict.get(name, {})

                    if is_md5:
                        content_dict.update({'md5': properties_dict['md5']})
                    else:
                        content_dict.update({'size': properties_dict['size'], 'header': properties_dict['header']})

                    tid_dict.update({name: content_dict})

                xml_dict.update({tid: tid_dict})

    # Generate output XML dataset.
    utilsGenerateXmlDataset(xml_dict, outdir)

def main() -> int:
    # Get git commit information.
    utilsGetGitInfo()

    parser = ArgumentParser(description='Generate XML dataset from ' + DEFAULT_DUMPER + '\'s Wii CDN dump.')
    parser.add_argument('--indir', type=str, metavar='DIR', help='Path to directory with ' + DEFAULT_DUMPER + '\'s Wii CDN dump. Defaults to \'' + NOLD_DATA_PATH + '\'.')
    parser.add_argument('--outdir', type=str, metavar='DIR', help='Path to output directory. Defaults to \'' + OUTPUT_PATH + '\'.')

    print(SCRIPT_NAME + '.\nRevision: ' + GIT_REV + '.\nMade by DarkMatterCore.\n')

    # Parse arguments.
    args = parser.parse_args()
    indir = utilsGetPath(args.indir, os.path.join(INITIAL_DIR, NOLD_DATA_PATH), False)
    outdir = utilsGetPath(args.outdir, os.path.join(INITIAL_DIR, OUTPUT_PATH), False, True)

    # Do our thing.
    utilsProcessData(indir, outdir)

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
